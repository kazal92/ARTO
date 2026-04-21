"""
triage.py — Phase 1 (Wide Net) → Phase 2 (Deep Spear) 사이의 Triage Gate API.

역할:
  - Phase 1 이 쌓아놓은 ai_findings.json(의심 취약점) 을 분류/스코어링
  - 사용자 혹은 AI 가 선별한 finding 에 대해 Phase 2 specialist 에이전트 실행
  - 검증 성공 → verified=true, 실패 → triage_status=failed 로 기록
"""

from __future__ import annotations

import os
import json
import asyncio
from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from core.session import find_session_dir
from core.logging import stream_log, stream_custom
from core.cancellation import (
    is_cancelled, mark_cancelled, mark_active, mark_inactive, is_active,
    clear_cancelled,
)
from core.sse import stream_log_file
from api.common import make_tool_stream
from agents.specialists import (
    classify_finding, get_specialist, list_specialist_classes, get_time_budget,
)
from agents.specialist_agent import (
    compute_finding_id, run_specialist_agent, find_finding_by_id,
)

router = APIRouter()

_triage_running_sessions: set = set()


# ── 요청 모델 ────────────────────────────────────────────────────────────────

class TriageListRequest(BaseModel):
    session_id: str


class TriageClassifyRequest(BaseModel):
    session_id: str


class TriageDeepDiveRequest(BaseModel):
    session_id: str
    finding_ids: List[str]
    ai_config: dict = {}
    time_budget_per_finding: Optional[int] = None  # 초, None = 클래스 기본값
    max_parallel: int = 1


class TriageStopRequest(BaseModel):
    session_id: str


class TriageDismissRequest(BaseModel):
    session_id: str
    finding_ids: List[str]
    reason: str = ""


# ── 유틸 ─────────────────────────────────────────────────────────────────────

def _load_findings(session_dir: str) -> list:
    path = os.path.join(session_dir, "ai_findings.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_findings(session_dir: str, findings: list) -> None:
    path = os.path.join(session_dir, "ai_findings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def _severity_score(sev: str) -> int:
    s = (sev or "").upper()
    if "CRITICAL" in s:
        return 40
    if "HIGH" in s:
        return 30
    if "MEDIUM" in s:
        return 20
    if "LOW" in s:
        return 10
    return 5


def _compute_priority(finding: dict) -> int:
    """우선순위 점수 (0~100)."""
    if not isinstance(finding, dict):
        return 0
    score = 0
    score += _severity_score(finding.get("severity", ""))  # 0~40
    conf = finding.get("confidence", 0)
    if isinstance(conf, str) and conf.isdigit():
        conf = int(conf)
    if isinstance(conf, (int, float)):
        score += min(int(conf) // 4, 25)  # 0~25
    evidence = str(finding.get("evidence", "") or "")
    if len(evidence) > 80:
        score += 10
    target = str(finding.get("target", "") or "")
    if any(tok in target.lower() for tok in ("admin", "auth", "login", "api", "upload", "password", "token")):
        score += 15
    if finding.get("verified"):
        score += 10
    return min(score, 100)


def _classify_in_place(findings: list) -> int:
    """vuln_class / id / priority_score / triage_status 필드를 in-place 부여.
    기존 값은 유지. 변경된 항목 수를 반환.
    """
    changed = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        touched = False
        if not f.get("id"):
            f["id"] = compute_finding_id(f)
            touched = True
        if not f.get("vuln_class"):
            f["vuln_class"] = classify_finding(f)
            touched = True
        if "priority_score" not in f:
            f["priority_score"] = _compute_priority(f)
            touched = True
        if not f.get("triage_status"):
            f["triage_status"] = "verified" if f.get("verified") else "pending"
            touched = True
        if touched:
            changed += 1
    return changed


# ── 엔드포인트 ────────────────────────────────────────────────────────────────

@router.post("/api/triage/list")
async def triage_list(req: TriageListRequest):
    """현재 세션의 findings 에 triage 메타데이터를 부여하고 목록 반환."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    findings = _load_findings(session_dir)
    changed = _classify_in_place(findings)
    if changed:
        _save_findings(session_dir, findings)

    specialists = {
        cls: {
            "title_kr": get_specialist(cls).get("title_kr", cls),
            "time_budget_seconds": get_time_budget(cls),
        }
        for cls in list_specialist_classes()
    }

    return {
        "status": "success",
        "count": len(findings),
        "findings": findings,
        "specialists": specialists,
    }


@router.post("/api/triage/classify")
async def triage_classify(req: TriageClassifyRequest):
    """모든 findings 에 vuln_class / priority / id 필드 부여 (지연 분류 강제 적용)."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    findings = _load_findings(session_dir)
    changed = _classify_in_place(findings)
    if changed:
        _save_findings(session_dir, findings)

    by_class = {}
    for f in findings:
        cls = f.get("vuln_class", "GENERIC")
        by_class[cls] = by_class.get(cls, 0) + 1

    return {
        "status": "success",
        "updated": changed,
        "total": len(findings),
        "by_class": by_class,
    }


@router.post("/api/triage/deep-dive")
async def triage_deep_dive(req: TriageDeepDiveRequest):
    """선택된 finding_ids 에 대해 Phase 2 specialist 를 순차/병렬 실행 (SSE)."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    if not req.finding_ids:
        return {"status": "error", "message": "선택된 취약점이 없습니다."}

    if session_dir in _triage_running_sessions:
        return {"status": "error", "message": "이미 전문가 검증이 실행 중입니다."}
    _triage_running_sessions.add(session_dir)

    # findings 분류 메타데이터 보정
    findings = _load_findings(session_dir)
    changed = _classify_in_place(findings)
    if changed:
        _save_findings(session_dir, findings)

    log_file = os.path.join(session_dir, "scan_log.jsonl")

    async def run_task():
        await clear_cancelled(session_dir)
        try:
            stream_log(
                session_dir,
                f"Phase 2 전문가 검증 시작 — {len(req.finding_ids)}건 (병렬 {req.max_parallel})",
                "Triage", 0,
            )
            stream_custom(
                session_dir,
                {"type": "triage_batch_start", "total": len(req.finding_ids)},
            )

            sem = asyncio.Semaphore(max(1, int(req.max_parallel)))
            completed = 0
            summary = []

            async def _one(fid: str):
                nonlocal completed
                async with sem:
                    if is_cancelled(session_dir):
                        return
                    _idx, finding = find_finding_by_id(session_dir, fid)
                    if not finding:
                        stream_log(
                            session_dir,
                            f"[Triage] finding_id={fid} 를 찾을 수 없습니다.",
                            "Triage",
                        )
                        return
                    result = await run_specialist_agent(
                        finding, session_dir, req.ai_config,
                        time_budget_seconds=req.time_budget_per_finding,
                    )
                    completed += 1
                    summary.append(result)
                    pct = int(completed / len(req.finding_ids) * 100)
                    stream_log(
                        session_dir,
                        f"[Triage] 진행 {completed}/{len(req.finding_ids)} ({pct}%)",
                        "Triage", pct,
                    )

            await asyncio.gather(*(_one(fid) for fid in req.finding_ids))

            verified_cnt = sum(1 for r in summary if r.get("verified"))
            stream_log(
                session_dir,
                f"Phase 2 완료 — 성공 {verified_cnt} / 전체 {len(summary)}",
                "Triage", 100,
            )

        except Exception as e:
            stream_log(session_dir, f"Triage 오류: {e}", "Triage")
        finally:
            stream_custom(
                session_dir,
                {"type": "triage_batch_complete", "total": len(req.finding_ids)},
            )
            # scan_complete 이벤트로 프론트엔드 기존 로직과 호환
            stream_custom(session_dir, {"type": "scan_complete", "data": []})
            await mark_inactive(session_dir)
            _triage_running_sessions.discard(session_dir)

    return make_tool_stream(session_dir, log_file, run_task, "triage_batch_complete")


@router.post("/api/triage/stop")
async def triage_stop(req: TriageStopRequest):
    """실행 중인 전문가 검증 중단."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    await mark_cancelled(session_dir)
    _triage_running_sessions.discard(session_dir)
    stream_log(session_dir, "Triage 중단 요청이 전달되었습니다.", "Triage")
    return {"status": "success", "message": "전문가 검증 중단 요청이 전달되었습니다."}


@router.post("/api/triage/dismiss")
async def triage_dismiss(req: TriageDismissRequest):
    """선택된 finding 을 dismissed 로 표시 (false positive 처리)."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    findings = _load_findings(session_dir)
    target = set(req.finding_ids)
    updated = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or compute_finding_id(f)
        if fid in target:
            f["id"] = fid
            f["triage_status"] = "dismissed"
            f["verified"] = False
            if req.reason:
                f["dismiss_reason"] = req.reason
            updated += 1
    if updated:
        _save_findings(session_dir, findings)
    return {"status": "success", "dismissed": updated}
