import httpx
import asyncio
import urllib.parse
import time

class ZAPClient:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/JSON"

    async def wait_for_zap(self, timeout=60):
        """ZAP API가 준비될 때까지 기다립니다."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{self.api_url}/core/view/version/")
                    if resp.status_code == 200:
                        return True
            except:
                pass
            await asyncio.sleep(2)
        return False

    async def start_spider(self, target_url):
        """ZAP Spider를 시작하고 스캔 ID를 반환합니다."""
        params = {
            "url": target_url,
            "maxChildren": "",
            "recurse": "true",
            "contextName": "",
            "subtreeOnly": ""
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/spider/action/scan/", params=params)
            if resp.status_code != 200:
                print(f"[ZAP ERROR] Status: {resp.status_code}, Body: {resp.text}")
                return None
            try:
                data = resp.json()
                return data.get("scan")
            except Exception as e:
                print(f"[ZAP JSON ERROR] {e}, Body: {resp.text}")
                return None

    async def get_spider_status(self, scan_id):
        """Spider 진행률(%)을 반환합니다."""
        if not scan_id: return 0
        params = {"scanId": scan_id}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/spider/view/status/", params=params)
            if resp.status_code != 200: return 0
            try:
                data = resp.json()
                return int(data.get("status", 0))
            except: return 0

    async def get_spider_results(self, scan_id):
        """Spider가 발견한 URL 목록을 반환합니다."""
        params = {"scanId": scan_id}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/spider/view/results/", params=params)
            if resp.status_code != 200: return []
            try:
                data = resp.json()
                return data.get("results", [])
            except: return []

    async def wait_for_spider(self, scan_id, interval=2):
        """Spider가 완료될 때까지 기다립니다."""
        while True:
            status = await self.get_spider_status(scan_id)
            if status >= 100:
                break
            await asyncio.sleep(interval)
            yield status

    async def get_all_messages(self, base_url=None):
        """ZAP에 기록된 모든 메시지의 요청/응답 데이터를 가져옵니다."""
        params = {"baseurl": base_url} if base_url else {}
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/core/view/messages/", params=params)
            if resp.status_code != 200: return []
            try:
                return resp.json().get("messages", [])
            except: return []

    async def get_all_urls(self):
        """ZAP Sites 트리에서 모든 URL을 가져옵니다."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self.api_url}/core/view/sites/")
            if resp.status_code != 200: return []
            try:
                data = resp.json()
                return data.get("sites", [])
            except: return []

    async def set_upstream_proxy(self, proxy_host, proxy_port):
        """상위 프록시(Upstream Proxy)를 설정합니다."""
        async with httpx.AsyncClient() as client:
            # ZAP API: core/action/setOptionProxyChainName 등 사용 시 매개변수명은 대문자로 시작해야 함 (String, Integer, Boolean)
            await client.get(f"{self.api_url}/core/action/setOptionProxyChainName/", params={"String": proxy_host})
            await client.get(f"{self.api_url}/core/action/setOptionProxyChainPort/", params={"Integer": proxy_port})
            await client.get(f"{self.api_url}/core/action/setOptionUseProxyChain/", params={"Boolean": "true"})
            return True

    async def disable_upstream_proxy(self):
        """상위 프록시 설정을 해제합니다."""
        async with httpx.AsyncClient() as client:
            await client.get(f"{self.api_url}/core/action/setOptionUseProxyChain/", params={"Boolean": "false"})
            return True

    async def clear_zap_history(self):
        """ZAP 세션을 새로 생성하여 히스토리와 사이트 트리를 초기화합니다."""
        async with httpx.AsyncClient() as client:
            # name이 비어있으면 기본 세션을 덮어씁니다.
            await client.get(f"{self.api_url}/core/action/newSession/", params={"name": "", "overwrite": "true"})
            return True
