try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.scan import router as scan_router
from api.history import router as history_router
from api.zap import router as zap_router
from api.precheck import router as precheck_router
from api.session_ops import router as session_router
from api.agent import router as agent_router
from api.terminal import router as terminal_router

app = FastAPI(title="ARTO Web Dashboard")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(scan_router)
app.include_router(history_router)
app.include_router(zap_router)
app.include_router(precheck_router)
app.include_router(session_router)
app.include_router(agent_router)
app.include_router(terminal_router)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"existing_report": ""}
    )


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, full_path: str):
    from fastapi import HTTPException
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found")
    return templates.TemplateResponse(request=request, name="index.html", context={})


if __name__ == "__main__":
    import uvicorn
    from config import ARTO_HOST, ARTO_PORT
    uvicorn.run("main:app", host=ARTO_HOST, port=ARTO_PORT, reload=True)
