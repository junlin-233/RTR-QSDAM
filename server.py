import os
import threading
import subprocess
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent
RESULT_DIR = BASE_DIR / "data"  # all outputs under data/
RESULT_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Analysis Orchestrator")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    folder: str


def run_cmd(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, cwd=str(RESULT_DIR), check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Command failed: {' '.join(cmd)}\n{e.stderr}")


# Simple in-memory progress state
PROGRESS = {
    "status": "idle",   # idle|running|done|error
    "percent": 0,
    "stage": "",
    "error": ""
}

PROGRESS_LOCK = threading.Lock()

def set_progress(status: str = None, percent: int = None, stage: str = None, error: str = None):
    with PROGRESS_LOCK:
        if status is not None:
            PROGRESS["status"] = status
        if percent is not None:
            PROGRESS["percent"] = max(0, min(100, percent))
        if stage is not None:
            PROGRESS["stage"] = stage
        if error is not None:
            PROGRESS["error"] = error

def run_analysis_thread(folder_path: Path):
    try:
        set_progress(status="running", percent=5, stage="准备环境")
        # Clear previous outputs
        outputs = [
            "permissions_by_file.csv",
            "permissions_total.csv",
            "permissions_top_apis.png",
            "permissions_type_distribution.png",
            "syscalls_by_file.csv",
            "syscalls_total.csv",
            "syscall_scores.png",
            "syscall_confidence_distribution.png",
            "defense_assessment.csv",
            "defense_assessment_scatter.png",
            "defense_assessment_scatter.svg",
            "security_report.txt",
            "security_report.json",
        ]
        for name in outputs:
            p = RESULT_DIR / name
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        set_progress(percent=15, stage="运行权限分析 (check.py)")
        run_cmd(["python", str(BASE_DIR / "check.py"), str(folder_path)])

        set_progress(percent=45, stage="运行系统调用分析 (find_syscall.py)")
        run_cmd(["python", str(BASE_DIR / "find_syscall.py"), str(folder_path)])

        set_progress(percent=70, stage="合并并生成可视化 (link.py)")
        run_cmd(["python", str(BASE_DIR / "link.py")])  # defaults

        set_progress(percent=85, stage="生成安全报告")
        run_cmd(["python", str(BASE_DIR / "report.py")])  # new report generator

        set_progress(status="done", percent=100, stage="完成")
    except HTTPException as he:
        set_progress(status="error", stage="出错", error=str(he.detail))
    except Exception as e:
        set_progress(status="error", stage="出错", error=str(e))


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    folder_path = Path(req.folder)
    if not folder_path.exists() or not folder_path.is_dir():
        raise HTTPException(status_code=400, detail="Folder does not exist or is not a directory")
    # If already running, reject
    with PROGRESS_LOCK:
        if PROGRESS.get("status") == "running":
            raise HTTPException(status_code=409, detail="Analysis already running")
    # set initial progress outside the lock to avoid deadlock
    set_progress(status="running", percent=1, stage="启动")

    t = threading.Thread(target=run_analysis_thread, args=(folder_path,), daemon=True)
    t.start()
    return {"started": True}


@app.get("/progress")
def progress():
    with PROGRESS_LOCK:
        return dict(PROGRESS)


@app.get("/results")
def results():
    files = []
    for name in os.listdir(RESULT_DIR):
        if any(name.endswith(ext) for ext in [".png", ".svg", ".csv", ".txt", ".json"]):
            files.append(name)
    # Sort for consistency
    files.sort()
    return {"files": files}


# Serve static frontend under /
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
app.mount("/files", StaticFiles(directory=str(RESULT_DIR)), name="files")


