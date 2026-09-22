import os
import uuid
import json
import hashlib
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from ..database import get_db
from ..security.auth import get_current_user
from ..models.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["File Sandbox"])

SANDBOX_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "sandbox")
os.makedirs(SANDBOX_DIR, exist_ok=True)

JOBS_FILE = os.path.join(SANDBOX_DIR, "jobs.json")


def load_jobs():
    if os.path.exists(JOBS_FILE):
        with open(JOBS_FILE, "r") as f:
            return json.load(f)
    return {"jobs": []}


def save_jobs(data):
    with open(JOBS_FILE, "w") as f:
        json.dump(data, f, indent=2)


@router.get("/jobs")
def list_jobs(current_user: User = Depends(get_current_user)):
    data = load_jobs()
    jobs = data.get("jobs", [])
    jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"jobs": jobs}


@router.post("/submit")
async def submit_file(
    file: UploadFile = File(...),
    duration: int = Form(30),
    current_user: User = Depends(get_current_user),
):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()

    job_id = str(uuid.uuid4())[:8]
    file_ext = os.path.splitext(file.filename)[1] or ".bin"
    stored_filename = f"{job_id}{file_ext}"
    stored_path = os.path.join(SANDBOX_DIR, stored_filename)

    with open(stored_path, "wb") as f:
        f.write(content)

    job = {
        "id": job_id,
        "filename": file.filename,
        "stored_filename": stored_filename,
        "hash": file_hash,
        "size": len(content),
        "duration": duration,
        "status": "running",
        "verdict": None,
        "behaviors": [],
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "user_id": current_user.id,
    }

    data = load_jobs()
    data["jobs"].append(job)
    save_jobs(data)

    import threading

    def simulate_analysis():
        import time
        time.sleep(min(duration, 5))

        data = load_jobs()
        for j in data["jobs"]:
            if j["id"] == job_id:
                j["status"] = "completed"
                j["completed_at"] = datetime.now().isoformat()
                risk = hash(file_hash) % 100
                if risk > 70:
                    j["verdict"] = "malicious"
                    j["behaviors"] = [
                        {"description": "Modifies system registry keys", "risk_level": "high"},
                        {"description": "Creates network connections to external IPs", "risk_level": "medium"},
                        {"description": "Attempts to access credential stores", "risk_level": "high"},
                    ]
                elif risk > 40:
                    j["verdict"] = "suspicious"
                    j["behaviors"] = [
                        {"description": "Reads system environment variables", "risk_level": "low"},
                        {"description": "Creates temporary files", "risk_level": "medium"},
                    ]
                else:
                    j["verdict"] = "clean"
                    j["behaviors"] = [
                        {"description": "Normal file operations observed", "risk_level": "low"},
                    ]
                break
        save_jobs(data)

    thread = threading.Thread(target=simulate_analysis, daemon=True)
    thread.start()

    return {"message": "File submitted for analysis", "job_id": job_id, "status": "running"}


@router.get("/jobs/{job_id}")
def get_job(job_id: str, current_user: User = Depends(get_current_user)):
    data = load_jobs()
    for job in data.get("jobs", []):
        if job["id"] == job_id:
            return job
    raise HTTPException(status_code=404, detail="Job not found")


@router.delete("/jobs/{job_id}")
def delete_job(job_id: str, current_user: User = Depends(get_current_user)):
    data = load_jobs()
    job = next((j for j in data["jobs"] if j["id"] == job_id), None)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    stored_path = os.path.join(SANDBOX_DIR, job.get("stored_filename", ""))
    if os.path.exists(stored_path):
        os.remove(stored_path)

    data["jobs"] = [j for j in data["jobs"] if j["id"] != job_id]
    save_jobs(data)
    return {"message": "Job deleted"}
