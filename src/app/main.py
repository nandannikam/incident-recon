import uuid
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.orchestrator import run_analysis
from app.storage import save_incident, get_incident
from app.models import Incident

app = FastAPI(title="Cybersecurity Incident Reconstruction API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@app.post("/upload")
async def upload_endpoint(file: UploadFile = File(...)):
    if not (file.filename.endswith(".csv") or file.filename.endswith(".ndjson")):
        raise HTTPException(400, "Only .csv or .ndjson files are accepted")

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (max 50 MB)")

    file_id = uuid.uuid4().hex
    path = f"/tmp/{file_id}_{file.filename}"
    with open(path, "wb") as f:
        f.write(contents)

    return {"file_id": file_id, "path": path}


@app.post("/analyze", response_model=Incident)
async def analyze_endpoint(file: UploadFile = File(...)):
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File too large (max 50 MB)")

    path = f"/tmp/{uuid.uuid4().hex}_{file.filename}"
    with open(path, "wb") as f:
        f.write(contents)

    incident = run_analysis(path)
    save_incident(incident)
    return incident


@app.get("/incident/{incident_id}", response_model=Incident)
def get_incident_endpoint(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident