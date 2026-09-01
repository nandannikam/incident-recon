from fastapi import FastAPI, UploadFile, File, HTTPException
from app.orchestrator import run_analysis
from app.storage import save_incident, get_incident
from app.models import Incident

app = FastAPI(title="Cybersecurity Incident Reconstruction API")


@app.post("/analyze", response_model=Incident)
async def analyze_endpoint(file: UploadFile = File(...)):
    path = f"/tmp/{file.filename}"
    with open(path, "wb") as f:
        f.write(await file.read())
    incident = run_analysis(path)
    save_incident(incident)
    return incident


@app.get("/incident/{incident_id}", response_model=Incident)
def get_incident_endpoint(incident_id: str):
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident