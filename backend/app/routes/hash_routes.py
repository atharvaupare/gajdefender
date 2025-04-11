from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.controllers.hash_controller import check_hash

router = APIRouter()  # Do not remove your user router; we are keeping it intact.

class HashRequest(BaseModel):
    file_hash: str

@router.post("/scan", summary="Scan a file hash against MalwareBazaar & VirusTotal")
def scan_file_hash(payload: HashRequest):
    """
    Takes a SHA-256 or MD5 file hash as JSON input,
    queries the external services (MalwareBazaar, VirusTotal),
    and returns combined results.
    """
    file_hash = payload.file_hash.strip().lower()
    if not file_hash:
        raise HTTPException(status_code=400, detail="Hash cannot be empty")

    results = check_hash(file_hash)
    return results
