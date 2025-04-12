from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, root_validator
from app.controllers.hash_controller import check_hash
import os
import hashlib
from typing import List, Optional

router = APIRouter()

class HashRequest(BaseModel):
    file_hash: str | None = None
    file_path: str | None = None

    @root_validator(pre=True)
    def check_exactly_one(cls, values):
        # Count keys with non-empty values
        provided = [key for key in ("file_hash", "file_path") if values.get(key)]
        if len(provided) != 1:
            raise ValueError("Provide exactly one of 'file_hash' or 'file_path'.")
        return values

@router.post("/scan", summary="Scan a file by hash or file path against MalwareBazaar & VirusTotal")
def scan_file_hash(payload: HashRequest):
    """
    Accepts either a file_hash or a file_path.
    If file_path is provided, calculates SHA256.
    Queries MalwareBazaar and VirusTotal.
    """
    hash_str = None

    if payload.file_hash:
        hash_str = payload.file_hash.strip().lower()
    elif payload.file_path:
        path = payload.file_path.strip()
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="File path does not exist.")
        
        try:
            with open(path, "rb") as f:
                file_data = f.read()
                hash_str = hashlib.sha256(file_data).hexdigest()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    results = check_hash(hash_str)
    return {
        "sha256": hash_str,
        "results": results
    }

# --- New Batch Scan Route (does not change existing functionality) ---

class BatchHashRequest(BaseModel):
    file_paths: Optional[List[str]] = None
    folder_path: Optional[str] = None

    @root_validator(pre=True)
    def validate_batch(cls, values):
        file_paths = values.get("file_paths")
        folder_path = values.get("folder_path")
        # Either one must be provided, but not both
        if (file_paths and folder_path) or (not file_paths and not folder_path):
            raise ValueError("Provide exactly one of 'file_paths' or 'folder_path'.")
        return values

@router.post("/batch-scan", summary="Batch scan by file paths or a folder path")
def batch_scan(payload: BatchHashRequest):
    """
    Accepts either an array of file paths or a single folder path.
    For each file, it computes its SHA-256 hash and queries external services.
    Returns combined results in a batch.
    """
    paths = []
    if payload.file_paths:
        paths = [p.strip() for p in payload.file_paths]
    elif payload.folder_path:
        folder = payload.folder_path.strip()
        if not os.path.exists(folder):
            raise HTTPException(status_code=404, detail="Folder path does not exist.")
        # List all files in folder (non-recursive)
        for entry in os.listdir(folder):
            file_path = os.path.join(folder, entry)
            if os.path.isfile(file_path):
                paths.append(file_path)

    if not paths:
        raise HTTPException(status_code=404, detail="No files found to scan.")

    batch_results = []
    for path in paths:
        if not os.path.exists(path):
            batch_results.append({"path": path, "error": "File path does not exist."})
            continue
        try:
            with open(path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                res = check_hash(file_hash)
                batch_results.append({
                    "path": path,
                    "sha256": file_hash,
                    "results": res
                })
        except Exception as e:
            batch_results.append({"path": path, "error": str(e)})

    return {"batch_results": batch_results}
