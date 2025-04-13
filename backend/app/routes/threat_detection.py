import os
import subprocess
import time
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pathlib import Path
import threading
import shutil

router = APIRouter()

# Directory to store SLIPS output
SLIPS_OUTPUT_DIR = Path("slips_output")
SLIPS_OUTPUT_DIR.mkdir(exist_ok=True)

# Global variables to track SLIPS process
slips_process = None
slips_container_id = None
slips_running = False
slips_lock = threading.Lock()

class ScanResponse(BaseModel):
    status: str
    message: str

@router.post("/start", response_model=ScanResponse)
async def start_threat_detection():
    """Start SLIPS threat detection"""
    global slips_process, slips_container_id, slips_running
   
    with slips_lock:
        if slips_running:
            return {"status": "already_running", "message": "Threat detection is already running"}
       
        # Clear previous output directory
        if SLIPS_OUTPUT_DIR.exists():
            shutil.rmtree(SLIPS_OUTPUT_DIR)
        SLIPS_OUTPUT_DIR.mkdir(exist_ok=True)
       
        # Start SLIPS container
        try:
            cmd = [
                "docker", "run", "--rm", "-d",
                "--cpu-shares", "700",
                "--memory", "8g",
                "--memory-swap", "8g",
                "--net", "host",
                "--cap-add", "NET_ADMIN",
                "-v", f"{SLIPS_OUTPUT_DIR.absolute()}:/output",
                "--name", "slips_realtime",
                "stratosphereips/slips:latest",
                "./slips.py", "-i", "any", "-o", "/output"  # -i any for monitoring network interfaces
            ]
           
            # Execute the command and get container ID
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            slips_container_id = result.stdout.strip()
            slips_running = True
           
            return {"status": "started", "message": "Threat detection started successfully"}
        except subprocess.CalledProcessError as e:
            return JSONResponse(
                status_code=500,
                content={"status": "error", "message": f"Failed to start SLIPS: {e.stderr}"},
                headers={"Access-Control-Allow-Origin": "*"}
            )

@router.post("/stop", response_model=ScanResponse)
async def stop_threat_detection():
    """Stop SLIPS threat detection"""
    global slips_running, slips_container_id
   
    with slips_lock:
        if not slips_running:
            return {"status": "not_running", "message": "Threat detection is not running"}
       
        try:
            # Stop SLIPS container
            subprocess.run(["docker", "stop", "slips_realtime"], check=True)
            slips_running = False
            slips_container_id = None
           
            return {"status": "stopped", "message": "Threat detection stopped successfully"}
        except subprocess.CalledProcessError as e:
            return JSONResponse(
                status_code=500,
                content={"status": "error", "message": f"Failed to stop SLIPS: {str(e)}"}
            )

@router.get("/status")
async def get_detection_status():
    """Get the current status of threat detection"""
    global slips_running
   
    # Check if container is actually running
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=slips_realtime", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True
        )
        container_running = bool(result.stdout.strip())
       
        # Update global status if there's a mismatch
        if slips_running != container_running:
            with slips_lock:
                slips_running = container_running
    except:
        # If docker command fails, assume not running
        with slips_lock:
            slips_running = False
   
    return {"status": "running" if slips_running else "stopped"}

@router.get("/logs")
async def get_detection_logs():
    """Get the current SLIPS alerts logs"""
    alerts_file = SLIPS_OUTPUT_DIR / "alerts.log"
   
    if not alerts_file.exists():
        return {"alerts": [], "message": "No alerts generated yet"}
   
    try:
        with open(alerts_file, "r") as f:
            alerts_content = f.readlines()
       
        # Parse alerts into structured format
        alerts = []
        for line in alerts_content:
            line = line.strip()
            if line:
                alerts.append({"alert": line})
       
        return {"alerts": alerts}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Error reading logs: {str(e)}"}
        )