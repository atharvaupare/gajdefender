# main.py

from fastapi import FastAPI, File, UploadFile
import uvicorn
import lightgbm as lgb
import ember

app = FastAPI(
    title="AI-Powered Malware Detection",
    description="A web app that uses a pretrained EMBER model for malware detection.",
    version="1.0",
)

# Load the pretrained LightGBM model (update path if needed)
MODEL_PATH = "models/ember_model.txt"
model = lgb.Booster(model_file=MODEL_PATH)

@app.post("/scan/", summary="Scan a file for malware")
async def scan_file(file: UploadFile = File(...)):
    """
    Accept a file upload, process the file bytes, extract features using EMBER,
    and produce a malware probability score.
    """
    # Read file bytes from the uploaded file
    file_data = await file.read()

    # Predict malware score using EMBER's predict_sample function
    # We assume feature_version 2 (consistent with EMBER 2018 version2 features)
    score = ember.predict_sample(model, file_data, feature_version=2)
    
    # Define a threshold to classify as malware (adjust threshold if necessary)
    threshold = 0.5
    verdict = "malware" if score > threshold else "benign"

    # Return a JSON response with details
    return {
        "filename": file.filename,
        "score": float(score),
        "verdict": verdict,
    }

if __name__ == "__main__":
    # Run the app using Uvicorn when executed directly
    uvicorn.run(app, host="0.0.0.0", port=8000)
