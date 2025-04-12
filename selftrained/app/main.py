import os
import io
import numpy as np
import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
import joblib

# Load pre-trained models
pdf_model = joblib.load("models/model_pdf.joblib") if os.path.exists("models/model_pdf.joblib") else None
doc_model = joblib.load("models/model_doc.joblib") if os.path.exists("models/model_doc.joblib") else None
js_model = joblib.load("models/model_js.joblib") if os.path.exists("models/model_js.joblib") else None

# Load anomaly detection models
anomaly_pdf_model = joblib.load("models/model_anomaly_pdf.joblib") if os.path.exists("models/model_anomaly_pdf.joblib") else None
anomaly_doc_model = joblib.load("models/model_anomaly_doc.joblib") if os.path.exists("models/model_anomaly_doc.joblib") else None
anomaly_js_model = joblib.load("models/model_anomaly_js.joblib") if os.path.exists("models/model_anomaly_js.joblib") else None

app = FastAPI(title="Universal Malware Detector", version="1.0")

def get_file_type(filename: str, file_bytes: bytes) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.pdf':
        return 'pdf'
    elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.docm', '.xlsm', '.pptm']:
        return 'doc'
    elif ext in ['.js', '.jsx', '.html', '.hta', '.vbs', '.ps1', '.bat']:
        return 'js'
    return 'unknown'

def predict_anomaly(model, features):
    """Predict if a file is anomalous (zero-day malware)."""
    prediction = model.predict(features)
    return prediction  # Returns -1 for anomalous, 1 for normal

def predict_file(file_type: str, file_bytes: bytes) -> dict:
    # Read features from pre-processed data
    features = None
    if file_type == "pdf":
        features = np.load("features/features_pdf.npy")
    elif file_type == "doc":
        features = np.load("features/features_doc.npy")
    elif file_type == "js":
        features = np.load("features/features_js.npy")

    if file_type == "pdf" and pdf_model:
        pred = pdf_model.predict(features)
        if anomaly_pdf_model:
            anomaly_prediction = predict_anomaly(anomaly_pdf_model, features)
            if anomaly_prediction == -1:
                pred = 1  # Flag as malware if anomaly detected
        label = "malware" if pred == 1 else "benign"
        return {"classifier": "PDF + Anomaly Detection", "label": label}

    elif file_type == "doc" and doc_model:
        pred = doc_model.predict(features)
        if anomaly_doc_model:
            anomaly_prediction = predict_anomaly(anomaly_doc_model, features)
            if anomaly_prediction == -1:
                pred = 1  # Flag as malware if anomaly detected
        label = "malware" if pred == 1 else "benign"
        return {"classifier": "DOC + Anomaly Detection", "label": label}

    elif file_type == "js" and js_model:
        pred = js_model.predict(features)
        if anomaly_js_model:
            anomaly_prediction = predict_anomaly(anomaly_js_model, features)
            if anomaly_prediction == -1:
                pred = 1  # Flag as malware if anomaly detected
        label = "malware" if pred == 1 else "benign"
        return {"classifier": "JS + Anomaly Detection", "label": label}

    else:
        raise ValueError("Unsupported file type or model not available.")

@app.get("/", summary="Home")
async def read_root():
    return {"message": "Welcome to the Universal Malware Detector API. Use the /scan/ endpoint to upload a file."}

@app.post("/scan/", summary="Upload a file to scan for malware")
async def scan_file(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        file_type = get_file_type(file.filename, file_bytes)
        result = predict_file(file_type, file_bytes)
        result.update({"filename": file.filename, "file_type": file_type})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
