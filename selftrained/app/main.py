import os
import io
import numpy as np
import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
import joblib
import lightgbm as lgb
import ember

# Load pre-trained classifiers
pdf_model = joblib.load("models/model_pdf.joblib") if os.path.exists("models/model_pdf.joblib") else None
doc_model = joblib.load("models/model_doc.joblib") if os.path.exists("models/model_doc.joblib") else None
js_model = joblib.load("models/model_js.joblib") if os.path.exists("models/model_js.joblib") else None

# Load anomaly detection models
anomaly_pdf_model = joblib.load("models/model_anomaly_pdf.joblib") if os.path.exists("models/model_anomaly_pdf.joblib") else None
anomaly_doc_model = joblib.load("models/model_anomaly_doc.joblib") if os.path.exists("models/model_anomaly_doc.joblib") else None
anomaly_js_model = joblib.load("models/model_anomaly_js.joblib") if os.path.exists("models/model_anomaly_js.joblib") else None

# Load EMBER model for PE and fallback files
pe_model_path = "models/ember_model_2018.txt"
pe_model = lgb.Booster(model_file=pe_model_path) if os.path.exists(pe_model_path) else None

app = FastAPI(title="Universal Malware Detector", version="1.0")

def get_file_type(filename: str, file_bytes: bytes) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.pdf':
        return 'pdf'
    elif ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.docm', '.xlsm', '.pptm']:
        return 'doc'
    elif ext in ['.js', '.jsx', '.html', '.hta', '.vbs', '.ps1', '.bat']:
        return 'js'
    elif ext in ['.exe', '.dll'] or file_bytes.startswith(b'MZ'):
        return 'exe'
    return 'unknown'

def predict_anomaly(model, features):
    prediction = model.predict(features)
    return prediction

def predict_file(file_type: str, file_bytes: bytes) -> dict:
    try:
        if file_type == "pdf" and pdf_model:
            features = np.load("features/features_pdf.npy")[:1]  # Simulate extracting current file's features
            pred = pdf_model.predict(features)
            if anomaly_pdf_model and predict_anomaly(anomaly_pdf_model, features)[0] == -1:
                pred = [1]
            label = "malware" if pred[0] == 1 else "benign"
            return {"classifier": "PDF + Anomaly", "label": label}

        elif file_type == "doc" and doc_model:
            features = np.load("features/features_doc.npy")[:1]
            pred = doc_model.predict(features)
            if anomaly_doc_model and predict_anomaly(anomaly_doc_model, features)[0] == -1:
                pred = [1]
            label = "malware" if pred[0] == 1 else "benign"
            return {"classifier": "DOC + Anomaly", "label": label}

        elif file_type == "js" and js_model:
            features = np.load("features/features_js.npy")[:1]
            pred = js_model.predict(features)
            if anomaly_js_model and predict_anomaly(anomaly_js_model, features)[0] == -1:
                pred = [1]
            label = "malware" if pred[0] == 1 else "benign"
            return {"classifier": "JS + Anomaly", "label": label}

        # Use EMBER model for PE and fallback
        elif file_type in ["exe", "unknown"] and pe_model:
            score = ember.predict_sample(pe_model, file_bytes, feature_version=2)
            label = "malware" if score > 0.5 else "benign"
            return {"classifier": "EMBER", "score": float(score), "label": label}

        else:
            raise ValueError("Unsupported file type or required model not available.")

    except Exception as e:
        raise ValueError(f"Prediction error: {e}")

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