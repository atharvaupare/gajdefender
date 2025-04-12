# main without anomaly models
import os
import io
import numpy as np
import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
import joblib
import lightgbm as lgb
import ember  # For fallback malware detection using EMBER model

app = FastAPI(
    title="Universal Malware Detector",
    description="AI-based multi-format malware detection with EMBER fallback.",
    version="1.0",
)

# Load ML models
pdf_model = joblib.load("models/model_pdf.joblib") if os.path.exists("models/model_pdf.joblib") else None
doc_model = joblib.load("models/model_doc.joblib") if os.path.exists("models/model_doc.joblib") else None
js_model = joblib.load("models/model_js.joblib") if os.path.exists("models/model_js.joblib") else None

# Load EMBER fallback model
EMBER_MODEL_PATH = "models/ember_model_2018.txt"
ember_model = lgb.Booster(model_file=EMBER_MODEL_PATH) if os.path.exists(EMBER_MODEL_PATH) else None

@app.get("/", summary="Home")
async def read_root():
    return {"message": "Welcome to the Universal Malware Detector API. Use the /scan/ endpoint to upload a file."}

def get_file_type(filename: str, file_bytes: bytes) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext == ".pdf":
        return "pdf"
    elif ext in [
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".docm", ".xlsm", ".pptm"
    ]:
        return "doc"
    elif ext in [".js", ".jsx", ".html", ".hta", ".vbs", ".ps1", ".bat"]:
        return "js"
    else:
        return "other"

@app.post("/scan/", summary="Upload a file to scan for malware")
async def scan_file(file: UploadFile = File(...)):
    try:
        file_bytes = await file.read()
        file_type = get_file_type(file.filename, file_bytes)

        features = None
        label = None
        classifier_used = None

        if file_type == "pdf" and pdf_model:
            features = np.load("features/features_pdf.npy")[:1]  # simulate one sample
            pred = pdf_model.predict(features)[0]
            classifier_used = "PDF"
            label = "malware" if pred == 1 else "benign"

        elif file_type == "doc" and doc_model:
            features = np.load("features/features_doc.npy")[:1]
            pred = doc_model.predict(features)[0]
            classifier_used = "DOC"
            label = "malware" if pred == 1 else "benign"

        elif file_type == "js" and js_model:
            features = np.load("features/features_js.npy")[:1]
            pred = js_model.predict(features)[0]
            classifier_used = "JS"
            label = "malware" if pred == 1 else "benign"

        else:
            if ember_model:
                score = ember.predict_sample(ember_model, file_bytes, feature_version=2)
                label = "malware" if score > 0.5 else "benign"
                classifier_used = "EMBER"
            else:
                raise HTTPException(status_code=500, detail="EMBER model not found")

        return {
            "filename": file.filename,
            "file_type": file_type,
            "label": label,
            "classifier": classifier_used,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
