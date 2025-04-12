from fastapi import APIRouter, File, UploadFile, HTTPException
import lightgbm as lgb
import ember

router = APIRouter()

# Load the LightGBM model (once, on startup)
MODEL_PATH = "app/models/ember_model.txt"

# MOADEL_PTH = "../models/ember_model.txt"
try:
    model = lgb.Booster(model_file=MODEL_PATH)
except Exception as e:
    raise RuntimeError(f"Failed to load EMBER model: {e}")

@router.post("/", summary="Scan a file using EMBER ML model")
async def ember_scan(file: UploadFile = File(...)):
    """
    Upload a PE file to analyze it using EMBER features and a pretrained LightGBM model.
    """
    try:
        file_data = await file.read()
        score = ember.predict_sample(model, file_data, feature_version=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EMBER prediction failed: {str(e)}")

    threshold = 0.5
    verdict = "malware" if score > threshold else "benign"

    return {
        "filename": file.filename,
        "score": float(score),
        "verdict": verdict
    }
