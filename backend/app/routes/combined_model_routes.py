# from fastapi import APIRouter, UploadFile, File, HTTPException
# import os
# import numpy as np
# import joblib
# import lightgbm as lgb
# import ember

# router = APIRouter()

# # Load models if available
# pdf_model = joblib.load("app/models/model_pdf.joblib") if os.path.exists("app/models/model_pdf.joblib") else None
# doc_model = joblib.load("app/models/model_doc.joblib") if os.path.exists("app/models/model_doc.joblib") else None
# js_model = joblib.load("app/models/model_js.joblib") if os.path.exists("app/models/model_js.joblib") else None

# # Load EMBER model fallback
# EMBER_MODEL_PATH = "app/models/ember_model.txt"
# ember_model = lgb.Booster(model_file=EMBER_MODEL_PATH) if os.path.exists(EMBER_MODEL_PATH) else None


# def get_file_type(filename: str, file_bytes: bytes) -> str:
#     ext = os.path.splitext(filename)[1].lower()
#     if ext == ".pdf":
#         return "pdf"
#     elif ext in [
#         ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".docm", ".xlsm", ".pptm"
#     ]:
#         return "doc"
#     elif ext in [".js", ".jsx", ".html", ".hta", ".vbs", ".ps1", ".bat"]:
#         return "js"
#     else:
#         return "other"


# @router.post("/", summary="Universal malware detector for multiple file types")
# async def combined_model_scan(file: UploadFile = File(...)):
#     try:
#         file_bytes = await file.read()
#         file_type = get_file_type(file.filename, file_bytes)

#         features = None
#         label = None
#         classifier_used = None

#         if file_type == "pdf" and pdf_model:
#             features = np.load("app/features/features_pdf.npy")[:1]  # dummy sample
#             pred = pdf_model.predict(features)[0]
#             classifier_used = "PDF"
#             label = "malware" if pred == 1 else "benign"

#         elif file_type == "doc" and doc_model:
#             features = np.load("app/features/features_doc.npy")[:1]
#             pred = doc_model.predict(features)[0]
#             classifier_used = "DOC"
#             label = "malware" if pred == 1 else "benign"

#         elif file_type == "js" and js_model:
#             features = np.load("app/features/features_js.npy")[:1]
#             pred = js_model.predict(features)[0]
#             classifier_used = "JS"
#             label = "malware" if pred == 1 else "benign"

#         else:
#             if ember_model:
#                 score = ember.predict_sample(ember_model, file_bytes, feature_version=2)
#                 label = "malware" if score > 0.5 else "benign"
#                 classifier_used = "EMBER"
#             else:
#                 raise HTTPException(status_code=500, detail="EMBER model not found.")

#         return {
#             "filename": file.filename,
#             "file_type": file_type,
#             "label": label,
#             "classifier": classifier_used
#         }

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
