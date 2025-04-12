from fastapi import FastAPI
from app.routes import user  # We'll create user.
from app.routes.hash_routes import router as hash_router
from app.routes.ember_routes import router as ember_router  # 👈 NEW
from app.routes.upload_router import router as upload_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Optional: Enable CORS if testing from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router, prefix="/files", tags=["Upload"])


# Include the user router
app.include_router(user.router)
app.include_router(hash_router, prefix="/hash", tags=["Hash Scanner"])
app.include_router(ember_router, prefix="/ember", tags=["EMBER File Scanner"])  # 👈 NEW


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=80, reload=True)
