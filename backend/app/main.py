from fastapi import FastAPI
from app.routes import user  # We'll create user.
from app.routes.hash_routes import router as hash_router
from app.routes.ember_routes import router as ember_router  # 👈 NEW



app = FastAPI()

# Include the user router
app.include_router(user.router)
app.include_router(hash_router, prefix="/hash", tags=["Hash Scanner"])
app.include_router(ember_router, prefix="/ember", tags=["EMBER File Scanner"])  # 👈 NEW


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=80, reload=True)
