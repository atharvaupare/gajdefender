from fastapi import FastAPI
from app.routes import user  # We'll create user.
from app.routes.hash_routes import router as hash_router


app = FastAPI()

# Include the user router
app.include_router(user.router)
app.include_router(hash_router, prefix="/hash", tags=["Hash Scanner"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=80, reload=True)
