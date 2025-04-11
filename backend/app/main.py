from fastapi import FastAPI
from app.routes import user  # We'll create user.

app = FastAPI()

# Include the user router
app.include_router(user.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=80, reload=True)
