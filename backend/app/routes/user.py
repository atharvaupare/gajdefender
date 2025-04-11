from fastapi import APIRouter
from app.controllers import user as user_controller
from pydantic import BaseModel

# We'll use a simple Pydantic model here for request/response data
class UserCreate(BaseModel):
    name: str
    email: str

router = APIRouter()

@router.get("/users")
def get_users():
    """
    GET endpoint to retrieve users
    """
    return user_controller.get_users_logic()

@router.post("/users")
def create_user(user_data: UserCreate):
    """
    POST endpoint to create a user.
    """
    return user_controller.create_user_logic(user_data)
