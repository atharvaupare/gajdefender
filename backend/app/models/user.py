# A simple Python model (not using any ORM yet)
class UserModel:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
