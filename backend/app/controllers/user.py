def create_user_logic(user_data):
    """
    A simple function to 'create' a user in memory.
    In a real app, you'd do database actions here.
    """
    # For demonstration, just return the data
    return {
        "name": user_data.name,
        "email": user_data.email,
        "message": "User created successfully!"
    }

def get_users_logic():
    """
    A simple function to retrieve users.
    In a real app, you'd query the database here.
    """
    # Dummy list of users
    dummy_users = [
        {"name": "Alice", "email": "alice@example.com"},
        {"name": "Bob", "email": "bob@example.com"}
    ]
    return dummy_users
