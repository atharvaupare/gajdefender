# Use an official Python runtime as a parent image
FROM python:3.10.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend directory into the container
COPY . .

# Expose port 80 (or whichever port you wish to use)
EXPOSE 8000

# Define the command to run your app using uvicorn,
# The "app.main:app" corresponds to the file structure where main.py is in the app/ folder
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
