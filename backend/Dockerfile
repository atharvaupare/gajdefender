# Use an official Python runtime as a parent image
FROM python:3.10.10-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies: git, libgomp (for lightgbm), and cleanup
RUN apt-get update && apt-get install -y git libgomp1 && rm -rf /var/lib/apt/lists/*


# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend directory into the container
COPY . .

# PATCH: override ember's features.py
COPY ember_patch/features.py /usr/local/lib/python3.10/site-packages/ember/features.py


# Expose port 80 (or whichever port you wish to use)
EXPOSE 8000

# Define the command to run your app using uvicorn,
# The "app.main:app" corresponds to the file structure where main.py is in the app/ folder
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
