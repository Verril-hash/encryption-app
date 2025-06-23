FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libglib2.0-0 libsm6 libxext6 libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy app code
COPY . .

# Expose the port Flask uses
EXPOSE 7860

# Set environment variables for Flask
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=7860

# Run the Flask app
CMD ["flask", "run"]