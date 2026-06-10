FROM python:3.12-slim

# tesseract is needed to read the text out of scam images
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# pass DISCORD_TOKEN as an env var, and mount a volume at /app/config.json to keep settings
CMD ["python", "main.py"]
