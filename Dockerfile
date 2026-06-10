FROM python:3.12-slim

# tesseract is needed to read the text out of scam images
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# settings (and the learned hash pool) live in a mounted directory, not a single bind-mounted
# file: os.replace can't atomically swap a bind-mounted file (EBUSY), and a host file that
# doesn't exist yet would be created as a directory and crash startup
ENV EXORCIST_CONFIG=/data/config.json
RUN mkdir -p /data
VOLUME /data

# pass DISCORD_TOKEN as an env var; mount a volume at /data to keep settings across restarts
CMD ["python", "main.py"]
