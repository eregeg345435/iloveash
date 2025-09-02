FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive

# 1) Minimal tools so we can add Google's repo
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget gnupg \
 && rm -rf /var/lib/apt/lists/*

# 2) Add Google Chrome repo and install Chrome + a few common libs
RUN mkdir -p /etc/apt/keyrings \
 && wget -qO- https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /etc/apt/keyrings/google-chrome.gpg \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
 && apt-get update && apt-get install -y --no-install-recommends \
    google-chrome-stable \
    fonts-liberation libasound2 libatk-bridge2.0-0 libgtk-3-0 libnss3 libxss1 libgbm1 xdg-utils \
 && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/google-chrome

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . /app

CMD ["python", "snusbase_reporter.py"]
