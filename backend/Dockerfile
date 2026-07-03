FROM python:3.12-slim

WORKDIR /app

# Build deps for packages with native extensions (bcrypt, fastuuid, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nmap \
    nikto \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# recon-ng has no pip package -- it's installed by cloning the repo and running its
# own requirements file, then exposing recon-cli on PATH. See backend/reconng.py for
# how it gets invoked (one disposable workspace + resource-file script per run).
RUN git clone --depth 1 https://github.com/lanmaster53/recon-ng.git /opt/recon-ng \
    && pip install --no-cache-dir -r /opt/recon-ng/REQUIREMENTS \
    && ln -s /opt/recon-ng/recon-cli /usr/local/bin/recon-cli \
    && ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng

COPY . .

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
