FROM python:3.12-slim

WORKDIR /app

# Build deps for packages with native extensions (bcrypt, fastuuid, etc.)
# nikto lives in Debian's non-free component, which isn't enabled by default --
# turn it on (covers both the legacy one-line sources.list format and the newer
# deb822 sources.list.d/*.sources format, whichever this base image uses) before
# installing it, so this doesn't silently fail as "Unable to locate package nikto"
# on a base image where non-free isn't already on.
RUN (sed -i 's/^Components: main$/Components: main non-free non-free-firmware/' /etc/apt/sources.list.d/*.sources 2>/dev/null || true) \
    && (sed -i '/^deb /s/$/ non-free non-free-firmware/' /etc/apt/sources.list 2>/dev/null || true) \
    && apt-get update && apt-get install -y --no-install-recommends \
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
