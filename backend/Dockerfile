FROM python:3.12-slim

WORKDIR /app

# Build deps for packages with native extensions (bcrypt, fastuuid, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    nmap \
    git \
    perl \
    libjson-perl \
    libxml-writer-perl \
    libnet-ssleay-perl \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Nikto -- installed from source (git clone) rather than Debian's packaged version.
# Debian's `nikto` apt package is a very old 2013-era release (2.1.5) that predates
# `-Format json` / `-output -` support entirely (JSON output wasn't added to Nikto
# until 2.5.0) -- that's the real cause of the "Invalid output format" / "produced no
# output" errors, not a config or non-free-component issue. Cloning upstream gets the
# current release, which does support what nikto_scan.py actually shells out with.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# recon-ng has no pip package -- it's installed by cloning the repo and running its
# own requirements file, then exposing recon-cli on PATH. See backend/reconng.py for
# how it gets invoked (one disposable workspace + resource-file script per run).
RUN git clone --depth 1 https://github.com/lanmaster53/recon-ng.git /opt/recon-ng \
    && pip install --no-cache-dir -r /opt/recon-ng/REQUIREMENTS \
    && ln -s /opt/recon-ng/recon-cli /usr/local/bin/recon-cli \
    && ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng

# Trivy -- used ONLY as an SBOM generator (`trivy image --format cyclonedx`) for
# container image scanning, never in its full CVE-scanning mode. That mode needs
# its own multi-hundred-MB vulnerability database mirrored inside the container,
# which is exactly what backend/sbom.py's own docstring explains this app avoids
# by querying OSV.dev directly instead -- see backend/container_scan.py for the
# full reasoning. Installed via Trivy's official install script (no separate DB
# download happens at build time or at SBOM-generation time).
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

COPY . .

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
