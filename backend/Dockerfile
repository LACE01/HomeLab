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

COPY . .

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
