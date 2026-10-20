# Container image for the agent itself: Python, git, pip-audit and Trivy.
FROM python:3.12-slim

# Trivy v0.69.4 and most aquasecurity/trivy-action tags were compromised in March 2026
# (CVE-2026-33634). v0.69.3 is confirmed clean; the checksum below is from the official
# trivy_0.69.3_checksums.txt release asset and is verified before the binary is used.
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/trivy.tgz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c - \
 && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy \
 && rm /tmp/trivy.tgz

WORKDIR /opt/vra
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --create-home agent
USER agent
RUN git config --global --add safe.directory '*'
WORKDIR /work

ENTRYPOINT ["vra"]
CMD ["--help"]
