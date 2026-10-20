# Image for the auth-service test repository, so the agent's Trivy step has something to scan.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY authsvc ./authsvc
CMD ["python", "-c", "import authsvc; print('ok')"]
