FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ core/
COPY okam/ okam/

EXPOSE 8080 8554

ENV OKAM_DID=VE3326855YITZ
ENV OKAM_USER=admin
ENV OKAM_PWD=888888
ENV OKAM_HTTP_PORT=8080

CMD python -m okam.proxy_server \
    --did "$OKAM_DID" \
    --user "$OKAM_USER" \
    --pwd "$OKAM_PWD" \
    --http-port "$OKAM_HTTP_PORT"
