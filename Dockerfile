FROM golangboyme/wxocr:latest

LABEL com.centurylinklabs.watchtower.enable="false"

RUN pip install flask_cors

COPY main.py /app/main.py

COPY templates /app/templates