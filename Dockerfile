FROM golangboyme/wxocr:latest

RUN pip install flask_cors

COPY main.py /app/main.py

COPY templates /app/templates