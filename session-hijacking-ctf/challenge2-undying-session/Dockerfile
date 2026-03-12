FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

ENV FLAG="flag{s3ss10ns_sh0uld_3xp1r3_s0m3t1m3}"

EXPOSE 5000

CMD ["python", "app.py"]
