FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

ENV FLAG="flag{l0g0ut_sh0uld_k1ll_s3rv3r_s3ss10n}"

EXPOSE 5000

CMD ["python", "app.py"]
