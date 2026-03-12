FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

ENV FLAG="flag{pr3d1ct4bl3_t0k3ns_4r3_n0t_s3cur3}"
ENV ADMIN_PASS="Sup3rS3cr3tAdm1nP@ss!"

EXPOSE 5000

CMD ["python", "app.py"]
