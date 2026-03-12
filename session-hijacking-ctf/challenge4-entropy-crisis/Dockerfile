FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app.py .

ENV FLAG="flag{3ntr0py_m4tt3rs_1000_1s_n0t_3n0ugh}"

EXPOSE 5000

CMD ["python", "app.py"]
