FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

# Ignore root user warning by setting environment variable
ENV PIP_ROOT_USER_ACTION=ignore

# Upgrade pip first (optional, but recommended)
RUN pip install --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PGSSLMODE=verify-ca

CMD ["python", "main.py"]
