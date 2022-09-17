FROM python:3.9

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /var/www/social

COPY requirements.txt /var/www/social

RUN pip install --upgrade pip
RUN pip install -r requirements.txt