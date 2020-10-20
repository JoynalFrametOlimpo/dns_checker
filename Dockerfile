FROM python:3.9.0-slim-buster
MAINTAINER JoynalFrametOlimpo

RUN set -x; \
    apt-get update 

RUN pip3 install dnspython \
    && pip install python3-nmap  \
    && apt-get install iputils-ping -y

RUN apt-get install python3-nmap -y

RUN mkdir /app

COPY ./dns_checker.py /app

RUN chmod +x /app

