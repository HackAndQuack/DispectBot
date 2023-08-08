FROM ubuntu:20.04

RUN apt-get update && apt-get install -y python3 python3-venv build-essential
RUN useradd -m -u 1000 runner
USER runner
WORKDIR /home/runner
COPY dispect.py emailrepclient.py vtclient.py shodanclient.py requirements.txt ./
RUN python3 -m venv .venv
RUN .venv/bin/pip install -r requirements.txt

ENTRYPOINT [".venv/bin/python", "dispect.py"]