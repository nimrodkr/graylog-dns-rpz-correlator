# DNS Lookup Service

## Install
pip3 install -r requirements.txt

## Run
python3 app.py

Health:
curl http://localhost:5000/health

Lookup:
curl "http://localhost:5000/lookup?domain=apple.com"
