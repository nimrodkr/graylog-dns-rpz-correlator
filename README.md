# Graylog DNS RPZ Correlator

A lightweight Python service that enriches Graylog RPZ (Response Policy Zone) policy events with the originating DNS client IP address by querying OpenSearch.

## Overview

Many DNS servers generate two separate syslog events:

- A DNS Query event containing the client IP address and requested domain.
- An RPZ Policy event indicating that a DNS policy matched and an action (DROP, NODATA, NXDOMAIN, etc.) was taken.

Unfortunately, RPZ policy events typically do **not** contain the client IP address, making investigations difficult.

This project solves that problem by searching recent DNS query events stored in OpenSearch and returning the matching client IP address to Graylog via an HTTP Lookup Table.

The result is automatic enrichment of RPZ events with the originating client IP.

---

## Features

- Fast OpenSearch lookups
- Designed for Graylog 6.x
- Supports OpenSearch 2.x
- Wildcard domain correlation
- Simple REST API
- Lightweight Flask application
- Easy systemd deployment
- Stale result detection

---

## Architecture

```
                     DNS Query
                         │
                         ▼
                   Graylog Input
                         │
                         ▼
                    OpenSearch
                         ▲
                         │ REST Search
                         │
             Python Lookup Service
                         ▲
                         │ HTTP JSON
             Graylog Lookup Table
                         ▲
                         │
              Graylog Pipeline Rule
                         │
                         ▼
              Enriched RPZ Event
```

---

## Repository Structure

```
.
├── app.py
├── dnslookup.py
├── opensearch.py
├── config.py.example
├── requirements.txt
├── graylog/
├── systemd/
├── screenshots/
└── README.md
```

---

## Requirements

- Python 3.8 or newer
- Graylog 6.x
- OpenSearch 2.x
- Recent DNS query logs indexed in OpenSearch

---

## Installation

Clone the repository:

```bash
git clone https://github.com/nimrodkr/graylog-dns-rpz-correlator.git
cd graylog-dns-rpz-correlator
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create your configuration:

```bash
cp config.py.example config.py
```

Edit **config.py** to match your environment.

---

## Running

Start the application:

```bash
python app.py
```

The service listens on:

```
http://localhost:5000
```

---

## REST API

### Request

```
GET /lookup?domain=facebook.com
```

### Successful Response

```json
{
    "lookup": {
        "client_ip": "192.168.1.55",
        "domain": "facebook.com",
        "domain_full": "www.facebook.com",
        "timestamp": "2026-07-30T09:10:00Z",
        "age_seconds": 3,
        "stale": false
    }
}
```

### No Match

```json
{
    "lookup": null
}
```

---

## Graylog Configuration

### HTTP JSONPath Data Adapter

URL:

```
http://localhost:5000/lookup?domain=${key}
```

JSONPath:

```
$.lookup.client_ip
```

### Pipeline Example

```groovy
let client_ip = lookup_value(
    "dns_lookup",
    to_string(domain_root)
);

set_field("client_ip", client_ip);
```

---

## Example Workflow

1. Client queries:

```
www.facebook.com
```

2. DNS Query log is indexed in OpenSearch.

3. RPZ Policy log is received by Graylog.

4. Pipeline extracts the root domain.

5. Graylog performs an HTTP Lookup.

6. Lookup service searches OpenSearch.

7. Matching client IP is returned.

8. Graylog enriches the RPZ event.

---

## Example Use Case

Original RPZ event:

```
Policy Zone=a10rpz
Trigger Reason=www.facebook.com+5
Action Type=drop
```

After enrichment:

```
client_ip=192.168.1.55
policy_zone=a10rpz
domain_root=facebook.com
action=drop
```

---

## Installing as a systemd Service

Example service file is included under:

```
systemd/
```

Install:

```bash
sudo cp systemd/dnslookup.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dnslookup
sudo systemctl start dnslookup
```

---

## Screenshots

Recommended screenshots:

- Graylog Dashboard
- Lookup Table configuration
- Pipeline Rule
- Search example
- Enriched RPZ event

Place screenshots under:

```
screenshots/
```

---

## Compatibility

Tested with:

- Graylog 6.x
- OpenSearch 2.x
- Ubuntu 20.04
- Python 3.8+

---

## Roadmap

Future improvements include:

- Docker image
- Docker Compose deployment
- Redis cache
- Multi-value lookup support
- Prometheus metrics
- Automatic installer
- Weekly reporting

---

## Contributing

Contributions, suggestions and bug reports are welcome.

Please open an Issue or submit a Pull Request.

---

## License

MIT License

---

## Acknowledgements

Developed to simplify DNS RPZ investigations by automatically correlating DNS query logs with RPZ policy events inside Graylog using OpenSearch.

