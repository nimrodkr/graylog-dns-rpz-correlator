# Graylog DNS Client IP Lookup Service

## Overview

The **Graylog DNS Client IP Lookup Service** provides a lightweight HTTP API that allows Graylog Lookup Tables to correlate DNS policy events with the originating client IP address.

When Graylog receives a DNS Policy (RPZ) event, it typically contains only the queried domain and the action taken (DROP, NODATA, NXDOMAIN, etc.), but not the client IP that generated the request.

This service bridges that gap by searching recent DNS query logs stored in OpenSearch and returning the matching client IP(s) based on the requested domain.

The service was designed specifically for Graylog Data Adapters but can be integrated with any system capable of issuing HTTP GET requests.

---

## Features

* Lightweight Python HTTP service
* Compatible with Graylog HTTP JSONPath Data Adapters
* Searches recent DNS queries stored in OpenSearch
* Supports multiple lookup strategies
* Automatically retries searches to compensate for indexing delays
* Returns multiple unique client IPs when applicable
* Provides detailed debug logging
* Requires no external database

---

## Lookup Workflow

For every lookup request, the service searches OpenSearch using the following sequence:

1. Exact match against `domain_full` (Markdown formatted)
2. Exact match against `domain_full` (plain text)
3. Match against the extracted root `domain`
4. Wildcard search on the root domain

The first successful lookup is returned.

If no match is found, the service retries several times before returning an empty result to compensate for OpenSearch indexing latency.

---

## Example Request

```
GET /lookup?domain=www.example.com
```

---

## Example Response

```json
{
  "lookup": {
    "client_ip": "192.168.1.10"
  },
  "domain": "www.example.com",
  "matched_domain": "[www.example.com](https://www.example.com)",
  "match_type": "domain_full_markdown"
}
```

If multiple DNS clients queried the same domain within the configured time window:

```json
{
  "lookup": {
    "client_ip": "192.168.1.10,192.168.1.11"
  }
}
```

---

## Configuration

The following parameters can be adjusted inside the source code:

| Parameter         | Description                         |
| ----------------- | ----------------------------------- |
| `OPENSEARCH_URL`  | OpenSearch endpoint                 |
| `INDEX_PATTERN`   | Index pattern to search             |
| `TIME_WINDOW`     | Search window (default 120 seconds) |
| `QUERY_SIZE`      | Maximum search results              |
| `REQUEST_TIMEOUT` | OpenSearch request timeout          |
| `RETRY_COUNT`     | Number of retry attempts            |
| `RETRY_DELAY`     | Delay between retries               |
| `DEBUG`           | Enable verbose logging              |

---

## Graylog Configuration

Create an HTTP JSONPath Data Adapter.

Example URL:

```
http://127.0.0.1:5000/lookup?domain=${message.domain_full}
```

Configure the JSONPath expression as:

```
$.lookup.client_ip
```

The adapter returns the client IP associated with the DNS request, allowing Graylog Pipelines to enrich RPZ events with the originating client address.

---

## Running the Service

Start the service:

```bash
python3 lookup_listener.py
```

or

```bash
python3 app.py
```

The service listens on:

```
http://127.0.0.1:5000
```

Health check:

```
GET /health
```

Lookup endpoint:

```
GET /lookup?domain=<domain>
```

---

## Requirements

* Python 3.9+
* OpenSearch
* Graylog
* DNS query logs indexed in OpenSearch
* Python packages:

  * Flask (for the Flask implementation)
  * opensearch-py (if using the Flask wrapper)
  * Standard Python libraries

---

## Typical Use Case

1. A DNS client queries a domain.
2. Graylog stores the DNS query log.
3. A DNS RPZ policy event is received.
4. Graylog Lookup Table calls this service with the domain.
5. The service searches recent DNS query logs.
6. The matching client IP(s) are returned.
7. Graylog enriches the RPZ event with the client IP for dashboards, alerts, and investigations.

---

## Logging

When debug mode is enabled, the service prints:

* Incoming HTTP requests
* Search strategy used
* OpenSearch queries
* OpenSearch responses
* Matching client IPs
* Retry attempts

This greatly simplifies troubleshooting and validation.

---

## License

MIT License.
