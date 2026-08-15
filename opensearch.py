#!/usr/bin/env python3
"""
lookup_listener.py
Minimal HTTP server that listens on 127.0.0.1:5000 and prints every
GET /lookup?domain=... request it receives (e.g. from a Graylog HTTP
JSONPath data adapter).

Run:
    python3 lookup_listener.py
Stop:
    Ctrl+C
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json
import datetime
import urllib.request
import urllib.error
import time

HOST = "127.0.0.1"
PORT = 5000

# --- OpenSearch / Graylog index settings ---
OPENSEARCH_URL = "http://localhost:9200"
INDEX_PATTERN = "graylog_*"
TIME_WINDOW = "120s"     # how far back to search, e.g. "now-120s"
QUERY_SIZE = 50
REQUEST_TIMEOUT = 5      # seconds
DEBUG = True             # print raw query + OpenSearch response for troubleshooting
RETRY_COUNT = 3          # how many times to retry the full attempt sequence
RETRY_DELAY = 1.0        # seconds to wait between retries (indexing lag)


def get_root_domain(domain: str) -> str:
    """
    Very simple root-domain fallback: keep the last two labels.
    www.123.com -> 123.com
    x1.c.lencr.org -> lencr.org
    Returns the same domain if it already has 2 or fewer labels.
    """
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain


def wrap_domain_markdown(domain: str) -> str:
    """
    domain_full is indexed as a markdown link, e.g.:
      www.a10networks.com -> [www.a10networks.com](https://www.a10networks.com)
    """
    return f"[{domain}](https://{domain})"


def query_opensearch(field: str, value: str, query_type: str = "term"):
    """
    Query OpenSearch for the most recent log entry matching `field` = `value`
    (exact "term" match, or "wildcard" pattern match), with an existing
    client_ip field, within the configured time window.
    Returns the parsed JSON response dict, or None on error.
    """
    if query_type == "wildcard":
        match_clause = {"wildcard": {field: {"value": value}}}
    else:
        match_clause = {"term": {field: value}}

    body = {
        "size": QUERY_SIZE,
        "_source": True,
        "query": {
            "bool": {
                "must": [
                    match_clause,
                    {"exists": {"field": "client_ip"}},
                    {"range": {"timestamp": {"gte": f"now-{TIME_WINDOW}", "lte": "now"}}},
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
    }

    url = f"{OPENSEARCH_URL}/{INDEX_PATTERN}/_search"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if DEBUG:
        print(f"    [debug] query -> {url}")
        print(f"    [debug] body  -> {json.dumps(body)}")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            if DEBUG:
                print(f"    [debug] response -> {raw[:1000]}")
            return json.loads(raw)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        print(f"    [!] OpenSearch query failed: {e}")
        return None


def _collect_ips(result):
    """
    Return a list of unique client_ip values from all hits, preserving
    order (hits are already sorted newest-first by the query).
    """
    hits = (result or {}).get("hits", {}).get("hits", [])
    ips = []
    for hit in hits:
        ip = hit.get("_source", {}).get("client_ip")
        if ip and ip not in ips:
            ips.append(ip)
    return ips



def find_client_ip(domain: str):
    """
    Try, in order:
      1. domain_full = markdown-wrapped domain (how the field is actually stored)
      2. domain_full = plain domain (in case some entries aren't wrapped)
      3. domain = root domain, using the pre-extracted "domain" field
         (Graylog's own pipeline already computes this, so it's more
         reliable than a hand-rolled last-two-labels split)
    Returns (client_ips, matched_value, match_type) or (None, None, None).
    client_ips is a comma-separated string of unique IPs (newest hit first)
    when more than one distinct client_ip was found among matching entries.
    """
    attempts = [
        ("domain_full", wrap_domain_markdown(domain), "domain_full_markdown", "term"),
        ("domain_full", domain, "domain_full_plain", "term"),
        ("domain", get_root_domain(domain), "root_domain_field", "term"),
        ("domain_full", f"*{get_root_domain(domain)}*", "domain_full_wildcard", "wildcard"),
    ]

    for round_num in range(1, RETRY_COUNT + 1):
        for field, value, label, query_type in attempts:
            ips = _collect_ips(query_opensearch(field, value, query_type))
            if ips:
                return ",".join(ips), value, label

        if round_num < RETRY_COUNT:
            if DEBUG:
                print(f"    [debug] no match on round {round_num}, retrying in {RETRY_DELAY}s "
                      f"(indexing lag?)")
            time.sleep(RETRY_DELAY)

    return None, None, None


class LookupHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # silence default access logging; we print our own formatted line
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        domain = query.get("domain", [None])[0]
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"[{ts}] GET {self.path}")
        print(f"    Client       : {self.client_address[0]}:{self.client_address[1]}")
        print(f"    Path         : {parsed.path}")
        print(f"    Query params : {query}")
        print(f"    domain       : {domain}")

        client_ips, matched_domain, match_type = (None, None, None)
        if domain:
            client_ips, matched_domain, match_type = find_client_ip(domain)

        print(f"    matched_on   : {match_type} ({matched_domain})")
        print(f"    client_ip(s) : {client_ips}")
        print("-" * 60)

        # Graylog's HTTP JSONPath data adapter is configured with:
        #   Single value JSONPath = $.lookup.client_ip
        # so the response must have a top-level "lookup" object containing
        # a "client_ip" key. If multiple log entries matched, client_ip is
        # a single comma-separated string, e.g. "100.0.0.1,100.0.0.2".
        # Extra diagnostic fields are kept alongside it (Graylog simply
        # ignores anything outside the configured path).
        response_body = {
            "lookup": {
                "client_ip": client_ips,
            },
            "domain": domain,
            "matched_domain": matched_domain,
            "match_type": match_type,   # "domain_full_markdown", "domain_full_plain", "root_domain_field", "domain_full_wildcard", or None
        }
        body = json.dumps(response_body).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = HTTPServer((HOST, PORT), LookupHandler)
    print(f"Listening on http://{HOST}:{PORT}/lookup ... (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
