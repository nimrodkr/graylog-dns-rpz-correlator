#!/usr/bin/env python3

import os
import re
import sys
import json
import socket
import argparse
from datetime import datetime, timezone

import requests
from requests.auth import HTTPBasicAuth


# ============================================================
# Configuration
# ============================================================

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://127.0.0.1:9200")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "graylog_*")

OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "")

OPENSEARCH_VERIFY_TLS = (
    os.getenv("OPENSEARCH_VERIFY_TLS", "true").lower() == "true"
)

GRAYLOG_HOST = os.getenv("GRAYLOG_HOST", "127.0.0.1")
GRAYLOG_PORT = int(os.getenv("GRAYLOG_PORT", "5140"))

DEBUG = os.getenv("RPZ_DEBUG", "1").lower() in ("1", "true", "yes", "on")
DEBUG_LOG = os.getenv(
    "RPZ_DEBUG_LOG",
    "/tmp/rpz_correlator.log"
)

# Search before/after Policy timestamp
WINDOW_BEFORE_MS = int(os.getenv("WINDOW_BEFORE_MS", "3000"))
WINDOW_AFTER_MS = int(os.getenv("WINDOW_AFTER_MS", "1000"))

REQUEST_TIMEOUT = 5


# ============================================================
# Regex
# ============================================================

POLICY_RE = re.compile(
    r"Policy Zone=(?P<zone>[^,]+),\s*"
    r"Trigger Type=(?P<trigger_type>[^,]+),\s*"
    r"Trigger Reason=(?P<trigger_reason>[^,]+),\s*"
    r"Action Type=(?P<action>[^,]+)"
)

DNS_RE = re.compile(
    r"\bUDP\s+"
    r"(?P<client_ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<client_port>\d+)\s+"
    r"(?P<dns_server>\d+\.\d+\.\d+\.\d+)\s+"
    r"53\s+"
    r"Type=Query\s+"
    r"QueryId=(?P<query_id>\d+).*?"
    r"dhost=(?P<domain>[^\s]+).*?"
    r"QueryType=(?P<query_type>[^\s]+)"
)


# ============================================================
# Debug logging
# ============================================================

def debug_log(message):
    if not DEBUG:
        return

    now = datetime.now().astimezone().isoformat(timespec="milliseconds")
    line = f"{now} {message}"

    with open(DEBUG_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

    print(line)


# ============================================================
# Timestamp handling
# ============================================================

def parse_timestamp(timestamp_string):
    value = timestamp_string.strip()

    # Graylog/OpenSearch format:
    # 2026-08-15 14:27:50.000
    if "T" not in value:
        dt = datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S.%f"
        )
        return dt.replace(tzinfo=timezone.utc)

    # ISO8601 input
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def os_timestamp(dt):
    return dt.astimezone(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]


# ============================================================
# OpenSearch helpers
# ============================================================

def opensearch_auth():
    if OPENSEARCH_USER:
        return HTTPBasicAuth(
            OPENSEARCH_USER,
            OPENSEARCH_PASSWORD
        )
    return None


def opensearch_post(query):
    url = (
        f"{OPENSEARCH_URL.rstrip('/')}/"
        f"{OPENSEARCH_INDEX}/_search"
    )

    response = requests.post(
        url,
        json=query,
        auth=opensearch_auth(),
        verify=OPENSEARCH_VERIFY_TLS,
        timeout=REQUEST_TIMEOUT
    )

    if not response.ok:
        debug_log(
            f"OPENSEARCH_ERROR status={response.status_code} "
            f"body={response.text}"
        )
        response.raise_for_status()

    return response.json()


# ============================================================
# Policy parsing
# ============================================================

def parse_policy_message(message):
    match = POLICY_RE.search(message)

    if not match:
        return None

    data = match.groupdict()

    # Examples:
    # www.facebook.com+5 -> www.facebook.com
    # www.netflix.com    -> www.netflix.com
    domain = re.sub(
        r"\+\d+$",
        "",
        data["trigger_reason"]
    ).lower().rstrip(".")

    domains = [domain]

    # Treat www.domain.com and domain.com as equivalent
    # for this RPZ correlation logic.
    if domain.startswith("www."):
        domains.append(domain[4:])

    data["domain"] = domain
    data["domains"] = domains

    return data


def get_latest_policy():
    query = {
        "size": 1,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "match_phrase": {
                "message": "Policy Zone="
            }
        }
    }

    data = opensearch_post(query)

    hits = data.get("hits", {}).get("hits", [])

    if not hits:
        return None

    hit = hits[0]
    source = hit.get("_source", {})
    message = source.get("message", "")

    parsed = parse_policy_message(message)

    if not parsed:
        return None

    parsed["timestamp"] = source.get("timestamp")
    parsed["policy_id"] = hit.get("_id")
    parsed["message"] = message

    return parsed


# ============================================================
# DNS lookup
# ============================================================

def search_dns_query(domains, policy_timestamp):
    policy_dt = parse_timestamp(policy_timestamp)

    from_ts = policy_dt.timestamp() - (WINDOW_BEFORE_MS / 1000)
    to_ts = policy_dt.timestamp() + (WINDOW_AFTER_MS / 1000)

    from_dt = datetime.fromtimestamp(from_ts, tz=timezone.utc)
    to_dt = datetime.fromtimestamp(to_ts, tz=timezone.utc)

    domain_conditions = []

    for domain in domains:
        domain_conditions.append({
            "match_phrase": {
                "message": f"dhost={domain}"
            }
        })

    query = {
        "size": 20,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "match_phrase": {
                            "message": "Type=Query"
                        }
                    }
                ],
                "should": domain_conditions,
                "minimum_should_match": 1,
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": os_timestamp(from_dt),
                                "lte": os_timestamp(to_dt)
                            }
                        }
                    }
                ]
            }
        }
    }

    debug_log(
        f"SEARCH domains={','.join(domains)} "
        f"from={os_timestamp(from_dt)} "
        f"to={os_timestamp(to_dt)}"
    )

    data = opensearch_post(query)
    hits = data.get("hits", {}).get("hits", [])

    debug_log(
        f"SEARCH_RESULT domains={','.join(domains)} hits={len(hits)}"
    )

    return hits


# ============================================================
# DNS parsing / validation
# ============================================================

def parse_dns_message(message):
    match = DNS_RE.search(message)

    if not match:
        return None

    return match.groupdict()


def find_client_ip(domains, hits):
    valid_domains = {
        domain.lower().rstrip(".")
        for domain in domains
    }

    for hit in hits:
        source = hit.get("_source", {})

        # Prefer already-parsed Graylog fields.
        hit_domain = source.get("dhost")

        if hit_domain:
            hit_domain = (
                str(hit_domain)
                .lower()
                .rstrip(".")
            )

            if hit_domain in valid_domains:
                client_ip = source.get("client_ip")

                if client_ip:
                    return {
                        "client_ip": client_ip,
                        "matched_domain": hit_domain,
                        "query_id": (
                            source.get("QueryId")
                            or source.get("query_id")
                        ),
                        "query_type": (
                            source.get("QueryType")
                            or source.get("query_type")
                        ),
                        "timestamp": source.get("timestamp"),
                        "message": source.get("message", ""),
                        "opensearch_id": hit.get("_id")
                    }

        # Fallback to parsing original A10 DNS message.
        message = source.get("message", "")

        parsed = parse_dns_message(message)

        if not parsed:
            continue

        parsed_domain = (
            parsed["domain"]
            .lower()
            .rstrip(".")
        )

        if parsed_domain not in valid_domains:
            continue

        return {
            "client_ip": parsed["client_ip"],
            "matched_domain": parsed_domain,
            "query_id": parsed["query_id"],
            "query_type": parsed["query_type"],
            "timestamp": source.get("timestamp"),
            "message": message,
            "opensearch_id": hit.get("_id")
        }

    return None


# ============================================================
# Graylog syslog injection
# ============================================================

def send_rpz_match(
    domain,
    client_ip,
    action,
    zone,
    query_id=None,
    query_type=None,
    matched_domain=None,
    policy_id=None
):
    fields = [
        "RPZ_Match",
        f"domain={domain}",
        f"action={action}",
        f"client_ip={client_ip}",
        f"zone={zone}"
    ]

    if matched_domain:
        fields.append(f"matched_domain={matched_domain}")

    if query_id:
        fields.append(f"query_id={query_id}")

    if query_type:
        fields.append(f"query_type={query_type}")

    if policy_id:
        fields.append(f"policy_id={policy_id}")

    message = " ".join(fields)

    hostname = socket.gethostname()

    syslog_message = (
        f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} "
        f"{hostname} RPZ_Correlator: "
        f"{message}"
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:
        sock.sendto(
            syslog_message.encode("utf-8"),
            (GRAYLOG_HOST, GRAYLOG_PORT)
        )
    finally:
        sock.close()

    debug_log(
        f"SENT client_ip={client_ip} "
        f"domain={domain} "
        f"matched_domain={matched_domain} "
        f"action={action} "
        f"zone={zone} "
        f"graylog={GRAYLOG_HOST}:{GRAYLOG_PORT}"
    )

    return syslog_message


# ============================================================
# Manual correlation
# ============================================================

def correlate(
    domains,
    action,
    zone,
    policy_timestamp,
    send=True,
    policy_id=None
):
    hits = search_dns_query(
        domains,
        policy_timestamp
    )

    result = find_client_ip(
        domains,
        hits
    )

    if not result:
        debug_log(
            f"NO_MATCH domains={','.join(domains)} "
            f"action={action} "
            f"zone={zone} "
            f"policy_id={policy_id}"
        )
        return None

    debug_log(
        f"MATCH "
        f"domains={','.join(domains)} "
        f"matched_domain={result.get('matched_domain')} "
        f"client_ip={result['client_ip']} "
        f"query_id={result.get('query_id')} "
        f"query_type={result.get('query_type')} "
        f"dns_timestamp={result.get('timestamp')} "
        f"os_id={result.get('opensearch_id')} "
        f"policy_id={policy_id}"
    )

    if send:
        send_rpz_match(
            domain=domains[0],
            client_ip=result["client_ip"],
            action=action,
            zone=zone,
            query_id=result.get("query_id"),
            query_type=result.get("query_type"),
            matched_domain=result.get("matched_domain"),
            policy_id=policy_id
        )

    return result


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="A10 RPZ / DNS correlator"
    )

    # Manual test mode
    parser.add_argument(
        "--domain",
        help="Policy domain for manual test"
    )

    parser.add_argument(
        "--action",
        default="unknown"
    )

    parser.add_argument(
        "--zone",
        default="unknown"
    )

    parser.add_argument(
        "--timestamp",
        help="Policy event timestamp in ISO8601 or Graylog format"
    )

    # Automatic Policy discovery modes
    parser.add_argument(
        "--show-latest-policy",
        action="store_true",
        help="Show latest Policy message and parsed fields"
    )

    parser.add_argument(
        "--test-latest-policy",
        action="store_true",
        help="Find latest Policy and correlate it"
    )

    parser.add_argument(
        "--no-send",
        action="store_true",
        help="Do not send RPZ_Match to Graylog"
    )

    args = parser.parse_args()

    try:
        # ----------------------------------------------------
        # Show latest Policy only
        # ----------------------------------------------------

        if args.show_latest_policy:
            policy = get_latest_policy()

            if not policy:
                print("No Policy message found")
                return 2

            print(
                json.dumps(
                    policy,
                    indent=2
                )
            )

            return 0

        # ----------------------------------------------------
        # Automatically correlate latest Policy
        # ----------------------------------------------------

        if args.test_latest_policy:
            policy = get_latest_policy()

            if not policy:
                print("No Policy message found")
                return 2

            debug_log(
                f"POLICY "
                f"id={policy['policy_id']} "
                f"domain={policy['domain']} "
                f"candidates={','.join(policy['domains'])} "
                f"action={policy['action']} "
                f"zone={policy['zone']} "
                f"timestamp={policy['timestamp']}"
            )

            result = correlate(
                domains=policy["domains"],
                action=policy["action"],
                zone=policy["zone"],
                policy_timestamp=policy["timestamp"],
                send=not args.no_send,
                policy_id=policy["policy_id"]
            )

            if not result:
                print("No matching DNS query found")
                return 2

            print(
                json.dumps(
                    result,
                    indent=2
                )
            )

            return 0

        # ----------------------------------------------------
        # Manual mode
        # ----------------------------------------------------

        if not args.domain or not args.timestamp:
            parser.error(
                "Manual mode requires --domain and --timestamp, "
                "or use --show-latest-policy / --test-latest-policy"
            )

        domain = args.domain.lower().rstrip(".")

        domains = [domain]

        if domain.startswith("www."):
            domains.append(domain[4:])

        result = correlate(
            domains=domains,
            action=args.action,
            zone=args.zone,
            policy_timestamp=args.timestamp,
            send=not args.no_send
        )

        if not result:
            print("No matching DNS query found")
            return 2

        print(
            json.dumps(
                result,
                indent=2
            )
        )

        return 0

    except requests.RequestException as e:
        debug_log(
            f"ERROR OpenSearch request failed: {e}"
        )

        print(
            f"OpenSearch error: {e}",
            file=sys.stderr
        )

        return 1

    except Exception as e:
        debug_log(
            f"ERROR {type(e).__name__}: {e}"
        )

        print(
            f"Error: {e}",
            file=sys.stderr
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())