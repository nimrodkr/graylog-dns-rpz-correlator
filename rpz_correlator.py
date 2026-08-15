#!/usr/bin/env python3

import os
import re
import sys
import time
import socket
import sqlite3
import argparse
from datetime import datetime, timezone, timedelta

import requests
from requests.auth import HTTPBasicAuth


# ============================================================
# Configuration
# ============================================================

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://127.0.0.1:9200")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "graylog_*")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "")
OPENSEARCH_VERIFY_TLS = os.getenv("OPENSEARCH_VERIFY_TLS", "true").lower() == "true"

GRAYLOG_HOST = os.getenv("GRAYLOG_HOST", "127.0.0.1")
GRAYLOG_PORT = int(os.getenv("GRAYLOG_PORT", "5140"))

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
LOOKBACK_SECONDS = int(os.getenv("LOOKBACK_SECONDS", "90"))

WINDOW_BEFORE_MS = int(os.getenv("WINDOW_BEFORE_MS", "3000"))
WINDOW_AFTER_MS = int(os.getenv("WINDOW_AFTER_MS", "1000"))

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "5"))

STATE_DB = os.getenv("STATE_DB", "/var/lib/graylog-dns-rpz-correlator/state.db")

DEBUG = os.getenv("RPZ_DEBUG", "1").lower() in ("1", "true", "yes", "on")
STATE_RETENTION_SECONDS = int(os.getenv("STATE_RETENTION_SECONDS", "300"))


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
# Logging
# ============================================================

def log(message):
    now = datetime.now().astimezone().isoformat(timespec="milliseconds")
    print(f"{now} {message}", flush=True)


def debug(message):
    if DEBUG:
        log(message)


# ============================================================
# OpenSearch
# ============================================================

def opensearch_auth():
    if OPENSEARCH_USER:
        return HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
    return None


def os_timestamp(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def parse_os_timestamp(value):
    return datetime.strptime(
        value,
        "%Y-%m-%d %H:%M:%S.%f"
    ).replace(tzinfo=timezone.utc)


def opensearch_search(query):
    url = f"{OPENSEARCH_URL.rstrip('/')}/{OPENSEARCH_INDEX}/_search"

    response = requests.post(
        url,
        json=query,
        auth=opensearch_auth(),
        verify=OPENSEARCH_VERIFY_TLS,
        timeout=REQUEST_TIMEOUT
    )

    if not response.ok:
        log(
            f"OPENSEARCH_ERROR status={response.status_code} "
            f"body={response.text}"
        )
        response.raise_for_status()

    return response.json()


# ============================================================
# SQLite state
# ============================================================

def init_db():
    state_dir = os.path.dirname(STATE_DB)
    if state_dir:
        os.makedirs(state_dir, exist_ok=True)

    conn = sqlite3.connect(STATE_DB)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS processed_policy (
            policy_id TEXT PRIMARY KEY,
            processed_at TEXT NOT NULL,
            domain TEXT,
            client_ip TEXT,
            client_port TEXT,
            client_endpoint TEXT,
            dns_id TEXT
        )
        """
    )

    conn.commit()
    return conn


def already_processed(conn, policy_id):
    row = conn.execute(
        "SELECT 1 FROM processed_policy WHERE policy_id = ?",
        (policy_id,)
    ).fetchone()

    return row is not None


def mark_processed(
    conn,
    policy_id,
    domain,
    client_ip,
    client_port,
    client_endpoint,
    dns_id
):
    conn.execute(
        """
        INSERT OR IGNORE INTO processed_policy
            (
                policy_id,
                processed_at,
                domain,
                client_ip,
                client_port,
                client_endpoint,
                dns_id
            )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            policy_id,
            datetime.now(timezone.utc).isoformat(),
            domain,
            client_ip,
            client_port,
            client_endpoint,
            dns_id
        )
    )

    conn.commit()


def cleanup_state(conn):
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=STATE_RETENTION_SECONDS
    )

    cursor = conn.execute(
        "DELETE FROM processed_policy WHERE processed_at < ?",
        (cutoff.isoformat(),)
    )

    deleted = cursor.rowcount if cursor.rowcount is not None else 0
    conn.commit()

    if deleted:
        debug(f"STATE_CLEANUP deleted={deleted}")


# ============================================================
# Policy parsing
# ============================================================

def parse_policy_message(message):
    match = POLICY_RE.search(message or "")

    if not match:
        return None

    data = match.groupdict()

    domain = re.sub(
        r"\+\d+$",
        "",
        data["trigger_reason"]
    ).lower().rstrip(".")

    domains = [domain]

    if domain.startswith("www."):
        domains.append(domain[4:])

    data["domain"] = domain
    data["domains"] = list(dict.fromkeys(domains))

    return data


# ============================================================
# DNS parsing / lookup
# ============================================================

def parse_dns_message(message):
    match = DNS_RE.search(message or "")
    return match.groupdict() if match else None


def search_dns_query(domains, policy_timestamp):
    policy_dt = parse_os_timestamp(policy_timestamp)

    from_dt = datetime.fromtimestamp(
        policy_dt.timestamp() - (WINDOW_BEFORE_MS / 1000.0),
        tz=timezone.utc
    )

    to_dt = datetime.fromtimestamp(
        policy_dt.timestamp() + (WINDOW_AFTER_MS / 1000.0),
        tz=timezone.utc
    )

    domain_conditions = [
        {
            "match_phrase": {
                "message": f"dhost={domain}"
            }
        }
        for domain in domains
    ]

    query = {
        "size": 100,
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
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

    debug(
        f"DNS_SEARCH domains={','.join(domains)} "
        f"from={os_timestamp(from_dt)} "
        f"to={os_timestamp(to_dt)}"
    )

    data = opensearch_search(query)
    hits = data.get("hits", {}).get("hits", [])

    debug(
        f"DNS_SEARCH_RESULT domains={','.join(domains)} "
        f"hits={len(hits)}"
    )

    return hits


def build_dns_matches(domains, hits):
    valid_domains = {
        domain.lower().rstrip(".")
        for domain in domains
    }

    matches = []

    for hit in hits:
        source = hit.get("_source", {})
        hit_domain = source.get("dhost")

        if hit_domain:
            hit_domain = str(hit_domain).lower().rstrip(".")

            if hit_domain in valid_domains and source.get("client_ip"):
                client_ip = str(source.get("client_ip"))
                client_port = (
                    source.get("client_port")
                    or source.get("src_port")
                    or source.get("source_port")
                )

                # If Graylog has client_ip parsed but not client_port,
                # try the raw DNS message so CGN client identity is retained.
                if client_port is None:
                    raw_parsed = parse_dns_message(source.get("message", ""))
                    if raw_parsed:
                        client_port = raw_parsed.get("client_port")

                client_port = str(client_port) if client_port is not None else ""

                matches.append({
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "client_endpoint": (
                        f"{client_ip}:{client_port}"
                        if client_port
                        else client_ip
                    ),
                    "matched_domain": hit_domain,
                    "query_id": source.get("QueryId") or source.get("query_id"),
                    "query_type": source.get("QueryType") or source.get("query_type"),
                    "timestamp": source.get("timestamp"),
                    "opensearch_id": hit.get("_id")
                })
                continue

        parsed = parse_dns_message(source.get("message", ""))

        if not parsed:
            continue

        parsed_domain = parsed["domain"].lower().rstrip(".")

        if parsed_domain not in valid_domains:
            continue

        matches.append({
            "client_ip": parsed["client_ip"],
            "client_port": parsed["client_port"],
            "client_endpoint": (
                f"{parsed['client_ip']}:{parsed['client_port']}"
            ),
            "matched_domain": parsed_domain,
            "query_id": parsed["query_id"],
            "query_type": parsed["query_type"],
            "timestamp": source.get("timestamp"),
            "opensearch_id": hit.get("_id")
        })

    return matches


def choose_best_unused_match(policy_timestamp, matches, used_dns_ids):
    """
    Choose the closest DNS event to this Policy timestamp among DNS
    events that have not already been assigned to another Policy
    during this polling cycle.
    """
    policy_dt = parse_os_timestamp(policy_timestamp)

    available = [
        match for match in matches
        if match.get("opensearch_id")
        and match.get("opensearch_id") not in used_dns_ids
        and match.get("timestamp")
    ]

    if not available:
        return None

    def distance(match):
        dns_dt = parse_os_timestamp(match["timestamp"])
        return abs((dns_dt - policy_dt).total_seconds())

    available.sort(
        key=lambda match: (
            distance(match),
            match.get("timestamp", ""),
            match.get("opensearch_id", "")
        )
    )

    return available[0]


# ============================================================
# Policy polling
# ============================================================

def get_recent_policies():
    now = datetime.now(timezone.utc)
    start = now - timedelta(seconds=LOOKBACK_SECONDS)

    query = {
        "size": 1000,
        "sort": [
            {
                "timestamp": {
                    "order": "asc"
                }
            }
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "match_phrase": {
                            "message": "Policy Zone="
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": os_timestamp(start),
                                "lte": os_timestamp(now)
                            }
                        }
                    }
                ]
            }
        }
    }

    debug(
        f"POLICY_SCAN from={os_timestamp(start)} "
        f"to={os_timestamp(now)}"
    )

    data = opensearch_search(query)
    hits = data.get("hits", {}).get("hits", [])

    debug(f"POLICY_SCAN_RESULT hits={len(hits)}")

    return hits


# ============================================================
# Graylog output
# ============================================================

def send_rpz_match(policy, match):
    fields = [
        "RPZ_Match",
        f"domain={policy['domain']}",
        f"action={policy['action']}",
        f"client_ip={match['client_ip']}",
        f"client_port={match.get('client_port', '')}",
        f"client_endpoint={match.get('client_endpoint', match['client_ip'])}",
        f"zone={policy['zone']}",
        f"matched_domain={match.get('matched_domain')}",
        f"query_id={match.get('query_id')}",
        f"query_type={match.get('query_type')}",
        f"policy_id={policy['policy_id']}",
        f"dns_id={match.get('opensearch_id')}"
    ]

    message = " ".join(fields)

    hostname = socket.gethostname()

    syslog_message = (
        f"<134>{datetime.now().strftime('%b %d %H:%M:%S')} "
        f"{hostname} RPZ_Correlator: {message}"
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

    log(
        f"SENT policy_id={policy['policy_id']} "
        f"domain={policy['domain']} "
        f"client_ip={match['client_ip']} "
        f"dns_id={match.get('opensearch_id')} "
        f"graylog={GRAYLOG_HOST}:{GRAYLOG_PORT}"
    )

    return syslog_message


# ============================================================
# Processing
# ============================================================

def process_policy_hit(conn, hit, used_dns_ids, send=False):
    policy_id = hit.get("_id")
    source = hit.get("_source", {})

    if not policy_id:
        return "invalid"

    if already_processed(conn, policy_id):
        debug(f"SKIP_PROCESSED policy_id={policy_id}")
        return "skipped"

    parsed = parse_policy_message(
        source.get("message", "")
    )

    if not parsed:
        log(
            f"POLICY_PARSE_FAILED policy_id={policy_id} "
            f"message={source.get('message', '')!r}"
        )
        return "parse_failed"

    policy_timestamp = source.get("timestamp")

    if not policy_timestamp:
        log(f"POLICY_TIMESTAMP_MISSING policy_id={policy_id}")
        return "timestamp_missing"

    parsed["policy_id"] = policy_id
    parsed["timestamp"] = policy_timestamp

    log(
        f"NEW_POLICY policy_id={policy_id} "
        f"domain={parsed['domain']} "
        f"candidates={','.join(parsed['domains'])} "
        f"action={parsed['action']} "
        f"zone={parsed['zone']} "
        f"timestamp={policy_timestamp}"
    )

    dns_hits = search_dns_query(
        parsed["domains"],
        policy_timestamp
    )

    matches = build_dns_matches(
        parsed["domains"],
        dns_hits
    )

    if not matches:
        log(
            f"NO_MATCH policy_id={policy_id} "
            f"domain={parsed['domain']}"
        )
        return "no_match"

    log(
        f"CANDIDATES policy_id={policy_id} "
        f"domain={parsed['domain']} "
        f"count={len(matches)} "
        f"clients={','.join(match.get('client_endpoint', match['client_ip']) for match in matches)}"
    )

    selected = choose_best_unused_match(
        policy_timestamp,
        matches,
        used_dns_ids
    )

    if not selected:
        log(
            f"NO_UNUSED_MATCH policy_id={policy_id} "
            f"domain={parsed['domain']}"
        )
        return "no_unused_match"

    log(
        f"SELECTED policy_id={policy_id} "
        f"domain={parsed['domain']} "
        f"client_ip={selected['client_ip']} "
        f"client_port={selected.get('client_port', '')} "
        f"client_endpoint={selected.get('client_endpoint', selected['client_ip'])} "
        f"dns_id={selected.get('opensearch_id')} "
        f"dns_timestamp={selected.get('timestamp')}"
    )

    if not send:
        log(
            f"DRY_RUN policy_id={policy_id} "
            f"would_send_client={selected['client_ip']} "
            f"client_port={selected.get('client_port', '')} "
            f"client_endpoint={selected.get('client_endpoint', selected['client_ip'])} "
            f"dns_id={selected.get('opensearch_id')}"
        )
        # Still reserve it for this dry-run cycle so subsequent Policy
        # events demonstrate the intended one-DNS-per-Policy assignment.
        used_dns_ids.add(selected["opensearch_id"])
        return "dry_run"

    send_rpz_match(
        parsed,
        selected
    )

    used_dns_ids.add(
        selected["opensearch_id"]
    )

    mark_processed(
        conn,
        policy_id,
        parsed["domain"],
        selected["client_ip"],
        selected.get("client_port", ""),
        selected.get("client_endpoint", selected["client_ip"]),
        selected.get("opensearch_id")
    )

    return "sent"


def run_cycle(conn, send=False):
    cleanup_state(conn)
    policies = get_recent_policies()

    # This set exists only for the current polling cycle.
    # A DNS record can be assigned to at most one Policy during this cycle.
    used_dns_ids = set()

    stats = {
        "found": len(policies),
        "sent": 0,
        "skipped": 0,
        "no_match": 0,
        "no_unused_match": 0,
        "dry_run": 0,
        "other": 0
    }

    for hit in policies:
        try:
            result = process_policy_hit(
                conn,
                hit,
                used_dns_ids,
                send=send
            )

            if result in stats:
                stats[result] += 1
            else:
                stats["other"] += 1

        except Exception as exc:
            log(
                f"POLICY_ERROR id={hit.get('_id')} "
                f"error={type(exc).__name__}:{exc}"
            )
            stats["other"] += 1

    log(
        "CYCLE_COMPLETE "
        + " ".join(
            f"{key}={value}"
            for key, value in stats.items()
        )
    )

    return stats


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="A10 RPZ polling correlator v3 - one Policy to one CGN-aware DNS/client"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one poll cycle and exit"
    )

    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously"
    )

    parser.add_argument(
        "--send",
        action="store_true",
        help="Actually send RPZ_Match messages to Graylog"
    )

    parser.add_argument(
        "--reset-state",
        action="store_true",
        help="Delete all processed Policy IDs before starting"
    )

    args = parser.parse_args()

    if not args.once and not args.loop:
        args.loop = True
        args.send = True

    conn = init_db()

    if args.reset_state:
        conn.execute("DELETE FROM processed_policy")
        conn.commit()
        log("STATE_RESET")

    mode = "SEND" if args.send else "DRY_RUN"

    log(
        f"START mode={mode} "
        f"interval={POLL_INTERVAL_SECONDS}s "
        f"lookback={LOOKBACK_SECONDS}s "
        f"state_db={STATE_DB}"
    )

    try:
        while True:
            run_cycle(
                conn,
                send=args.send
            )

            if args.once:
                break

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        log("STOP keyboard_interrupt")

    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
