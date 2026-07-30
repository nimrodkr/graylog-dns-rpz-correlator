import requests
from datetime import datetime, timezone
from config import OPENSEARCH_URL, INDEX_PATTERN, MAX_AGE_SECONDS, REQUEST_TIMEOUT


def lookup_domain(domain):
    query = {
        "size": 1,
        "_source": [
            "client_ip",
            "domain",
            "domain_full",
            "timestamp",
            "message"
        ],
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "domain": domain
                        }
                    },
                    {
                        "exists": {
                            "field": "client_ip"
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    r = requests.post(
        f"{OPENSEARCH_URL}/{INDEX_PATTERN}/_search",
        json=query,
        timeout=REQUEST_TIMEOUT
    )

    r.raise_for_status()
    data = r.json()

    #
    # Nothing found
    #
    if data["hits"]["total"]["value"] == 0:
        return {
            "lookup": None
        }

    src = data["hits"]["hits"][0]["_source"]

    ts = datetime.strptime(
        src["timestamp"],
        "%Y-%m-%d %H:%M:%S.%f"
    ).replace(tzinfo=timezone.utc)

    age = int((datetime.now(timezone.utc) - ts).total_seconds())

    #
    # Always return the lookup.
    # Graylog can decide whether it is too old.
    #
    return {
        "lookup": {
            "client_ip": src.get("client_ip"),
            "domain": src.get("domain"),
            "domain_full": src.get("domain_full"),
            "timestamp": src.get("timestamp"),
            "age_seconds": age,
            "stale": age > MAX_AGE_SECONDS
        }
    }
