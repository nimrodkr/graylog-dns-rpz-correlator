from flask import Flask, request, jsonify
import requests
from datetime import datetime, timezone

app = Flask(__name__)

OPENSEARCH_URL = "http://localhost:9200"
INDEX = "graylog_*"
MAX_AGE_SECONDS = 10


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/lookup")
def lookup():

    domain = request.args.get("domain")

    if not domain:
        return jsonify({
            "status": "error",
            "message": "missing domain"
        }), 400

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
        f"{OPENSEARCH_URL}/{INDEX}/_search",
        json=query,
        timeout=3
    )

    result = r.json()

    if result["hits"]["total"]["value"] == 0:
        return jsonify({"status": "not_found"})

    hit = result["hits"]["hits"][0]["_source"]

    ts = datetime.strptime(
        hit["timestamp"],
        "%Y-%m-%d %H:%M:%S.%f"
    ).replace(tzinfo=timezone.utc)

    age = int((datetime.now(timezone.utc) - ts).total_seconds())

    if age > MAX_AGE_SECONDS:
        return jsonify({
            "status": "stale",
            "age_seconds": age
        })

    return jsonify({
        "status": "found",
        "client_ip": hit["client_ip"],
        "domain": hit["domain"],
        "domain_full": hit["domain_full"],
        "timestamp": hit["timestamp"],
        "age_seconds": age
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
