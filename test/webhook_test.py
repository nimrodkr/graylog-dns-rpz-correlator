from flask import Flask, request, jsonify

app = Flask(__name__)


@app.post("/policy")
def policy():
    print("\n===== GRAYLOG WEBHOOK =====")
    print(request.get_json())
    print("===========================\n")

    return jsonify({"status": "ok"})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000
    )