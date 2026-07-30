from flask import Flask, request, jsonify
from opensearch import lookup_domain

app=Flask(__name__)

@app.get("/health")
def health():
    return jsonify({"status":"ok"})

@app.get("/lookup")
def lookup():
    domain=request.args.get("domain","").lower().strip()
    if not domain:
        return jsonify({"status":"error","message":"missing domain"}),400
    return jsonify(lookup_domain(domain))

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000)
