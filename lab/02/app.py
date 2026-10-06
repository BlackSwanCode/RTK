import os
from flask import Flask, request, send_from_directory, Response

app = Flask(__name__)
BASE_DIR = "/tiles"

@app.route("/<path:filepath>", methods=["GET", "OPTIONS"])
def serve(filepath):
    if request.method == "OPTIONS":
        resp = Response(status=204)
    else:
        # Vulnérabilité volontaire : pas de sanitisation du chemin -> traversée
        resp = send_from_directory(BASE_DIR, filepath)
    # Vulnérabilité volontaire : reflet de l'origine + credentials=true
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
