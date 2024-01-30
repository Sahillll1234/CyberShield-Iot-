import os, ast, socket
from logger import log_to_database
from Cryptography import decrypt_AES_CBC_256
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from flask_caching import Cache 

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
CORS(app)

@app.get("/")
def Home():
    json = request.get_json()
    print(json)
    # return jsonify({"status" : "logged"})
    return render_template("index.html")

@app.post("/decode")
def decode():
    Json = request.get_json()
    encrypted = Json["encrypted"]
    print("encrypted:",encrypted)
    # hash = Json["hash"]
    encryption_key = os.environ.get("AES_KEY")
    decrypted = decrypt_AES_CBC_256(encryption_key, encrypted)
    data = ast.literal_eval(str(decrypted))
    print("decrypted:",decrypted)
    log_to_database(data,Json)
    return jsonify({"status":"received"})

if __name__ == "__main__":
    app.debug=True
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0',0))
    _, port= s.getsockname()
    s.close()

    print(f"using port: {port})")
    app.run(host='0.0.0.0', port=8081)