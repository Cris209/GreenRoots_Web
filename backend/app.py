from flask import Flask, request, jsonify, session, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import re
import os
import json
import random
import time
from datetime import timedelta

# ----------------------------
# Configuración general
# ----------------------------
app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.getenv("SECRET_KEY", "clave_super_secreta")

# Duración de sesión
app.permanent_session_lifetime = timedelta(minutes=15)

# Inicializar Firebase
firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_key:
    raise Exception("❌ La variable de entorno FIREBASE_KEY no está configurada en Render")

cred_dict = json.loads(firebase_key)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()

usuarios_ref = db.collection("usuarios")
intentos_ref = db.collection("intentos_fallidos")

# Lista básica de palabras prohibidas
PALABRAS_OBSCENAS = ["tonto", "idiota", "estupido", "puto", "mierda", "imbecil"]

# ----------------------------
# Validaciones auxiliares
# ----------------------------
def validar_nombre(nombre):
    if len(nombre) > 30:
        return False
    if any(palabra in nombre.lower() for palabra in PALABRAS_OBSCENAS):
        return False
    return re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ ]+$", nombre) is not None

def validar_password(password):
    return bool(re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$", password))

def validar_correo(correo):
    return bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$", correo))

# ----------------------------
# Registro de usuario
# ----------------------------
@app.route("/api/registro", methods=["POST"])
def registro():
    data = request.json
    nombre = data.get("nombre", "").strip()
    correo = data.get("correo", "").strip()
    password = data.get("password", "").strip()
    rol = data.get("rol", "voluntario")

    # Validaciones
    if not (nombre and correo and password):
        return jsonify({"error": "Faltan datos"}), 400
    if not validar_nombre(nombre):
        return jsonify({"error": "Nombre inválido"}), 400
    if not validar_correo(correo):
        return jsonify({"error": "Correo inválido"}), 400
    if not validar_password(password):
        return jsonify({"error": "Contraseña insegura"}), 400

    # Verificar si ya existe
    docs = usuarios_ref.where("correo", "==", correo).stream()
    if any(docs):
        return jsonify({"error": "El correo ya está registrado"}), 400

    # Encriptar contraseña
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Crear documento con ID aleatorio
    user_id = str(random.randint(10000, 99999))

    usuarios_ref.document(user_id).set({
        "nombre": nombre,
        "correo": correo,
        "contraseña": hashed.decode("utf-8"),
        "rol": rol
    })

    return jsonify({"mensaje": "Usuario registrado con éxito"}), 201

# ----------------------------
# Inicio de sesión
# ----------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    correo = data.get("correo", "").strip()
    password = data.get("password", "").strip()

    if not (correo and password):
        return jsonify({"error": "Faltan datos"}), 400

    # Buscar usuario
    docs = usuarios_ref.where("correo", "==", correo).limit(1).stream()
    user = next((doc.to_dict() for doc in docs), None)

    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Comprobar bloqueos
    intento_doc = intentos_ref.document(correo).get()
    if intento_doc.exists:
        intento_data = intento_doc.to_dict()
        if intento_data["intentos"] >= 3 and time.time() - intento_data["ultimo_intento"] < 600:
            return jsonify({"error": "Cuenta bloqueada temporalmente. Intenta más tarde."}), 403

    # Validar contraseña
    if not bcrypt.checkpw(password.encode("utf-8"), user["contraseña"].encode("utf-8")):
        intentos_ref.document(correo).set({
            "intentos": (intento_doc.to_dict()["intentos"] + 1 if intento_doc.exists else 1),
            "ultimo_intento": time.time()
        })
        return jsonify({"error": "Credenciales incorrectas"}), 401

    # Restablecer intentos fallidos
    intentos_ref.document(correo).set({"intentos": 0, "ultimo_intento": time.time()})

    # Crear sesión
    session.permanent = True
    session["usuario"] = {"correo": user["correo"], "rol": user["rol"], "nombre": user["nombre"]}

    resp = make_response(jsonify({
        "mensaje": "Inicio de sesión exitoso",
        "usuario": session["usuario"]
    }))
    resp.set_cookie("session_id", session["usuario"]["correo"], max_age=900, httponly=True, secure=True, samesite="None")

    return resp, 200

# ----------------------------
# Verificación de sesión
# ----------------------------
@app.route("/api/verificar_sesion", methods=["GET"])
def verificar_sesion():
    if "usuario" in session:
        return jsonify({"logueado": True, "usuario": session["usuario"]})
    return jsonify({"logueado": False}), 401

# ----------------------------
# Cierre de sesión
# ----------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    resp = make_response(jsonify({"mensaje": "Sesión cerrada"}))
    resp.delete_cookie("session_id")
    return resp, 200

# ----------------------------
# Ejecución
# ----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
