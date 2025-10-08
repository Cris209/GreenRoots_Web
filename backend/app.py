from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import json
import os
import re
import time
from datetime import datetime, timedelta

# ----------------------------
# CONFIGURACIÓN BASE
# ----------------------------
app = Flask(__name__)

# Ajuste de CORS: incluye el dominio de tu frontend y soporta cookies
CORS(app, supports_credentials=True, origins=[
    "https://greenroots-web.onrender.com",  # Cambia esto por tu dominio real
    "http://localhost:5500"           # Para pruebas locales
])

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "mi_clave_segura")

firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_key:
    raise Exception("❌ La variable de entorno FIREBASE_KEY no está configurada")

cred_dict = json.loads(firebase_key)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()

usuarios_ref = db.collection("usuarios")

# Control de intentos fallidos
intentos_fallidos = {}
bloqueados = {}

# ----------------------------
# FUNCIONES DE VALIDACIÓN
# ----------------------------

def validar_correo(correo):
    """Valida que el correo tenga un dominio válido y sin caracteres raros"""
    patron = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(patron, correo)

def esta_bloqueado(correo):
    if correo in bloqueados:
        if time.time() < bloqueados[correo]:
            return True
        else:
            del bloqueados[correo]
    return False

def registrar_intento_fallido(correo):
    if correo not in intentos_fallidos:
        intentos_fallidos[correo] = 0
    intentos_fallidos[correo] += 1

    if intentos_fallidos[correo] >= 3:
        bloqueados[correo] = time.time() + 600  # 10 min
        intentos_fallidos[correo] = 0

def limpiar_intentos(correo):
    if correo in intentos_fallidos:
        del intentos_fallidos[correo]

# ----------------------------
# INICIO DE SESIÓN
# ----------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    correo = data.get("correo")
    password = data.get("password")

    if not (correo and password):
        return jsonify({"error": "Faltan datos"}), 400

    if not validar_correo(correo):
        return jsonify({"error": "Correo inválido"}), 400

    if esta_bloqueado(correo):
        return jsonify({"error": "Demasiados intentos fallidos. Intenta de nuevo en 10 minutos."}), 403

    docs = usuarios_ref.where("correo", "==", correo).stream()
    user = None
    for doc in docs:
        user = doc.to_dict()
        break

    if not user:
        registrar_intento_fallido(correo)
        return jsonify({"error": "Usuario no encontrado"}), 404

    if not bcrypt.checkpw(password.encode("utf-8"), user["contraseña"].encode("utf-8")):
        registrar_intento_fallido(correo)
        return jsonify({"error": "Contraseña incorrecta"}), 401

    limpiar_intentos(correo)

    # Crear cookie de sesión (15 min)
    respuesta = make_response(jsonify({
        "mensaje": "Login exitoso",
        "usuario": {
            "nombre": user["nombre"],
            "correo": user["correo"],
            "rol": user["rol"]
        }
    }))
    expiracion = datetime.utcnow() + timedelta(minutes=15)
    respuesta.set_cookie(
        "session_token",
        correo,  # temporal, idealmente un JWT
        httponly=True,
        secure=True,          # HTTPS obligatorio
        samesite="None",      # permite cookies cross-site
        expires=expiracion
    )

    return respuesta, 200

# ----------------------------
# VERIFICAR SESIÓN ACTIVA
# ----------------------------
@app.route("/api/verificar_sesion", methods=["GET"])
def verificar_sesion():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Sesión expirada o no iniciada"}), 401
    return jsonify({"mensaje": "Sesión activa"}), 200

# ----------------------------
# CERRAR SESIÓN
# ----------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    respuesta = make_response(jsonify({"mensaje": "Sesión cerrada"}))
    respuesta.set_cookie("session_token", "", expires=0)
    return respuesta, 200

# ----------------------------
# EJECUCIÓN
# ----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
