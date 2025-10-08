from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import random
import os
import json
import re
import time
from datetime import datetime, timedelta

# ----------------------------
# Inicializar Flask
# ----------------------------
app = Flask(__name__)

# Configurar CORS
ORIGINS_PERMITIDOS = [
    "http://localhost:5500",  # frontend local
    "https://greenroots-web.onrender.com"   # reemplazar con tu dominio de producción
]
CORS(app, supports_credentials=True, origins=ORIGINS_PERMITIDOS)

# ----------------------------
# Firebase
# ----------------------------
firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_key:
    raise Exception("❌ La variable de entorno FIREBASE_KEY no está configurada en Render")

cred_dict = json.loads(firebase_key)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()
usuarios_ref = db.collection("usuarios")

# ----------------------------
# Control de intentos de login
# ----------------------------
intentos_fallidos = {}
bloqueados = {}

# ----------------------------
# Funciones de validación
# ----------------------------
def validar_nombre(nombre):
    """No caracteres especiales, no obscenos, máximo 30 caracteres"""
    if len(nombre) > 30:
        return False
    if not re.match(r"^[a-zA-Z\s]+$", nombre):
        return False
    # Lista simple de palabras obscenas
    obscenos = ["malo", "obsceno", "tonto"]  
    for palabra in obscenos:
        if palabra in nombre.lower():
            return False
    return True

def validar_contraseña(password):
    """Contraseña >6 caracteres, con mayúsculas, minúsculas, números y especiales"""
    if len(password) < 6:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def validar_correo(correo):
    """Correo con dominio válido y sin caracteres raros"""
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
# Registro de usuario
# ----------------------------
@app.route("/api/registro", methods=["POST"])
def registro():
    data = request.json
    nombre = data.get("nombre")
    correo = data.get("correo")
    password = data.get("password")
    rol = data.get("rol", "voluntario")

    if not (nombre and correo and password):
        return jsonify({"error": "Faltan datos"}), 400

    if not validar_nombre(nombre):
        return jsonify({"error": "Nombre inválido"}), 400

    if not validar_correo(correo):
        return jsonify({"error": "Correo inválido"}), 400

    if not validar_contraseña(password):
        return jsonify({"error": "Contraseña no cumple los requisitos"}), 400

    # Verificar duplicados
    docs = usuarios_ref.where("correo", "==", correo).stream()
    if any(docs):
        return jsonify({"error": "El correo ya está registrado"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    user_id = str(random.randint(10000, 99999))

    usuarios_ref.document(user_id).set({
        "nombre": nombre,
        "correo": correo,
        "contraseña": hashed.decode("utf-8"),
        "rol": rol
    })

    return jsonify({"mensaje": "Usuario registrado con éxito", "id": user_id}), 201

# ----------------------------
# Inicio de sesión
# ----------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    correo = data.get("correo")
    password = data.get("password")

    if not (correo and password):
        return jsonify({"error": "Faltan datos"}), 400

    if esta_bloqueado(correo):
        return jsonify({"error": "Demasiados intentos fallidos. Intenta en 10 min"}), 403

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

    # Crear cookie de sesión por 15 min
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
        correo,  # temporal, idealmente JWT
        httponly=True,
        secure=True,
        samesite="None",
        expires=expiracion
    )

    return respuesta, 200

# ----------------------------
# Verificar sesión activa
# ----------------------------
@app.route("/api/verificar_sesion", methods=["GET"])
def verificar_sesion():
    token = request.cookies.get("session_token")
    if not token:
        return jsonify({"error": "No autorizado"}), 401
    return jsonify({"mensaje": "Sesión activa"}), 200

# ----------------------------
# Cerrar sesión
# ----------------------------
@app.route("/api/logout", methods=["POST"])
def logout():
    resp = make_response(jsonify({"mensaje": "Sesión cerrada"}))
    resp.set_cookie("session_token", "", expires=0)
    return resp, 200

# ----------------------------
# Ejecutar app
# ----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
