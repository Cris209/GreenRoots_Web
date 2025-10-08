from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import os
import json
import re
import time
from datetime import datetime, timedelta

# ----------------------------
# CONFIGURACIÓN BASE
# ----------------------------
app = Flask(__name__)

# ----------------------------
# CORS: definir dominios permitidos
# ----------------------------
ORIGINS_PERMITIDOS = [
    "http://localhost:5500",       # si pruebas con servidor local
    "https://greenroots-web.onrender.com",  # dominio de Render
]
CORS(app, supports_credentials=True, origins=ORIGINS_PERMITIDOS)

firebase_key = os.getenv("FIREBASE_KEY")
if not firebase_key:
    raise Exception("❌ FIREBASE_KEY no configurada en Render")

cred_dict = json.loads(firebase_key)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()
usuarios_ref = db.collection("usuarios")

# ----------------------------
# Control de intentos fallidos
# ----------------------------
intentos_fallidos = {}
bloqueados = {}

# ----------------------------
# FUNCIONES DE VALIDACIÓN
# ----------------------------
def validar_correo(correo):
    patron = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(patron, correo)

def validar_nombre(nombre):
    if len(nombre) > 30:
        return False
    patron = r"^[a-zA-Z\s]+$"  # solo letras y espacios
    if not re.match(patron, nombre):
        return False
    # lista simple de palabras prohibidas
    obscenos = ["malo", "palabra1", "palabra2"]
    for p in obscenos:
        if p.lower() in nombre.lower():
            return False
    return True

def validar_contraseña(password):
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
# REGISTRO (solo admin puede agregar)
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
        return jsonify({"error": "Contraseña demasiado débil"}), 400

    # verificar correo único
    docs = usuarios_ref.where("correo", "==", correo).stream()
    if any(docs):
        return jsonify({"error": "El correo ya está registrado"}), 400

    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    user_id = str(int(time.time()*1000))  # id único
    usuarios_ref.document(user_id).set({
        "nombre": nombre,
        "correo": correo,
        "contraseña": hashed.decode("utf-8"),
        "rol": rol
    })

    return jsonify({"mensaje": "Usuario registrado con éxito", "id": user_id}), 201

# ----------------------------
# LOGIN
# ----------------------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    correo = data.get("correo")
    password = data.get("password")
    if not (correo and password):
        return jsonify({"error": "Faltan datos"}), 400
    if esta_bloqueado(correo):
        return jsonify({"error": "Usuario bloqueado. Intenta en 10 minutos"}), 403

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

    # cookie de sesión segura 15 min
    respuesta = make_response(jsonify({
        "mensaje": "Login exitoso",
        "usuario": {"nombre": user["nombre"], "correo": user["correo"], "rol": user["rol"]}
    }))
    expiracion = datetime.utcnow() + timedelta(minutes=15)
    respuesta.set_cookie(
        "session_token",
        correo,
        httponly=True,
        secure=True,
        samesite="None",
        expires=expiracion
    )
    return respuesta, 200

# ----------------------------
# VERIFICAR SESIÓN
# ----------------------------
@app.route("/api/verificar_sesion", methods=["GET"])
def verificar_sesion():
    session_token = request.cookies.get("session_token")
    if not session_token:
        return jsonify({"error": "Sesión expirada o no iniciada"}), 401
    return jsonify({"mensaje": "Sesión activa"}), 200

# ----------------------------
# LOGOUT
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
