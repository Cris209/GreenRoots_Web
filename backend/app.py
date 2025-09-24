from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import bcrypt
import random

# Inicializar Flask
app = Flask(__name__)
CORS(app)


firebase_key = os.getenv("FIREBASE_KEY")
firebase_admin.initialize_app(firebase_key)
db = firestore.client()

usuarios_ref = db.collection("usuarios")

# ----------------------------
# Registro de usuario
# ----------------------------
@app.route("/api/registro", methods=["POST"])
def registro():
    data = request.json
    nombre = data.get("nombre")
    correo = data.get("correo")
    password = data.get("password")
    rol = data.get("rol", "voluntario")  # por defecto voluntario

    if not (nombre and correo and password):
        return jsonify({"error": "Faltan datos"}), 400

    # Verificar si ya existe
    docs = usuarios_ref.where("correo", "==", correo).stream()
    if any(docs):
        return jsonify({"error": "El correo ya está registrado"}), 400

    # 🔐 Encriptar contraseña con bcrypt
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Crear documento con ID de 5 dígitos
    user_id = str(random.randint(10000, 99999))

    usuarios_ref.document(user_id).set({
        "nombre": nombre,
        "correo": correo,
        "contraseña": hashed.decode("utf-8"),  # se guarda encriptada
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

    # Buscar usuario por correo
    docs = usuarios_ref.where("correo", "==", correo).stream()
    user = None
    for doc in docs:
        user = doc.to_dict()
        break

    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # 🔐 Comparar contraseña ingresada con la encriptada en Firebase
    if not bcrypt.checkpw(password.encode("utf-8"), user["contraseña"].encode("utf-8")):
        return jsonify({"error": "Contraseña incorrecta"}), 401

    return jsonify({
        "mensaje": "Login exitoso",
        "usuario": {
            "nombre": user["nombre"],
            "correo": user["correo"],
            "rol": user["rol"]
        }
    }), 200


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

