const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");

// Inicializar Express
const app = express();
app.use(cors());
app.use(express.json());

// Inicializar Firebase con la variable de entorno
if (!process.env.FIREBASE_KEY) {
  throw new Error("❌ La variable de entorno FIREBASE_KEY no está configurada");
}
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// ==========================
// 📌 Ruta: Registro de usuario
// ==========================
app.post("/api/registro", async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password) {
      return res.status(400).json({ ok: false, mensaje: "Faltan datos" });
    }

    // Verificar si el usuario ya existe
    const snapshot = await db.collection("usuarios").where("email", "==", email).limit(1).get();
    if (!snapshot.empty) {
      return res.status(400).json({ ok: false, mensaje: "El usuario ya existe" });
    }

    // Hashear contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guardar usuario en Firestore
    await db.collection("usuarios").add({
      nombre,
      email,
      password: hashedPassword,
      rol,
    });

    res.json({ ok: true, mensaje: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en registro:", error);
    res.status(500).json({ ok: false, mensaje: "Error en el servidor" });
  }
});

// ==========================
// 📌 Ruta: Iniciar sesión
// ==========================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, mensaje: "Faltan datos" });
    }

    // Buscar usuario en Firestore
    const snapshot = await db.collection("usuarios").where("email", "==", email).limit(1).get();

    if (snapshot.empty) {
      return res.status(401).json({ ok: false, mensaje: "Usuario no encontrado" });
    }

    let usuario = null;
    snapshot.forEach((doc) => {
      usuario = doc.data();
    });

    // Verificar contraseña
    const passwordValida = await bcrypt.compare(password, usuario.password);
    if (!passwordValida) {
      return res.status(401).json({ ok: false, mensaje: "Credenciales incorrectas" });
    }

    res.json({ ok: true, mensaje: "Sesión iniciada", usuario: { email: usuario.email, nombre: usuario.nombre, rol: usuario.rol } });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ ok: false, mensaje: "Error en el servidor" });
  }
});

// ==========================
// 📌 Servidor en Render
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Express corriendo en puerto ${PORT}`);
});
