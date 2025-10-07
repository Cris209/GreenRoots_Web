const API_URL = "https://greenroots-web.onrender.com/api";

// -------------------------
// INICIO DE SESIÓN
// -------------------------
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const correo = document.getElementById("correo").value.trim();
  const password = document.getElementById("password").value.trim();
  const mensajeError = document.getElementById("mensaje-error");

  mensajeError.textContent = "";

  try {
    const res = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include", // permite recibir cookie del backend
      body: JSON.stringify({ correo, password })
    });

    const data = await res.json();

    if (!res.ok) {
      mensajeError.textContent = data.error || "Error en el inicio de sesión";
      return;
    }

    // Redirigir si el login es exitoso
    window.location.href = "home.html";
  } catch (err) {
    console.error("Error al iniciar sesión:", err);
    mensajeError.textContent = "Error de conexión con el servidor.";
  }
});

// -------------------------
// VERIFICAR SESIÓN ACTIVA
// -------------------------
async function verificarSesion() {
  try {
    const res = await fetch(`${API_URL}/verificar_sesion`, {
      method: "GET",
      credentials: "include",
    });

    if (!res.ok) {
      window.location.href = "index.html"; // si no hay sesión, volver al login
    }
  } catch (err) {
    console.error("Error verificando sesión:", err);
    window.location.href = "index.html";
  }
}

// -------------------------
// CERRAR SESIÓN
// -------------------------
async function cerrarSesion() {
  try {
    await fetch(`${API_URL}/logout`, {
      method: "POST",
      credentials: "include",
    });
    window.location.href = "index.html";
  } catch (err) {
    console.error("Error al cerrar sesión:", err);
  }
}

// Exportar para usar desde home.html
window.verificarSesion = verificarSesion;
window.cerrarSesion = cerrarSesion;
