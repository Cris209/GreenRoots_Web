// Login
document.getElementById("loginForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  // Obtener valores del formulario
  const correo = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!correo || !password) {
    alert("Por favor completa todos los campos");
    return;
  }

  try {
    // Llamada al backend
    const response = await fetch("https://greenroots-web.onrender.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: correo, // ⚠️ Debe ser 'email' para coincidir con el backend
        password
      })
    });

    const data = await response.json();

    if (response.ok && data.ok) {
      alert(`Bienvenido, ${data.usuario.nombre} 🎉`);
      
      // Redirigir según rol si existe
      if (data.usuario.rol === "administrador") {
        window.location.href = "admin.html";
      } else if (data.usuario.rol === "gobierno") {
        window.location.href = "gobierno.html";
      } else {
        window.location.href = "voluntario.html";
      }

    } else {
      alert(data.mensaje || "Credenciales incorrectas");
    }

  } catch (err) {
    console.error("Error al conectar con el servidor:", err);
    alert("Error al conectar con el servidor");
  }
});
