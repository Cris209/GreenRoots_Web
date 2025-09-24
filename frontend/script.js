document.getElementById("loginForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  const correo = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  try {
    const response = await fetch("https://greenroots-web.onrender.com/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ correo, password })
    });

    const data = await response.json();

    if (response.ok) {
      alert(`Bienvenido, ${data.usuario.nombre} (Rol: ${data.usuario.rol})`);
      // Redirigir según rol
      if (data.usuario.rol === "administrador") {
        window.location.href = "admin.html";
      } else if (data.usuario.rol === "gobierno") {
        window.location.href = "gobierno.html";
      } else {
        window.location.href = "voluntario.html";
      }
    } else {
      alert(data.error);
    }

  } catch (err) {
    console.error(err);
    alert("Error al conectar con el servidor");
  }
});
