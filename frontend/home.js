// DOM Elements
const volunteerForm = document.getElementById('volunteerForm');
const novedadesSection = document.getElementById('novedades');
const novedadesLink = document.getElementById('novedades-link');
const monterreyMap = document.getElementById('monterrey-map');

//Navegacion
function scrollToSection(sectionId) {
    const section = document.getElementById(sectionId);
    const headerHeight = 80;
    const targetPosition = section.offsetTop - headerHeight;
    
    window.scrollTo({
        top: targetPosition,
        behavior: 'smooth'
    });
}

//Barra de Menu
const hamburger = document.querySelector('.hamburger');
const navMenu = document.querySelector('.nav-menu');

hamburger.addEventListener('click', () => {
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
});

// Se cierra el menu al hacer click en el enlace
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', () => {
        hamburger.classList.remove('active');
        navMenu.classList.remove('active');
    });
});

// Desplazamiento suave para enlaces de navegación
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href').substring(1);
        scrollToSection(targetId);
    });
});

// Se cambia de fondo del encabezado al desplazarse
window.addEventListener('scroll', () => {
    const header = document.querySelector('.header');
    if (window.scrollY > 100) {
        header.style.background = 'rgba(45, 95, 79, 0.95)';
        header.style.backdropFilter = 'blur(10px)';
    } else {
        header.style.background = 'linear-gradient(135deg, var(--primary-green), var(--light-green))';
        header.style.backdropFilter = 'none';
    }
});

// Mapa interactivo de Monterrey improvisado y temporal
function initializeMap() {
    const mapPoints = [
        { x: '15%', y: '25%', name: 'Cerro de la Silla', planted: false },
        { x: '30%', y: '40%', name: 'Parque Fundidora', planted: true },
        { x: '60%', y: '30%', name: 'Cerro del Mirador', planted: false },
        { x: '45%', y: '55%', name: 'Macroplaza', planted: true },
        { x: '70%', y: '60%', name: 'Parque Ecológico Chipinque', planted: false },
        { x: '25%', y: '70%', name: 'Santa Catarina', planted: false },
        { x: '80%', y: '45%', name: 'San Pedro Garza García', planted: true },
        { x: '20%', y: '50%', name: 'Escobedo', planted: false },
        { x: '55%', y: '75%', name: 'General Zuazua', planted: false },
        { x: '75%', y: '25%', name: 'Guadalupe', planted: false }
    ];

    mapPoints.forEach((point, index) => {
        const gpsPoint = document.createElement('div');
        gpsPoint.className = `gps-point ${point.planted ? 'planted' : ''}`;
        gpsPoint.style.left = point.x;
        gpsPoint.style.top = point.y;
        
        // Agrega informacion
        const tooltip = document.createElement('div');
        tooltip.className = 'gps-tooltip';
        tooltip.textContent = `${point.name} - ${point.planted ? 'Árbol plantado' : 'Disponible para plantar'}`;
        gpsPoint.appendChild(tooltip);
        
        // Agrega click de evento
        gpsPoint.addEventListener('click', () => {
            showPointInfo(point);
        });
        
        monterreyMap.appendChild(gpsPoint);
    });
}

function showPointInfo(point) {
    const message = point.planted 
        ? `¡Excelente! Ya hay un árbol plantado en ${point.name}. Gracias por contribuir al medio ambiente.`
        : `${point.name} está disponible para plantación. ¡Únete al voluntariado para participar!`;
    
    // Crear alerta moderno 
    const modal = document.createElement('div');
    modal.className = 'custom-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <i class="fas ${point.planted ? 'fa-tree' : 'fa-map-marker-alt'}"></i>
                <h3>${point.name}</h3>
            </div>
            <div class="modal-body">
                <p>${message}</p>
                ${!point.planted ? '<p><strong>¿Te interesa plantar aquí?</strong> Regístrate como voluntario para participar en nuestras actividades de reforestación.</p>' : ''}
            </div>
            <div class="modal-footer">
                <button onclick="closeModal()" class="modal-btn">Cerrar</button>
                ${!point.planted ? '<button onclick="scrollToVolunteer()" class="modal-btn primary">Ser Voluntario</button>' : ''}
            </div>
        </div>
    `;
    
    //Agrega un estilo modal
    const modalStyles = `
        .custom-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
            animation: fadeIn 0.3s ease;
        }
        .modal-content {
            background: white;
            padding: 0;
            border-radius: 15px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            animation: slideUp 0.3s ease;
        }
        .modal-header {
            background: linear-gradient(135deg, var(--primary-green), var(--accent-green));
            color: white;
            padding: 1.5rem;
            border-radius: 15px 15px 0 0;
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        .modal-header i {
            font-size: 1.5rem;
        }
        .modal-header h3 {
            margin: 0;
            font-size: 1.3rem;
        }
        .modal-body {
            padding: 1.5rem;
            line-height: 1.6;
        }
        .modal-footer {
            padding: 1rem 1.5rem;
            display: flex;
            gap: 1rem;
            justify-content: flex-end;
            border-top: 1px solid #f0f0f0;
        }
        .modal-btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .modal-btn:not(.primary) {
            background: #f8f9fa;
            color: #6c757d;
        }
        .modal-btn.primary {
            background: linear-gradient(45deg, var(--primary-green), var(--accent-green));
            color: white;
        }
        .modal-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        @keyframes slideUp {
            from { transform: translateY(50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    `;
    
    // Estilo de encabezado 
    if (!document.getElementById('modal-styles')) {
        const style = document.createElement('style');
        style.id = 'modal-styles';
        style.textContent = modalStyles;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(modal);
    
    // Cerrar modal al hacer clic en segundo plano
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
}

function closeModal() {
    const modal = document.querySelector('.custom-modal');
    if (modal) {
        modal.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => {
            modal.remove();
        }, 300);
    }
}

function scrollToVolunteer() {
    closeModal();
    scrollToSection('voluntariado');
}

// Formularios de voluntarios
let isVolunteerRegistered = localStorage.getItem('volunteerRegistered') === 'true';

// Comprueba si el usuario ya está registrado y muestra la sección de noticias
if (isVolunteerRegistered) {
    showNewsSection();
}

function showNewsSection() {
    novedadesSection.style.display = 'block';
    novedadesLink.style.display = 'block';
    novedadesLink.style.color = '#4a8269';
    novedadesLink.style.fontWeight = '600';
    
    // Añade un pequeño indicador
    if (!novedadesLink.querySelector('.new-indicator')) {
        const indicator = document.createElement('span');
        indicator.className = 'new-indicator';
        indicator.textContent = '●';
        indicator.style.color = '#27ae60';
        indicator.style.marginLeft = '5px';
        indicator.style.animation = 'pulse 2s infinite';
        novedadesLink.appendChild(indicator);
    }
}

volunteerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    // Obtener datos del formulario
    const formData = new FormData(volunteerForm);
    const volunteerData = {};
    
    for (let [key, value] of formData.entries()) {
        volunteerData[key] = value;
    }
    
    // Valida el formulario
    if (!formData.get('terminos')) {
        showNotification('Por favor, acepta los términos y condiciones.', 'error');
        return;
    }
    
    // Mostrar estado de carga
    const submitBtn = volunteerForm.querySelector('.submit-btn');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Registrando...';
    submitBtn.disabled = true;
    
    // Simula llamada de API
    setTimeout(() => {
        // Guardar datos de registro
        localStorage.setItem('volunteerData', JSON.stringify(volunteerData));
        localStorage.setItem('volunteerRegistered', 'true');
        isVolunteerRegistered = true;
        
        //Resetea formulario
        volunteerForm.reset();
        
        // Mostrar mensaje de éxito
        showNotification('¡Registro exitoso! Bienvenido al equipo Green Roots. Ahora tienes acceso a la sección de novedades.', 'success');
        
        // Mostrar sección de noticias
        showNewsSection();
        
        // Desplazarse a la sección de noticias
        setTimeout(() => {
            scrollToSection('novedades');
        }, 1500);
        
        // botón de reinicio
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
        
    }, 2000);
});

// Sistema de notificación
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icon = type === 'success' ? 'fa-check-circle' : 
                 type === 'error' ? 'fa-exclamation-circle' : 
                 'fa-info-circle';
    
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas ${icon}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="closeNotification(this)">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Añade estilo de notificaciones
    const notificationStyles = `
        .notification {
            position: fixed;
            top: 100px;
            right: 20px;
            max-width: 400px;
            padding: 1rem;
            border-radius: 10px;
            color: white;
            z-index: 10000;
            animation: slideInRight 0.5s ease;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
        }
        .notification.success {
            background: linear-gradient(135deg, #27ae60, #2ecc71);
        }
        .notification.error {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }
        .notification.info {
            background: linear-gradient(135deg, #3498db, #2980b9);
        }
        .notification-content {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex: 1;
        }
        .notification-content i {
            font-size: 1.2rem;
        }
        .notification-close {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            padding: 0.25rem;
            border-radius: 50%;
            transition: background-color 0.3s ease;
        }
        .notification-close:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        @keyframes slideInRight {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutRight {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    
    // añade estilo de encabezado
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = notificationStyles;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Se remueve automaticamente despues de 5 segundos 
    setTimeout(() => {
        closeNotification(notification.querySelector('.notification-close'));
    }, 5000);
}

function closeNotification(button) {
    const notification = button.closest('.notification');
    notification.style.animation = 'slideOutRight 0.5s ease forwards';
    setTimeout(() => {
        notification.remove();
    }, 500);
}

// Intersection Observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.animation = 'fadeInUp 0.8s ease forwards';
        }
    });
}, observerOptions);

// Elementos para animacion 
document.addEventListener('DOMContentLoaded', () => {
    const animateElements = document.querySelectorAll('.info-card, .stat-item, .benefit-item, .feature-card');
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        observer.observe(el);
    });
});

// Inicia el mapa al cargar la página
document.addEventListener('DOMContentLoaded', () => {
    initializeMap();
});

// Añade animacion de desvanecido
const additionalStyles = `
    @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
    }
    
    .nav-menu.active {
        display: flex !important;
        flex-direction: column;
        position: absolute;
        top: 100%;
        left: 0;
        width: 100%;
        background: var(--primary-green);
        padding: 1rem 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }
    
    .hamburger.active span:nth-child(1) {
        transform: rotate(-45deg) translate(-5px, 6px);
    }
    
    .hamburger.active span:nth-child(2) {
        opacity: 0;
    }
    
    .hamburger.active span:nth-child(3) {
        transform: rotate(45deg) translate(-5px, -6px);
    }
    
    @media (max-width: 768px) {
        .nav-menu {
            display: none;
        }
    }
`;

// estilos adicionales
const additionalStyleSheet = document.createElement('style');
additionalStyleSheet.textContent = additionalStyles;
document.head.appendChild(additionalStyleSheet);

//Mensaje de bienvenida
console.log(`
 Welcome to Green Roots!
============================
Una plataforma dedicada a la reforestación y consciencia ambiental.
Desarrollado con HTML, CSS y JavaScript vanilla.

Features:
- Información sobre reforestación y deforestación
- Mapa interactivo de Monterrey con puntos GPS
- Sistema de registro de voluntarios
- Sección de novedades para usuarios registrados
- Diseño responsivo y moderno

¡Gracias por ser parte del cambio! 🌍
`);
