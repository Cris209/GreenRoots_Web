// =================================================================
// SERVICE WORKER: green-roots-cache-v1.2
// ESTRATEGIA: Cache-First con Fallback a Offline Page
// =================================================================

// Nombre de la caché. ¡CAMBIA LA VERSIÓN si modificas la lista urlsToCache!
const CACHE_NAME = 'green-roots-cache-v1.2';

// -----------------------------------------------------------------
// ARCHIVOS A CACHEAR (Debe coincidir con la estructura de tu servidor)
// -----------------------------------------------------------------
const urlsToCache = [
  '/',                     // Raíz del sitio (navegación a /)
  '/index.html',           // Home
  '/login.html',           // Login
  '/registro.html',        // Registro
  
  // Archivos dentro de la subcarpeta 'frontend/'
  '/frontend/styles.css',
  '/frontend/home.css',
  '/frontend/Green_Roots.jpg',
  '/frontend/manifest.json',
  '/frontend/offline.html',
  '/frontend/home_script.js', // Asegúrate de que este script esté incluido si existe
  
  // Librerías CDN (Opcional, pero recomendado si quieres que los estilos funcionen offline)
  'https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// ===========================================
// 1. INSTALACIÓN (Caching de todos los archivos esenciales)
// ===========================================
self.addEventListener('install', event => {
  console.log('SW: Evento Install - Iniciando caching de shell...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        // Añade todos los archivos de la lista a la caché
        return cache.addAll(urlsToCache);
      })
      .then(() => {
          console.log('SW: Caching completado con éxito.');
          self.skipWaiting(); // Forzar la activación inmediata
      })
      .catch(error => {
          console.error('SW: Fallo en addAll. El error puede deberse a que una ruta es incorrecta (404) o un recurso no pudo ser accedido.', error);
          // throw error; // Lanzar el error para que el Service Worker falle y no se instale mal
      })
  );
});

// ===========================================
// 2. ACTIVACIÓN (Limpieza de cachés antiguas)
// ===========================================
self.addEventListener('activate', event => {
  console.log('SW: Evento Activate - Limpiando cachés antiguas...');
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            // Eliminar cachés que no están en la lista blanca
            return caches.delete(cacheName);
          }
        })
      );
    })
    .then(() => self.clients.claim()) // Tomar control de las páginas inmediatamente
  );
});

// ===========================================
// 3. FETCH (Estrategia Cache-First con Fallback)
// ===========================================
self.addEventListener('fetch', event => {
  // Solo manejar peticiones GET. Las de POST (login/registro) deben ir a la red.
  if (event.request.method !== 'GET') return;
  
  // No cachear ni interceptar la API del backend
  if (event.request.url.includes('/api/')) {
    return;
  }

  // Estrategia principal: Intenta buscar en caché, si falla, va a la red.
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // 1. Si el archivo está en caché, lo devolvemos
        if (response) {
          return response;
        }
        
        // 2. Si no está en caché, intentamos obtenerlo de la red
        return fetch(event.request).catch(() => {
            // 3. Si la red falla Y la petición es una navegación (una página HTML),
            //    servimos la página de error offline.html, que debe estar cacheada.
            if (event.request.mode === 'navigate') {
                 return caches.match('/frontend/offline.html'); // Ruta corregida
            }
        });
      })
  );
});
