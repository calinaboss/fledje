// functions/api/_middleware.js
// OWASP Security Headers & CORS Preflight Handling

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: blob:; media-src 'self' data: blob:;",
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
};

export async function onRequest(context) {
  const { request, next } = context;

  // Gestione OPTIONS Preflight per CORS sicuro
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
        ...SECURITY_HEADERS
      }
    });
  }

  const response = await next();
  const newHeaders = new Headers(response.headers);

  // Applica Security Headers OWASP
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    newHeaders.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}
