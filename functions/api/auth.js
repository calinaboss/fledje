// functions/api/auth.js
// Authentication & Session Token Handler (OWASP PBKDF2 & HMAC-SHA256)

const DEFAULT_SECRET = "fledje_game_public_repo_default_secret_salt_2026";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function hexString(buffer) {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// PBKDF2 secure password hashing
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );

  return hexString(derivedKey);
}

// Generate signed HMAC-SHA256 token
async function generateToken(payload, secret) {
  const enc = new TextEncoder();
  const payloadStr = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(payloadStr));
  const sigHex = hexString(signature);
  return `${payloadStr}.${sigHex}`;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;
  const JWT_SECRET = env.JWT_SECRET || DEFAULT_SECRET;

  if (!db) {
    return jsonResponse({
      error: "Database not connected. Please bind Cloudflare D1 with name 'DB'."
    }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid JSON payload" }, 400);
  }

  const { action, username, password } = body;

  // OWASP Input Validation
  if (!username || typeof username !== 'string') {
    return jsonResponse({ error: "Username is required" }, 400);
  }

  const cleanUsername = username.trim();
  const usernameRegex = /^[a-zA-Z0-9_\-]{3,20}$/;
  if (!usernameRegex.test(cleanUsername)) {
    return jsonResponse({
      error: "Username must be 3-20 characters (alphanumeric, '_' or '-')"
    }, 400);
  }

  if (!password || typeof password !== 'string' || password.length < 4 || password.length > 64) {
    return jsonResponse({
      error: "Password must be between 4 and 64 characters"
    }, 400);
  }

  const now = Date.now();

  try {
    // 1. REGISTER
    if (action === 'register') {
      const existingUser = await db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE")
        .bind(cleanUsername)
        .first();

      if (existingUser) {
        return jsonResponse({ error: "Username already taken! Please login or pick another name." }, 409);
      }

      const randomSalt = hexString(crypto.getRandomValues(new Uint8Array(16)));
      const passwordHash = await hashPassword(password, randomSalt);
      const userId = crypto.randomUUID();

      await db.prepare(`
        INSERT INTO users (id, username, password_hash, salt, created_at, last_login)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(userId, cleanUsername, passwordHash, randomSalt, now, now).run();

      const token = await generateToken({
        userId,
        username: cleanUsername,
        exp: now + 30 * 24 * 60 * 60 * 1000 // 30 days
      }, JWT_SECRET);

      return jsonResponse({
        success: true,
        message: "Registration successful!",
        user: { id: userId, username: cleanUsername },
        token
      }, 201);
    }

    // 2. LOGIN
    else if (action === 'login') {
      const user = await db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE")
        .bind(cleanUsername)
        .first();

      if (!user) {
        return jsonResponse({ error: "Invalid credentials" }, 401);
      }

      const checkHash = await hashPassword(password, user.salt);
      if (checkHash !== user.password_hash) {
        return jsonResponse({ error: "Invalid credentials" }, 401);
      }

      await db.prepare("UPDATE users SET last_login = ? WHERE id = ?")
        .bind(now, user.id)
        .run();

      const token = await generateToken({
        userId: user.id,
        username: user.username,
        exp: now + 30 * 24 * 60 * 60 * 1000
      }, JWT_SECRET);

      return jsonResponse({
        success: true,
        message: "Logged in successfully!",
        user: { id: user.id, username: user.username },
        token
      });
    }

    return jsonResponse({ error: "Invalid action (use 'register' or 'login')" }, 400);

  } catch (err) {
    console.error("Auth DB error:", err);
    return jsonResponse({ error: "Internal authentication error" }, 500);
  }
}
