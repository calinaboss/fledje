// functions/api/leaderboard.js
// Global Leaderboard & Score submission with validation

const DEFAULT_SECRET = "fledje_game_public_repo_default_secret_salt_2026";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

async function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [payloadStr, sigHex] = token.split('.');
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sigBytes = new Uint8Array(sigHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payloadStr));

    if (!isValid) return null;

    const payload = JSON.parse(atob(payloadStr));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// GET: Top 30 High Scores
export async function onRequestGet(context) {
  const { request, env } = context;
  const db = env.DB;

  if (!db) {
    return jsonResponse({
      error: "Database not connected",
      leaderboard: []
    }, 500);
  }

  const url = new URL(request.url);
  const gameMode = url.searchParams.get('mode') || 'classic';

  try {
    const query = `
      SELECT username, MAX(score) as score, MAX(boss_defeated) as boss_defeated, MAX(created_at) as created_at
      FROM scores
      WHERE game_mode = ?
      GROUP BY username
      ORDER BY score DESC
      LIMIT 30
    `;
    const { results } = await db.prepare(query).bind(gameMode).all();

    return jsonResponse({
      success: true,
      game_mode: gameMode,
      leaderboard: results || []
    });
  } catch (err) {
    console.error("Leaderboard GET Error:", err);
    return jsonResponse({ error: "Failed to load leaderboard" }, 500);
  }
}

// POST: Submit a score
export async function onRequestPost(context) {
  const { request, env } = context;
  const db = env.DB;
  const JWT_SECRET = env.JWT_SECRET || DEFAULT_SECRET;

  if (!db) {
    return jsonResponse({ error: "Database not connected" }, 500);
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: "Authentication required to submit score" }, 401);
  }

  const token = authHeader.substring(7);
  const userSession = await verifyToken(token, JWT_SECRET);
  if (!userSession) {
    return jsonResponse({ error: "Session expired or invalid. Please log in again." }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Invalid JSON format" }, 400);
  }

  const { score, game_mode, boss_defeated, duration_sec } = body;

  const numScore = Number(score);
  if (!Number.isInteger(numScore) || numScore < 0 || numScore > 10000000) {
    return jsonResponse({ error: "Invalid score" }, 400);
  }

  const validGameMode = typeof game_mode === 'string' && game_mode.length <= 30 ? game_mode : 'classic';
  const bossBeat = boss_defeated ? 1 : 0;
  const scoreId = crypto.randomUUID();
  const now = Date.now();

  try {
    await db.prepare(`
      INSERT INTO scores (id, user_id, username, score, game_mode, boss_defeated, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(scoreId, userSession.userId, userSession.username, numScore, validGameMode, bossBeat, now).run();

    return jsonResponse({
      success: true,
      message: "Score submitted successfully!",
      score: numScore
    });
  } catch (err) {
    console.error("Leaderboard POST Error:", err);
    return jsonResponse({ error: "Failed to save score" }, 500);
  }
}
