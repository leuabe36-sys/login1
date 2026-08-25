// Worker: serves the static login page and handles auth against a D1 database.
// Includes: session cookies, brute-force rate limiting, generic auth errors,
// and security headers on every response.

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bufToHex(arr);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const saltBytes = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  if (email.length === 0 || email.length > 254) return false;
  if (/[\x00-\x1F\x7F]/.test(email)) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidPassword(password) {
  if (typeof password !== "string") return false;
  if (/[\x00-\x1F\x7F]/.test(password)) return false;
  return password.length >= 8 && password.length <= 256;
}

async function verifyTurnstile(token, secretKey, remoteip) {
  if (!token) return false;
  const body = new FormData();
  body.append("secret", secretKey);
  body.append("response", token);
  if (remoteip) body.append("remoteip", remoteip);

  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body,
  });
  const outcome = await res.json();
  return outcome.success === true;
}

// ---- Cookies ----

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  header.split(";").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function sessionCookie(token, maxAgeSeconds) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookie() {
  return `session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// ---- Sessions ----

const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60; // 7 days

async function createSession(env, userId) {
  const token = randomHex(32);
  await env.DB
    .prepare("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+7 days'))")
    .bind(token, userId)
    .run();
  return token;
}

async function getSessionUser(env, token) {
  if (!token) return null;
  const row = await env.DB
    .prepare(
      `SELECT users.id AS id, users.email AS email
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token = ? AND sessions.expires_at > datetime('now')`
    )
    .bind(token)
    .first();
  return row || null;
}

async function deleteSession(env, token) {
  if (!token) return;
  await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
}

// ---- Brute-force protection ----

async function countRecentAttempts(env, identifier, action, windowMinutes) {
  const row = await env.DB
    .prepare(
      "SELECT COUNT(*) AS c FROM login_attempts WHERE identifier = ? AND action = ? AND created_at > datetime('now', ?)"
    )
    .bind(identifier, action, `-${windowMinutes} minutes`)
    .first();
  return row ? row.c : 0;
}

async function recordAttempt(env, identifier, action) {
  await env.DB
    .prepare("INSERT INTO login_attempts (identifier, action) VALUES (?, ?)")
    .bind(identifier, action)
    .run();
}

// ---- Security headers ----

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Content-Security-Policy":
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline'; " +
    "frame-src https://challenges.cloudflare.com; " +
    "connect-src 'self' https://challenges.cloudflare.com; " +
    "img-src 'self' data:; " +
    "base-uri 'self'; " +
    "form-action 'self'",
};

function withSecurityHeaders(response) {
  const newHeaders = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    newHeaders.set(k, v);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}

// ---- Request handling ----

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  if (url.pathname === "/api/signup" && request.method === "POST") {
    try {
      const body = await request.json();
      if (typeof body.email !== "string" || typeof body.password !== "string") {
        return json({ error: "Invalid request." }, 400);
      }

      // Throttle signups per IP: max 5 per hour.
      const signupAttempts = await countRecentAttempts(env, ip, "signup", 60);
      if (signupAttempts >= 5) {
        return json({ error: "Too many accounts created recently. Try again later." }, 429);
      }
      await recordAttempt(env, ip, "signup");

      const verified = await verifyTurnstile(
        body.turnstileToken,
        env.TURNSTILE_SECRET_KEY,
        ip
      );
      if (!verified) {
        return json({ error: "Verification failed. Please try again." }, 403);
      }

      if (!isValidEmail(body.email)) {
        return json({ error: "That email address doesn't look right." }, 400);
      }
      if (!isValidPassword(body.password)) {
        return json({ error: "Password must be 8-256 characters." }, 400);
      }
      const email = normalizeEmail(body.email);
      const password = body.password;

      const existing = await env.DB
        .prepare("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .first();
      if (existing) {
        return json({ error: "An account with that email already exists." }, 409);
      }

      const salt = randomHex(16);
      const hash = await hashPassword(password, salt);

      const inserted = await env.DB
        .prepare("INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?) RETURNING id")
        .bind(email, salt, hash)
        .first();

      const token = await createSession(env, inserted.id);

      return json(
        { ok: true, email },
        200,
        { "Set-Cookie": sessionCookie(token, SESSION_MAX_AGE_SECONDS) }
      );
    } catch (err) {
      return json({ error: "Something went wrong creating your account." }, 500);
    }
  }

  if (url.pathname === "/api/login" && request.method === "POST") {
    try {
      const body = await request.json();
      if (typeof body.email !== "string" || typeof body.password !== "string") {
        return json({ error: "Invalid request." }, 400);
      }

      const email = isValidEmail(body.email) ? normalizeEmail(body.email) : body.email;

      // Lock out after too many recent failures, per email and per IP.
      const emailFails = await countRecentAttempts(env, email, "login-fail", 15);
      const ipFails = await countRecentAttempts(env, ip, "login-fail", 15);
      if (emailFails >= 5 || ipFails >= 20) {
        return json({ error: "Too many attempts. Please try again in a few minutes." }, 429);
      }

      const verified = await verifyTurnstile(
        body.turnstileToken,
        env.TURNSTILE_SECRET_KEY,
        ip
      );
      if (!verified) {
        return json({ error: "Verification failed. Please try again." }, 403);
      }

      if (!isValidEmail(body.email) || !body.password) {
        await recordAttempt(env, email, "login-fail");
        await recordAttempt(env, ip, "login-fail");
        return json({ error: "Invalid email or password." }, 401);
      }

      const user = await env.DB
        .prepare("SELECT id, email, salt, password_hash FROM users WHERE email = ?")
        .bind(email)
        .first();

      if (!user) {
        await recordAttempt(env, email, "login-fail");
        await recordAttempt(env, ip, "login-fail");
        return json({ error: "Invalid email or password." }, 401);
      }

      const hash = await hashPassword(body.password, user.salt);
      if (hash !== user.password_hash) {
        await recordAttempt(env, email, "login-fail");
        await recordAttempt(env, ip, "login-fail");
        return json({ error: "Invalid email or password." }, 401);
      }

      const token = await createSession(env, user.id);

      return json(
        { ok: true, email: user.email },
        200,
        { "Set-Cookie": sessionCookie(token, SESSION_MAX_AGE_SECONDS) }
      );
    } catch (err) {
      return json({ error: "Something went wrong signing you in." }, 500);
    }
  }

  if (url.pathname === "/api/me" && request.method === "GET") {
    const cookies = parseCookies(request);
    const user = await getSessionUser(env, cookies.session);
    if (!user) {
      return json({ error: "Not signed in." }, 401);
    }
    return json({ ok: true, email: user.email });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const cookies = parseCookies(request);
    await deleteSession(env, cookies.session);
    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  // Fall back to static assets (the HTML/CSS/JS front end)
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    const response = await handleRequest(request, env);
    return withSecurityHeaders(response);
  },
};
