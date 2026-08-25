// Worker: serves the static login page and handles /api/signup + /api/login
// against a D1 database of users (email + salted, hashed password).

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomSaltHex(bytes = 16) {
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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function isValidEmail(email) {
  // Reasonable length cap + strict shape check. Rejects control characters,
  // whitespace, and anything that isn't a plausible email address.
  if (typeof email !== "string") return false;
  if (email.length === 0 || email.length > 254) return false;
  if (/[\x00-\x1F\x7F]/.test(email)) return false; // control chars / null bytes
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

function isValidPassword(password) {
  if (typeof password !== "string") return false;
  if (/[\x00-\x1F\x7F]/.test(password)) return false; // control chars / null bytes
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/signup" && request.method === "POST") {
      try {
        const body = await request.json();
        if (typeof body.email !== "string" || typeof body.password !== "string") {
          return json({ error: "Invalid request." }, 400);
        }

        const verified = await verifyTurnstile(
          body.turnstileToken,
          env.TURNSTILE_SECRET_KEY,
          request.headers.get("CF-Connecting-IP")
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

        const salt = randomSaltHex();
        const hash = await hashPassword(password, salt);

        await env.DB
          .prepare("INSERT INTO users (email, salt, password_hash) VALUES (?, ?, ?)")
          .bind(email, salt, hash)
          .run();

        return json({ ok: true, email });
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

        const verified = await verifyTurnstile(
          body.turnstileToken,
          env.TURNSTILE_SECRET_KEY,
          request.headers.get("CF-Connecting-IP")
        );
        if (!verified) {
          return json({ error: "Verification failed. Please try again." }, 403);
        }

        if (!isValidEmail(body.email) || !body.password) {
          return json({ error: "Enter both an email and a password." }, 400);
        }
        const email = normalizeEmail(body.email);
        const password = body.password;

        const user = await env.DB
          .prepare("SELECT email, salt, password_hash FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (!user) {
          return json({ error: "No account found with that email." }, 401);
        }

        const hash = await hashPassword(password, user.salt);
        if (hash !== user.password_hash) {
          return json({ error: "Incorrect password." }, 401);
        }

        return json({ ok: true, email: user.email });
      } catch (err) {
        return json({ error: "Something went wrong signing you in." }, 500);
      }
    }

    // Fall back to static assets (the HTML/CSS/JS front end)
    return env.ASSETS.fetch(request);
  },
};
