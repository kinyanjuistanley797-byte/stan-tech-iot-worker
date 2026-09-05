/**
 * firestoreAuth.js
 * -----------------
 * Cloudflare Workers can't use the firebase-admin SDK (it's built for Node
 * servers), so instead we talk to Firestore's REST API directly. To do that
 * securely, we exchange our service account's private key for a short-lived
 * Google OAuth access token, using the Web Crypto API (built into Workers).
 *
 * The private key itself is stored as a Cloudflare secret (never in code) —
 * see wrangler.toml notes for how it's provided as env.GOOGLE_PRIVATE_KEY
 * and env.GOOGLE_CLIENT_EMAIL.
 */

function base64url(input) {
  let str = typeof input === "string" ? btoa(input) : btoa(String.fromCharCode(...new Uint8Array(input)));
  return str.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

let cachedToken = null;
let cachedTokenExpiry = 0;

export async function getAccessToken(env) {
  // Reuse a cached token if it's still valid for at least another minute.
  if (cachedToken && Date.now() < cachedTokenExpiry - 60000) {
    return cachedToken;
  }

  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claimSet = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedClaim = base64url(JSON.stringify(claimSet));
  const signingInput = `${encodedHeader}.${encodedClaim}`;

  const privateKeyPem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const keyData = pemToArrayBuffer(privateKeyPem);

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  const jwt = `${signingInput}.${base64url(signature)}`;

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) {
    throw new Error("Failed to get access token: " + JSON.stringify(tokenData));
  }

  cachedToken = tokenData.access_token;
  cachedTokenExpiry = Date.now() + tokenData.expires_in * 1000;
  return cachedToken;
}
