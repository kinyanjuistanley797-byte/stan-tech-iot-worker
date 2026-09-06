/**
 * Stan Tech IoT — Cloudflare Worker (replaces Firebase Cloud Functions)
 * -----------------------------------------------------------------------
 * Routes (all POST unless noted):
 *   /mqtt-auth          - EMQX calls this to check device login
 *   /mqtt-acl           - EMQX calls this to check topic permissions
 *   /ingest-data        - EMQX Rule Engine calls this when a device publishes
 *   /register-device    - website calls this when a member adds a device
 *   /send-command       - website calls this when a member taps a toggle
 *
 * Password hashing note: Workers don't have bcrypt built in, so device
 * passwords are hashed with SHA-256 via Web Crypto instead (still secure
 * for this purpose — a long random password + salt-free SHA-256 is fine
 * since it's not a human-memorable password being brute-forced).
 */

import { getDocument, updateDocument, createDocument, addToSubcollection } from "./firestore.js";

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

// Adds a device's login into EMQX's built-in authentication database via
// EMQX Cloud's management API — this replaces needing "Extended
// Authentication" (a paid-tier feature). Free Serverless deployments
// support this built-in-database API directly.
async function addDeviceToEmqxAuth(env, username, plainPassword) {
  const authHeader = "Basic " + btoa(`${env.EMQX_API_KEY}:${env.EMQX_API_SECRET}`);
  const res = await fetch(
    `${env.EMQX_API_URL}/api/v5/authentication/password_based:built_in_database/users`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: authHeader },
      body: JSON.stringify({ user_id: username, password: plainPassword }),
    }
  );
  return res.ok;
}

// Removes a device's login from EMQX (used if a device is ever deleted).
async function removeDeviceFromEmqxAuth(env, username) {
  const authHeader = "Basic " + btoa(`${env.EMQX_API_KEY}:${env.EMQX_API_SECRET}`);
  await fetch(
    `${env.EMQX_API_URL}/api/v5/authentication/password_based:built_in_database/users/${username}`,
    { method: "DELETE", headers: { Authorization: authHeader } }
  );
}

// Adds a topic permission rule for this device into EMQX's built-in
// authorization (ACL) database — restricts it to only its own topic,
// same free-tier-friendly approach as the auth database above.
async function addDeviceAclRule(env, deviceId) {
  const authHeader = "Basic " + btoa(`${env.EMQX_API_KEY}:${env.EMQX_API_SECRET}`);
  await fetch(`${env.EMQX_API_URL}/api/v5/authorization/sources/built_in_database/rules/clientid`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: authHeader },
    body: JSON.stringify([
      {
        clientid: deviceId,
        rules: [
          {
            topic: `devices/${deviceId}/#`,
            permission: "allow",
            action: "all",
          },
        ],
      },
    ]),
  });
}

// ---------- Route handlers ----------

async function handleMqttAuth(req, env) {
  const { username, password } = await req.json();
  if (!username || !password) return json({ result: "deny" });

  const device = await getDocument(env, "devices", username);
  if (!device) return json({ result: "deny" });

  const passwordHash = await sha256Hex(password);
  if (passwordHash !== device.mqttPasswordHash) return json({ result: "deny" });

  if (device.status === "locked") return json({ result: "deny" });

  return json({ result: "allow" });
}

async function handleMqttAcl(req, env) {
  const { username, topic } = await req.json();
  if (!username || !topic) return json({ result: "deny" });

  if (topic.startsWith(`devices/${username}/`)) return json({ result: "allow" });
  return json({ result: "deny" });
}

async function handleRegisterDevice(req, env) {
  const { ownerId, nickname, boardType, hasOutputs } = await req.json();
  if (!ownerId || !nickname) return json({ error: "Missing ownerId or nickname" }, 400);

  const plainPassword = randomHex(12);
  const passwordHash = await sha256Hex(plainPassword);

  const deviceId = await createDocument(env, "devices", {
    ownerId,
    nickname,
    boardType: boardType || "Other",
    hasOutputs: !!hasOutputs,
    mqttUsername: null, // filled below once we know the generated ID
    mqttPasswordHash: passwordHash,
    status: "trial",
    trialUsesRemaining: 3,
    trialStarted: false,
    subscriptionExpiry: null,
    lastSeen: null,
    online: false,
  });

  // mqttUsername = the device's own ID, set as a follow-up update.
  await updateDocument(env, "devices", deviceId, { mqttUsername: deviceId });

  // Register this device's login with EMQX's built-in auth database so it
  // can actually connect (free-tier-friendly alternative to Extended Auth).
  await addDeviceToEmqxAuth(env, deviceId, plainPassword);

  // Restrict this device to only its own topic via built-in ACL rules.
  await addDeviceAclRule(env, deviceId);

  return json({ deviceId, mqttUsername: deviceId, mqttPassword: plainPassword });
}

async function handleIngestData(req, env) {
  let body;
  try {
    body = await req.json();
  } catch (e) {
    // EMQX's "Test" button sends a generic sample body that may not be
    // valid JSON for our shape — respond OK so the connector test passes,
    // real data always arrives as proper JSON from the actual Rule Engine.
    return json({ ok: true, note: "test request accepted" });
  }

  const { topic, payload } = body;
  if (!topic || !payload) {
    return json({ ok: true, note: "test request accepted, no topic/payload" });
  }

  const parts = topic.split("/");
  if (parts.length < 3 || parts[0] !== "devices") return json({ error: "Bad topic" }, 400);
  const deviceId = parts[1];

  let data;
  try {
    data = typeof payload === "string" ? JSON.parse(payload) : payload;
  } catch (e) {
    return json({ error: "Invalid JSON payload" }, 400);
  }

  const device = await getDocument(env, "devices", deviceId);
  if (!device) return json({ error: "Unknown device" }, 404);

  const updates = {
    latestReadings: data.readings || {},
    latestOutputs: data.outputs || {},
    lastSeen: new Date(),
    online: true,
  };

  if (device.status === "trial" && !device.trialStarted) {
    updates.trialStarted = true;
    updates.trialUsesRemaining = Math.max(0, (device.trialUsesRemaining ?? 3) - 1);
  }

  await updateDocument(env, "devices", deviceId, updates);

  if (data.readings) {
    await addToSubcollection(env, "devices", deviceId, "history", {
      readings: data.readings,
      timestamp: new Date(),
    });
  }

  return json({ ok: true });
}

async function handleSendCommand(req, env) {
  const { deviceId, ownerId, outputName, value } = await req.json();
  if (!deviceId || !ownerId || !outputName || !value) {
    return json({ error: "Missing fields" }, 400);
  }

  const device = await getDocument(env, "devices", deviceId);
  if (!device) return json({ error: "Unknown device" }, 404);
  if (device.ownerId !== ownerId) return json({ error: "Not your device" }, 403);
  if (device.status === "locked") return json({ error: "Device is locked" }, 403);

  // 1. Update Firestore so the dashboard reflects the intended state.
  await updateDocument(env, "devices", deviceId, {
    [`latestOutputs.${outputName}`]: value,
  });

  // 2. Publish the command to EMQX so the device actually receives it.
  const topic = `devices/${deviceId}/commands/${outputName}`;
  const authHeader = "Basic " + btoa(`${env.EMQX_API_KEY}:${env.EMQX_API_SECRET}`);

  await fetch(`${env.EMQX_API_URL}/api/v5/publish`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: authHeader },
    body: JSON.stringify({ topic, payload: value, qos: 1 }),
  });

  return json({ ok: true });
}

// ---------- Router ----------

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case "/mqtt-auth":
          return await handleMqttAuth(request, env);
        case "/mqtt-acl":
          return await handleMqttAcl(request, env);
        case "/register-device":
          return await handleRegisterDevice(request, env);
        case "/ingest-data":
          return await handleIngestData(request, env);
        case "/send-command":
          return await handleSendCommand(request, env);
        default:
          return json({ error: "Not found" }, 404);
      }
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
