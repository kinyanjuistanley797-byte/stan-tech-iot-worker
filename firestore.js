/**
 * firestore.js
 * -------------
 * Small helper library for reading/writing Firestore over its REST API,
 * plus converting between Firestore's verbose JSON format and plain
 * JavaScript objects/values.
 */

import { getAccessToken } from "./firestoreAuth.js";

const PROJECT_ID = "iot-remote-control-online";
const BASE_URL = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;

// ---------- Convert plain JS values <-> Firestore's typed field format ----------

function toFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: null };
  if (typeof value === "string") return { stringValue: value };
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") {
    return Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  }
  if (value instanceof Date) return { timestampValue: value.toISOString() };
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map(toFirestoreValue) } };
  }
  if (typeof value === "object") {
    const fields = {};
    for (const key of Object.keys(value)) fields[key] = toFirestoreValue(value[key]);
    return { mapValue: { fields } };
  }
  return { stringValue: String(value) };
}

function fromFirestoreValue(fieldValue) {
  if (!fieldValue) return null;
  if ("stringValue" in fieldValue) return fieldValue.stringValue;
  if ("booleanValue" in fieldValue) return fieldValue.booleanValue;
  if ("integerValue" in fieldValue) return parseInt(fieldValue.integerValue, 10);
  if ("doubleValue" in fieldValue) return fieldValue.doubleValue;
  if ("timestampValue" in fieldValue) return fieldValue.timestampValue;
  if ("nullValue" in fieldValue) return null;
  if ("arrayValue" in fieldValue) {
    return (fieldValue.arrayValue.values || []).map(fromFirestoreValue);
  }
  if ("mapValue" in fieldValue) {
    return fieldsToObject(fieldValue.mapValue.fields || {});
  }
  return null;
}

function fieldsToObject(fields) {
  const obj = {};
  for (const key of Object.keys(fields)) obj[key] = fromFirestoreValue(fields[key]);
  return obj;
}

function objectToFields(obj) {
  const fields = {};
  for (const key of Object.keys(obj)) fields[key] = toFirestoreValue(obj[key]);
  return fields;
}

// ---------- Document operations ----------

export async function getDocument(env, collection, docId) {
  const token = await getAccessToken(env);
  const res = await fetch(`${BASE_URL}/${collection}/${docId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  const data = await res.json();
  if (!data.fields) return null;
  return fieldsToObject(data.fields);
}

export async function updateDocument(env, collection, docId, updates) {
  const token = await getAccessToken(env);
  const fieldPaths = Object.keys(updates).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join("&");
  const res = await fetch(`${BASE_URL}/${collection}/${docId}?${fieldPaths}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields: objectToFields(updates) }),
  });
  return res.ok;
}

export async function createDocument(env, collection, data, docId = null) {
  const token = await getAccessToken(env);
  const url = docId
    ? `${BASE_URL}/${collection}?documentId=${docId}`
    : `${BASE_URL}/${collection}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields: objectToFields(data) }),
  });
  const result = await res.json();
  // Firestore returns the document name as ".../collection/AUTO_ID"
  const generatedId = result.name ? result.name.split("/").pop() : docId;
  return generatedId;
}

export async function addToSubcollection(env, collection, docId, subcollection, data) {
  const token = await getAccessToken(env);
  const res = await fetch(`${BASE_URL}/${collection}/${docId}/${subcollection}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ fields: objectToFields(data) }),
  });
  return res.ok;
}
