'use strict';

// Candidatas asistidas por IA (opcional, solo con --ia). Pide a un modelo de
// lenguaje contraseñas plausibles a partir de las PISTAS que da el propietario
// del archivo ("mi perro Toby, nací en 1998, del Betis…"): combinaciones,
// mayúsculas, leet, años, sufijos. Esas candidatas se prueban las primeras y,
// además, pasan por las mutaciones de `romper`.
//
// Por defecto usa DeepSeek V4.1 Flash a través de la API de OpenCode
// (https://opencode.ai/inference/openai/v1, compatible con OpenAI
// chat/completions). Cualquier otro endpoint compatible sirve cambiando
// GANZUA_IA_URL / GANZUA_IA_MODELO.
//
// Privacidad: solo se envían las pistas y, si se pide (--ia-nombres), los
// NOMBRES de fichero. Nunca contenido, cifrado, salt, verificador ni claves.

const http = require('http');
const https = require('https');

const DEFAULT_URL = 'https://opencode.ai/inference/openai/v1';
const DEFAULT_MODEL = 'deepseek-v4.1-flash';
const DEFAULT_COUNT = 150;
const MAX_COUNT = 1000;
const MAX_LEN = 128; // candidatas más largas se descartan (prosa, no claves)
const MAX_NAMES = 50; // nombres de fichero enviados como contexto
const DEFAULT_TIMEOUT_MS = 60_000;

class IaError extends Error {}

const MISSING_KEY =
  'falta la clave de la API: define OPENCODE_API_KEY (créala en https://opencode.ai, en la consola de ' +
  'OpenCode → API Keys), o GANZUA_IA_KEY para otro proveedor compatible con OpenAI';

// Configuración desde el entorno (+ overrides de la CLI). La clave nunca se
// imprime: solo se usa en la cabecera Authorization.
function config(env = process.env, overrides = {}) {
  const timeout = Number(env.GANZUA_IA_TIMEOUT_MS);
  return {
    key: env.OPENCODE_API_KEY || env.GANZUA_IA_KEY || '',
    url: String(overrides.url || env.GANZUA_IA_URL || DEFAULT_URL).replace(/\/+$/, ''),
    model: overrides.model || env.GANZUA_IA_MODELO || DEFAULT_MODEL,
    timeoutMs: Number.isFinite(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT_MS,
  };
}

// http:// solo hacia la propia máquina (pruebas, modelos locales): la clave no
// debe viajar en claro por la red.
function checkUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    throw new IaError(`URL de la API inválida: ${url}`);
  }
  if (u.protocol === 'https:') return u;
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol === 'http:' && loopback) return u;
  throw new IaError(`la URL de la API debe ser https:// (o http:// a localhost): ${url}`);
}

function buildMessages({ pistas, nombres = [], cantidad = DEFAULT_COUNT }) {
  const system =
    'Ayudas al PROPIETARIO de un archivo ZIP a recordar su propia contraseña olvidada. ' +
    'A partir de sus pistas, genera contraseñas candidatas tal como las crearía una persona: ' +
    'combinaciones de las palabras, nombres y fechas de las pistas; variantes de mayúsculas; ' +
    'sustituciones leet (a→4, e→3, i→1, o→0, s→5); separadores (_ - .); años y sufijos ' +
    'habituales (1, 123, !, 2024). Responde SOLO con las contraseñas, una por línea, ' +
    'sin numerar, sin comillas y sin explicaciones.';
  const lines = [];
  if (pistas) lines.push(`Pistas del propietario: ${pistas}`);
  const names = nombres.filter(Boolean).slice(0, MAX_NAMES);
  if (names.length) lines.push(`Nombres de los ficheros (pueden inspirar la contraseña): ${names.join(', ')}`);
  lines.push(`Genera ${cantidad} contraseñas candidatas distintas, de la más a la menos probable.`);
  return [
    { role: 'system', content: system },
    { role: 'user', content: lines.join('\n') },
  ];
}

// Extrae candidatas del texto del modelo: una por línea, tolerando viñetas,
// numeración, comillas, bloques de código, <think>…</think> o un array JSON.
function parseCandidates(text, max = MAX_COUNT) {
  const body = String(text || '').replace(/<think>[\s\S]*?<\/think>/g, '');
  let raw;
  const trimmed = body.trim();
  if (trimmed.startsWith('[')) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) raw = arr.filter((x) => typeof x === 'string');
    } catch {
      /* no era JSON: se trata como líneas */
    }
  }
  if (!raw) {
    raw = body
      .split('\n')
      .filter((l) => !l.trim().startsWith('```'))
      .map((l) => l.replace(/\r$/, '').replace(/^\s*(?:[-*•]\s+|\d{1,4}[.)]\s+)/, ''));
  }
  const seen = new Set();
  const out = [];
  for (let c of raw) {
    c = c.trim();
    const q = c.match(/^(["'`])(.*)\1$/);
    if (q) c = q[2];
    if (!c || c.length > MAX_LEN || c.endsWith(':')) continue;
    if (seen.has(c)) continue;
    seen.add(c);
    out.push(c);
    if (out.length >= max) break;
  }
  return out;
}

// POST JSON con http/https nativos (sin fetch: en Node 18 es experimental y
// avisa por stderr). Resuelve { status, text }.
function postJson(url, body, { headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const data = Buffer.from(JSON.stringify(body));
    const req = lib.request(
      u,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': data.length, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', reject);
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new IaError(`sin respuesta de la API en ${timeoutMs / 1000} s`)));
    req.on('error', reject);
    req.end(data);
  });
}

function apiMessage(text) {
  try {
    const j = JSON.parse(text);
    const m = j?.error?.message || j?.message || (typeof j?.error === 'string' ? j.error : null);
    if (m) return String(m);
  } catch {
    /* cuerpo no JSON */
  }
  return String(text || '')
    .trim()
    .slice(0, 200);
}

// Pide `cantidad` candidatas al modelo. Devuelve { candidatas, modelo, uso }.
// `key`/`url`/`model`/`timeoutMs` sustituyen a los del entorno si se dan.
async function generateCandidates(
  { pistas, nombres = [], cantidad = DEFAULT_COUNT, key, url, model, timeoutMs } = {},
  deps = {},
) {
  if (!pistas && !nombres.length) throw new IaError('la IA necesita pistas (--pistas "…") o --ia-nombres');
  const cfg = config(deps.env || process.env, { url, model });
  if (key) cfg.key = key;
  if (timeoutMs) cfg.timeoutMs = timeoutMs;
  if (!cfg.key) throw new IaError(MISSING_KEY);
  const n = Math.min(Math.max(Number(cantidad) || DEFAULT_COUNT, 1), MAX_COUNT);
  const base = checkUrl(cfg.url);
  const endpoint = `${base.href.replace(/\/+$/, '')}/chat/completions`;

  const request = deps.request || postJson;
  let res;
  try {
    res = await request(
      endpoint,
      {
        model: cfg.model,
        messages: buildMessages({ pistas, nombres, cantidad: n }),
        temperature: 0.7,
        max_tokens: Math.min(16 * n + 256, 16384),
      },
      { headers: { Authorization: `Bearer ${cfg.key}` }, timeoutMs: cfg.timeoutMs },
    );
  } catch (err) {
    if (err instanceof IaError) throw err;
    throw new IaError(`no se pudo contactar con la API (${base.host}): ${err.message}`);
  }

  if (res.status === 401 || res.status === 403) {
    throw new IaError(`la API rechazó la clave (HTTP ${res.status}): ${apiMessage(res.text)}`);
  }
  if (res.status === 429) {
    throw new IaError(`límite de uso o sin créditos (HTTP 429): ${apiMessage(res.text)}`);
  }
  if (res.status < 200 || res.status >= 300) {
    throw new IaError(`la API respondió HTTP ${res.status}: ${apiMessage(res.text)}`);
  }
  let json;
  try {
    json = JSON.parse(res.text);
  } catch {
    throw new IaError('la respuesta de la API no es JSON');
  }
  const content = json?.choices?.[0]?.message?.content;
  if (typeof content !== 'string') {
    throw new IaError('la respuesta de la API no trae texto (choices[0].message.content)');
  }
  const candidatas = parseCandidates(content, n);
  if (candidatas.length === 0) throw new IaError('el modelo no devolvió candidatas utilizables');
  return { candidatas, modelo: json.model || cfg.model, uso: json.usage || null, host: base.host };
}

module.exports = {
  DEFAULT_URL,
  DEFAULT_MODEL,
  DEFAULT_COUNT,
  MAX_COUNT,
  MISSING_KEY,
  IaError,
  config,
  checkUrl,
  buildMessages,
  parseCandidates,
  postJson,
  generateCandidates,
};
