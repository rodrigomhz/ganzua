'use strict';

// Candidatas por IA (--ia / --pistas / comando ia). Todo contra una API
// simulada en local (compatible con OpenAI chat/completions): ni clave real ni
// red. Se comprueba qué se envía (privacidad), el parseo y la integración con
// romper / ataca-sonda / checkpoint.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const ia = require('../lib/ia');
const checkpoint = require('../lib/checkpoint');
const { makeAesZip, runCli, runCliAsync } = require('./helpers');

// API simulada: responde `content` como choices[0].message.content y guarda
// cada petición (cabeceras + cuerpo) para inspeccionarla.
async function mockApi({ content = '', status = 200, body } = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      requests.push({ url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : null });
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(
        body !== undefined
          ? body
          : JSON.stringify({ model: 'deepseek-v4.1-flash', choices: [{ message: { role: 'assistant', content } }] }),
      );
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/v1`;
  return { url, requests, close: () => new Promise((r) => server.close(r)) };
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ganzua-ia-'));

test('config: por defecto OpenCode + deepseek-v4.1-flash; el entorno lo cambia', () => {
  const d = ia.config({});
  assert.strictEqual(d.url, 'https://opencode.ai/inference/openai/v1');
  assert.strictEqual(d.model, 'deepseek-v4.1-flash');
  assert.strictEqual(d.key, '');

  const e = ia.config({
    OPENCODE_API_KEY: 'k1',
    GANZUA_IA_KEY: 'k2',
    GANZUA_IA_URL: 'https://api.deepseek.com/v1/',
    GANZUA_IA_MODELO: 'deepseek-chat',
  });
  assert.strictEqual(e.key, 'k1', 'OPENCODE_API_KEY tiene prioridad');
  assert.strictEqual(e.url, 'https://api.deepseek.com/v1', 'sin barra final');
  assert.strictEqual(e.model, 'deepseek-chat');
  assert.strictEqual(ia.config({}, { model: 'otro' }).model, 'otro', 'override de la CLI');
});

test('checkUrl: https sí; http solo a localhost (la clave no viaja en claro)', () => {
  assert.ok(ia.checkUrl('https://opencode.ai/inference/openai/v1'));
  assert.ok(ia.checkUrl('http://127.0.0.1:8080/v1'));
  assert.ok(ia.checkUrl('http://localhost/v1'));
  assert.throws(() => ia.checkUrl('http://ejemplo.com/v1'), /https/);
  assert.throws(() => ia.checkUrl('no es una url'), /inválida/);
});

test('buildMessages: incluye las pistas; los nombres solo si se dan', () => {
  const m = ia.buildMessages({ pistas: 'perra Luna, 1998', cantidad: 50 });
  assert.strictEqual(m[0].role, 'system');
  assert.match(m[0].content, /PROPIETARIO/);
  assert.match(m[1].content, /perra Luna, 1998/);
  assert.match(m[1].content, /50 contraseñas/);
  assert.doesNotMatch(m[1].content, /Nombres de los ficheros/);

  const n = ia.buildMessages({ pistas: 'x', nombres: ['fotos.zip', 'boda/'] });
  assert.match(n[1].content, /fotos\.zip, boda\//);
});

test('parseCandidates: viñetas, numeración, comillas, código, <think> y prosa', () => {
  const text = [
    '<think>razonando sobre las pistas…</think>',
    'Aquí tienes las contraseñas:',
    '```',
    '1. Luna1998',
    '2) luna_1998',
    '- "Luna1998!"',
    '* `L0n4`',
    '• luna1998',
    'Luna1998',
    '',
    'x'.repeat(200),
    '```',
  ].join('\n');
  assert.deepStrictEqual(ia.parseCandidates(text), ['Luna1998', 'luna_1998', 'Luna1998!', 'L0n4', 'luna1998']);
  assert.deepStrictEqual(ia.parseCandidates('["a1", "b2", 3, "a1"]'), ['a1', 'b2'], 'array JSON');
  assert.deepStrictEqual(ia.parseCandidates('a\nb\nc\nd', 2), ['a', 'b'], 'respeta el máximo');
});

test('generateCandidates: sin pistas ni nombres, o sin clave, falla antes de la red', async () => {
  const request = () => assert.fail('no debe llamar a la red');
  await assert.rejects(ia.generateCandidates({ key: 'k' }, { request }), /pistas/);
  await assert.rejects(ia.generateCandidates({ pistas: 'x' }, { request, env: {} }), /OPENCODE_API_KEY/);
});

test('generateCandidates: petición OpenAI-compatible y respuesta parseada', async () => {
  const api = await mockApi({ content: 'Toby1998\ntoby_1998\nToby1998' });
  try {
    const r = await ia.generateCandidates({
      pistas: 'perro Toby, 1998',
      cantidad: 20,
      key: 'clave-test',
      url: api.url,
    });
    assert.deepStrictEqual(r.candidatas, ['Toby1998', 'toby_1998']);
    assert.strictEqual(r.modelo, 'deepseek-v4.1-flash');

    const [req] = api.requests;
    assert.strictEqual(req.url, '/v1/chat/completions');
    assert.strictEqual(req.headers.authorization, 'Bearer clave-test');
    assert.strictEqual(req.body.model, 'deepseek-v4.1-flash');
    assert.match(req.body.messages[1].content, /perro Toby, 1998/);
    assert.match(req.body.messages[1].content, /20 contraseñas/);
  } finally {
    await api.close();
  }
});

test('generateCandidates: errores HTTP con mensaje claro (y sin filtrar la clave)', async () => {
  const cases = [
    [401, /rechazó la clave \(HTTP 401\): Invalid credential/],
    [429, /HTTP 429/],
    [500, /HTTP 500/],
  ];
  for (const [status, re] of cases) {
    const api = await mockApi({ status, body: JSON.stringify({ error: { message: 'Invalid credential' } }) });
    try {
      await assert.rejects(
        ia.generateCandidates({ pistas: 'x', key: 'secreto-no-mostrar', url: api.url }),
        (err) => err instanceof ia.IaError && re.test(err.message) && !err.message.includes('secreto-no-mostrar'),
      );
    } finally {
      await api.close();
    }
  }
});

test('generateCandidates: respuesta sin texto o sin candidatas útiles', async () => {
  const sinTexto = await mockApi({ body: JSON.stringify({ choices: [] }) });
  try {
    await assert.rejects(ia.generateCandidates({ pistas: 'x', key: 'k', url: sinTexto.url }), /no trae texto/);
  } finally {
    await sinTexto.close();
  }
  const vacia = await mockApi({ content: 'Lo siento, no puedo:' });
  try {
    await assert.rejects(ia.generateCandidates({ pistas: 'x', key: 'k', url: vacia.url }), /no devolvió candidatas/);
  } finally {
    await vacia.close();
  }
});

test('generateCandidates: tiempo de espera agotado', async () => {
  const server = http.createServer(() => {
    /* nunca responde */
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/v1`;
  try {
    await assert.rejects(ia.generateCandidates({ pistas: 'x', key: 'k', url, timeoutMs: 200 }), /sin respuesta/);
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});

test('checkpoint: la firma incluye la lista IA solo si la hay', () => {
  const base = checkpoint.signature('a.zip', 0, {});
  assert.strictEqual(checkpoint.signature('a.zip', 0, { iaWords: undefined }), base, 'sin IA no cambia');
  const conIa = checkpoint.signature('a.zip', 0, { iaWords: ['x', 'y'] });
  assert.notStrictEqual(conIa, base);
  assert.notStrictEqual(checkpoint.signature('a.zip', 0, { iaWords: ['x', 'z'] }), conIa);
});

// --- CLI -------------------------------------------------------------------

test('CLI ia: imprime las candidatas y avisa de qué se envía', async () => {
  const api = await mockApi({ content: '1. Luna1998\n2. luna_98' });
  try {
    const res = await runCliAsync(['ia', '--pistas', 'perra Luna, 1998', '--cantidad', '10'], {
      env: { OPENCODE_API_KEY: 'k', GANZUA_IA_URL: api.url },
    });
    assert.strictEqual(res.status, 0, res.stderr);
    assert.deepStrictEqual(res.stdout.trim().split('\n'), ['Luna1998', 'luna_98']);
    assert.match(res.stderr, /deepseek-v4\.1-flash \(127\.0\.0\.1:\d+\) — se envía: tus pistas/);
  } finally {
    await api.close();
  }
});

test('CLI ia --ia-nombres: envía los nombres del zip y --salida guarda la lista', async () => {
  const dir = tmp();
  const zip = makeAesZip({ dir, file: 'vacaciones.zip', entry: 'playa.txt', password: 'nada' });
  const api = await mockApi({ content: 'Playa2024\nvacaciones!' });
  const lista = path.join(dir, 'lista.txt');
  try {
    const res = await runCliAsync(['ia', zip, '--ia-nombres', '--salida', lista, '--json'], {
      env: { OPENCODE_API_KEY: 'k', GANZUA_IA_URL: api.url },
    });
    assert.strictEqual(res.status, 0, res.stderr);
    const j = JSON.parse(res.stdout);
    assert.deepStrictEqual(j.candidatas, ['Playa2024', 'vacaciones!']);
    assert.strictEqual(fs.readFileSync(lista, 'utf8'), 'Playa2024\nvacaciones!\n');
    assert.match(api.requests[0].body.messages[1].content, /vacaciones\.zip, playa\.txt/);
  } finally {
    await api.close();
  }
});

test('CLI romper --pistas: la contraseña sale de la IA (y los nombres NO se envían por defecto)', async () => {
  const dir = tmp();
  const password = 'Toby_Betis1998!'; // fuera de la wordlist común y sus mutaciones
  const zip = makeAesZip({ dir, file: 'privado.zip', entry: 'nota.txt', password });
  const api = await mockApi({ content: `toby1998\nTobyBetis\n${password}\nbetis1998` });
  try {
    const res = await runCliAsync(['romper', zip, '--pistas', 'perro Toby, Betis, 1998', '--json'], {
      env: { OPENCODE_API_KEY: 'k', GANZUA_IA_URL: api.url },
    });
    assert.strictEqual(res.status, 0, res.stderr);
    const j = JSON.parse(res.stdout);
    assert.strictEqual(j.encontrada, true);
    assert.strictEqual(j.contrasena, password);
    assert.ok(j.candidatas <= 4, `las candidatas IA van primero (probadas: ${j.candidatas})`);
    const enviado = api.requests[0].body.messages[1].content;
    assert.doesNotMatch(enviado, /privado\.zip|nota\.txt/, 'sin --ia-nombres no se envían nombres');
  } finally {
    await api.close();
  }
});

test('CLI ataca-sonda --romper --pistas: contraseña desde sonda con candidatas IA', async () => {
  const dir = tmp();
  const password = 'Luna-Sevilla-77';
  const zip = makeAesZip({ dir, file: 'grande.zip', entry: 'disco.vdi', password });
  const sonda = path.join(dir, 'sonda.json');
  const s = runCli(['sonda', zip, '--salida', sonda]);
  assert.strictEqual(s.status, 0, s.stderr);
  const api = await mockApi({ content: `luna77\n${password}` });
  try {
    const res = await runCliAsync(['ataca-sonda', sonda, '--romper', '--pistas', 'Luna, Sevilla, 77', '--json'], {
      env: { OPENCODE_API_KEY: 'k', GANZUA_IA_URL: api.url },
    });
    assert.strictEqual(res.status, 0, res.stderr);
    assert.strictEqual(JSON.parse(res.stdout).contrasena, password);
  } finally {
    await api.close();
  }
});

test('CLI --pistas sin clave: error claro antes de enviar nada', () => {
  const dir = tmp();
  const zip = makeAesZip({ dir, password: 'nada' });
  const res = runCli(['romper', zip, '--pistas', 'x'], {
    env: { OPENCODE_API_KEY: undefined, GANZUA_IA_KEY: undefined },
  });
  assert.strictEqual(res.status, 2);
  assert.match(res.stderr, /OPENCODE_API_KEY/);
  assert.doesNotMatch(res.stderr, /se envía/, 'no anuncia un envío que no ocurre');
});

test('CLI --checkpoint: al reanudar reutiliza la lista IA guardada (sin volver a llamar a la API)', () => {
  const dir = tmp();
  const password = 'Reanuda#2031';
  const zip = makeAesZip({ dir, password });
  const cp = path.join(dir, 'cp.json');
  // Checkpoint de una ejecución anterior con --pistas (posición 0).
  checkpoint.save(cp, { firma: 'x', archivo: zip, entrada: 0, position: 0, total: null, ia: ['otra', password] });
  // Sin clave ni API: si intentara llamar a la IA, fallaría.
  const res = runCli(['romper', zip, '--pistas', 'x', '--checkpoint', cp, '--json'], {
    env: { OPENCODE_API_KEY: undefined, GANZUA_IA_KEY: undefined },
  });
  assert.strictEqual(res.status, 0, res.stderr);
  assert.strictEqual(JSON.parse(res.stdout).contrasena, password);
});
