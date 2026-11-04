'use strict';
/**
 * oauth-server 单元/集成测试（本地起服务 + mock 开放平台）
 * 运行：node --test test/
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');

const APP_KEY = 'qz_test_key_0001';
const APP_SECRET = 'test_secret_abcdef';
const REDIRECT = 'https://ideanote.7373.com.cn/oauth/callback';
const PIN = 'pin_test_123456';

// 必须在 require index.js 之前设置环境变量（CFG 在模块加载时读取）
process.env.QZ_APP_KEY = APP_KEY;
process.env.QZ_APP_SECRET = APP_SECRET;
process.env.QZ_REDIRECT_URI = REDIRECT;
process.env.CLIENT_PIN = PIN;
process.env.QUIET = '1';

// ---------- mock 开放平台 ----------
const calls = { access_token: [], user_info: [] };
let mockBehavior = { tokenStatus: 200, tokenCode: 200, infoOk: true };

function rfc3986(v) {
  return encodeURIComponent(String(v)).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}
function fieldVal(v) {
  if (Array.isArray(v)) return JSON.stringify(v.map(String));
  if (v && typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
function expectSign(method, path, business, headers, accessToken) {
  const fields = { ...business };
  delete fields.app_secret;
  fields.app_key = headers['x-qz-app-key'];
  fields.timestamp = headers['x-qz-timestamp'];
  fields.nonce = headers['x-qz-nonce'];
  if (accessToken) fields.access_token = accessToken;
  const canonical = Object.keys(fields)
    .filter((k) => fields[k] !== undefined && fields[k] !== null)
    .sort()
    .map((k) => `${rfc3986(k)}=${rfc3986(fieldVal(fields[k]))}`)
    .join('&');
  return crypto
    .createHmac('sha256', APP_SECRET)
    .update(`${method}\n${path}\n${canonical}`)
    .digest('hex');
}

const mockPlatform = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const rawBody = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
    const path = req.url.split('?')[0];
    const queryStr = req.url.includes('?') ? req.url.split('?')[1] : '';
    const query = Object.fromEntries(new URLSearchParams(queryStr));
    const body = req.method === 'GET' ? query : rawBody;
    const signed = expectSign(req.method, path, body, req.headers, (req.headers.authorization || '').replace('Bearer ', '') || undefined);
    const signOk = signed === req.headers['x-qz-sign'];

    const reply = (obj) => {
      const s = JSON.stringify(obj);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(s);
    };

    if (path === '/oauth/access_token') {
      calls.access_token.push({ body, signOk, headers: req.headers });
      if (mockBehavior.tokenStatus !== 200 || mockBehavior.tokenCode !== 200) {
        res.writeHead(mockBehavior.tokenStatus, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ code: mockBehavior.tokenCode, msg: 'mock error' }));
      }
      const isRefresh = body.grant_type === 'refresh_token';
      return reply({
        code: 200,
        msg: 'ok',
        data: {
          access_token: isRefresh ? 'ou_refreshed' : 'ou_access',
          refresh_token: isRefresh ? 'or_rotated' : 'or_first',
          token_type: 'Bearer',
          credential_type: 'user',
          expires_in: 7200,
          refresh_expires_in: 7776000,
          user: { q_uid: 'q_123' }
        }
      });
    }
    if (path === '/open/idea_note/list') {
      calls.list = calls.list || [];
      calls.list.push({ signOk, headers: req.headers, query: req.url.split('?')[1] });
      return reply({ code: 200, msg: '获取成功', data: { list: [], per_page: 10, current_page: 1, has_more: false } });
    }
    if (path === '/open/idea_note/create') {
      calls.create = calls.create || [];
      calls.create.push({ body, signOk });
      return reply({ code: 200, msg: '创建成功', data: { id: 1, content_json: body.content_json, plain_text: 'x', tags: [], images: [], create_time: 1, update_time: 1 } });
    }
    if (path === '/open/user/info') {
      calls.user_info.push({ body, signOk });
      if (!mockBehavior.infoOk) return reply({ code: 40004, msg: 'no user' });
      return reply({ code: 200, msg: '获取成功', data: { q_uid: 'q_123', nickname: '老板', avatar: 'https://a/b.png' } });
    }
    res.writeHead(404).end('{}');
  });
});

let base; // oauth 服务地址
let platformBase;
let server;

function get(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString(), headers: res.headers }));
    }).on('error', reject);
  });
}

function post(url, obj, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(obj);
    const req = http.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), ...headers }
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test.before(async () => {
  await new Promise((r) => mockPlatform.listen(0, '127.0.0.1', r));
  platformBase = 'http://127.0.0.1:' + mockPlatform.address().port;
  process.env.QZ_API_BASE = platformBase;
  // 重新加载模块以拿到 mock 的 apiBase
  delete require.cache[require.resolve('../index.js')];
  const { createServer } = require('../index.js');
  server = createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
});

test.after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => mockPlatform.close(r));
});

test('GET /health 返回 ok 与配置状态', async () => {
  const r = await get(base + '/health');
  const j = JSON.parse(r.body);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.ok, true);
  assert.strictEqual(j.configured, true);
});

test('GET /oauth/start 返回 state 与正确授权地址', async () => {
  const r = await get(base + '/oauth/start');
  const j = JSON.parse(r.body);
  assert.strictEqual(j.code, 0);
  assert.match(j.data.state, /^[A-Za-z0-9_-]{16,256}$/);
  const u = new URL(j.data.authorizeUrl);
  assert.strictEqual(u.origin, platformBase, '授权地址基于 QZ_API_BASE');
  assert.strictEqual(u.pathname, '/oauth/authorize');
  assert.strictEqual(u.searchParams.get('app_key'), APP_KEY);
  assert.strictEqual(u.searchParams.get('redirect_uri'), REDIRECT);
  assert.strictEqual(u.searchParams.get('state'), j.data.state);
  assert.strictEqual(u.searchParams.get('scope'), 'user_info');
});

test('回调换 token → 轮询取到凭证，且只交付一次', async () => {
  const start = JSON.parse((await get(base + '/oauth/start')).body).data;
  const cb = await get(`${base}/oauth/callback?code=CODE1&state=${encodeURIComponent(start.state)}`);
  assert.strictEqual(cb.status, 200);
  assert.ok(cb.body.includes('授权成功'));

  // 平台请求：签名必须正确、app_secret 参与 body 但不参与签名
  assert.strictEqual(calls.access_token.length, 1);
  assert.strictEqual(calls.access_token[0].signOk, true, '换 token 请求签名应为有效');
  assert.strictEqual(calls.access_token[0].body.app_secret, APP_SECRET);
  assert.strictEqual(calls.access_token[0].body.redirect_uri, REDIRECT);
  assert.strictEqual(calls.user_info[0].signOk, true, '用户信息请求签名应为有效');

  const poll = JSON.parse((await get(`${base}/oauth/poll?state=${encodeURIComponent(start.state)}`)).body);
  assert.strictEqual(poll.code, 0);
  assert.strictEqual(poll.data.status, 'ok');
  assert.strictEqual(poll.data.access_token, 'ou_access');
  assert.strictEqual(poll.data.refresh_token, 'or_first');
  assert.strictEqual(poll.data.q_uid, 'q_123');
  assert.strictEqual(poll.data.nickname, '老板');
  assert.strictEqual(poll.data.expires_in, 7200);
  assert.strictEqual(poll.data.refresh_expires_in, 7776000);

  // 第二次轮询：已核销
  const again = JSON.parse((await get(`${base}/oauth/poll?state=${encodeURIComponent(start.state)}`)).body);
  assert.strictEqual(again.data.status, 'expired');
});

test('轮询 pending：回调前返回 pending', async () => {
  const start = JSON.parse((await get(base + '/oauth/start')).body).data;
  const poll = JSON.parse((await get(`${base}/oauth/poll?state=${encodeURIComponent(start.state)}`)).body);
  assert.strictEqual(poll.data.status, 'pending');
});

test('回调 state 不存在 → 错误页且不调平台', async () => {
  const before = calls.access_token.length;
  const r = await get(base + '/oauth/callback?code=X&state=unknown_state_123456');
  assert.ok(r.body.includes('授权未完成'));
  assert.strictEqual(calls.access_token.length, before);
});

test('用户拒绝授权 → 轮询得到 error=access_denied', async () => {
  const start = JSON.parse((await get(base + '/oauth/start')).body).data;
  await get(`${base}/oauth/callback?error=access_denied&state=${encodeURIComponent(start.state)}`);
  const poll = JSON.parse((await get(`${base}/oauth/poll?state=${encodeURIComponent(start.state)}`)).body);
  assert.strictEqual(poll.data.status, 'error');
  assert.strictEqual(poll.data.error, 'access_denied');
});

test('平台换 token 失败 → 轮询得到 error=exchange_failed，不泄露内部细节', async () => {
  mockBehavior = { tokenStatus: 400, tokenCode: 40004, infoOk: true };
  const start = JSON.parse((await get(base + '/oauth/start')).body).data;
  const cb = await get(`${base}/oauth/callback?code=BAD&state=${encodeURIComponent(start.state)}`);
  assert.ok(cb.body.includes('授权未完成'));
  assert.ok(!cb.body.includes('40004'), '页面不应暴露平台错误码');
  const poll = JSON.parse((await get(`${base}/oauth/poll?state=${encodeURIComponent(start.state)}`)).body);
  assert.strictEqual(poll.data.error, 'exchange_failed');
  mockBehavior = { tokenStatus: 200, tokenCode: 200, infoOk: true };
});

test('同一 state 重复回调 → 拒绝第二次（防重放）', async () => {
  const start = JSON.parse((await get(base + '/oauth/start')).body).data;
  await get(`${base}/oauth/callback?code=A&state=${encodeURIComponent(start.state)}`);
  const second = await get(`${base}/oauth/callback?code=B&state=${encodeURIComponent(start.state)}`);
  assert.ok(second.body.includes('已处理过'));
});

test('POST /oauth/refresh：成功返回轮换后的 token', async () => {
  const r = await post(base + '/oauth/refresh', { refresh_token: 'or_old' }, { 'x-ideanote-pin': PIN });
  const j = JSON.parse(r.body);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.code, 0);
  assert.strictEqual(j.data.access_token, 'ou_refreshed');
  assert.strictEqual(j.data.refresh_token, 'or_rotated');
  assert.strictEqual(j.data.q_uid, 'q_123');
  const last = calls.access_token[calls.access_token.length - 1];
  assert.strictEqual(last.signOk, true);
  assert.strictEqual(last.body.grant_type, 'refresh_token');
});

test('POST /oauth/refresh：缺少 PIN 返回 403', async () => {
  const r = await post(base + '/oauth/refresh', { refresh_token: 'or_old' });
  assert.strictEqual(r.status, 403);
});

test('POST /oauth/refresh：平台 40004 → 401 且 invalid=true（明确失效）', async () => {
  mockBehavior = { tokenStatus: 400, tokenCode: 40004, infoOk: true };
  const r = await post(base + '/oauth/refresh', { refresh_token: 'or_dead' }, { 'x-ideanote-pin': PIN });
  const j = JSON.parse(r.body);
  assert.strictEqual(r.status, 401);
  assert.strictEqual(j.invalid, true);
  mockBehavior = { tokenStatus: 200, tokenCode: 200, infoOk: true };
});

test('POST /oauth/refresh：平台 5xx → 502 且 invalid=false（瞬时故障不踢登录）', async () => {
  mockBehavior = { tokenStatus: 503, tokenCode: 0, infoOk: true };
  const r = await post(base + '/oauth/refresh', { refresh_token: 'or_x' }, { 'x-ideanote-pin': PIN });
  const j = JSON.parse(r.body);
  assert.strictEqual(r.status, 502);
  assert.strictEqual(j.invalid, false);
  mockBehavior = { tokenStatus: 200, tokenCode: 200, infoOk: true };
});

test('未知路径 404', async () => {
  const r = await get(base + '/nope');
  assert.strictEqual(r.status, 404);
});

test('POST /api/open：代签名代理列表请求（access_token 进签名）', async () => {
  const r = await post(base + '/api/open', {
    method: 'GET', path: '/open/idea_note/list', query: { page: 1, page_size: 10 }, access_token: 'ou_x'
  }, { 'x-ideanote-pin': PIN });
  const j = JSON.parse(r.body);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.code, 200);
  assert.strictEqual(j.data.has_more, false);
  const last = calls.list[calls.list.length - 1];
  assert.strictEqual(last.signOk, true);
  assert.strictEqual(last.headers.authorization, 'Bearer ou_x');
  assert.match(last.query, /page=1/);
});

test('POST /api/open： 创建 走 POST body 签名', async () => {
  const content_json = { type: 'doc', content: [{ type: 'paragraph', content: [{ type: 'text', text: '测试 #a' }] }] };
  const r = await post(base + '/api/open', {
    method: 'POST', path: '/open/idea_note/create',
    body: { content_json, images: ['img_1'] },
    access_token: 'ou_x'
  }, { 'x-ideanote-pin': PIN });
  const j = JSON.parse(r.body);
  assert.strictEqual(j.code, 200);
  const last = calls.create[calls.create.length - 1];
  assert.strictEqual(last.signOk, true, '嵌套 content_json 的签名需与平台一致');
  assert.deepStrictEqual(last.body.images, ['img_1']);
});

test('POST /api/open：非白名单路径 403', async () => {
  const r = await post(base + '/api/open', { method: 'GET', path: '/open/message/push' }, { 'x-ideanote-pin': PIN });
  assert.strictEqual(r.status, 403);
});

test('POST /api/open：缺少 PIN 403', async () => {
  const r = await post(base + '/api/open', { method: 'GET', path: '/open/idea_note/list' });
  assert.strictEqual(r.status, 403);
});

test('POST /api/open：缺少 access_token 502', async () => {
  const r = await post(base + '/api/open', { method: 'GET', path: '/open/idea_note/list' }, { 'x-ideanote-pin': PIN });
  assert.strictEqual(r.status, 502);
});

test('GET /oauth/health 前缀兼容（nginx 保留 /oauth）', async () => {
  const r = await get(base + '/oauth/health');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(JSON.parse(r.body).ok, true);
});
