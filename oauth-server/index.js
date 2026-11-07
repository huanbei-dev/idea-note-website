'use strict';
/**
 * 灵感笔记 · Q助理开放平台登录中转服务
 *
 * 为什么需要它：开放平台的 AppSecret 只能放服务端（不得进客户端），
 * 而桌面端必须自己拿到 token 才能调 /open/idea_note/*。
 * 所以由本服务代为签名换 token，再通过一次性 state 把 token 交给客户端。
 *
 * 接口（nginx 反代到 127.0.0.1:3100）：
 *   GET  /oauth/start                       生成 state，返回授权地址
 *   GET  /oauth/callback?code&state         平台回调：换 token + 取用户信息，存一次性结果
 *   GET  /oauth/poll?state                  客户端轮询取结果（一次性核销）
 *   POST /oauth/refresh {refresh_token}     代理刷新（AppSecret 只在服务端）
 *   POST /api/notes/publish                 生成 @ 分享页（PIN 鉴权），返回公开 URL
 *   GET  /notes/<id>                        公开展示页（无鉴权，仅展示文本内容）
 *   GET  /health                            探针
 *
 * 设计要点：
 *  - 无状态：登录流程只在内存里存 pending/result（TTL 到点清理），重启只影响进行中的登录。
 *  - refresh_token 交给客户端保管（它是用户凭证）；服务端不落库，避免多一套存储故障面。
 *  - @ 分享页持久化到磁盘 JSON（data/notes/<id>.json），重启不丢；页面只渲染转义后的文本。
 *  - 签名规则见 qz-sign.js，与客户端 qz/open-sign.js 同源。
 */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ---------- 配置 ----------
const CFG = {
  appKey: process.env.QZ_APP_KEY || '',
  appSecret: process.env.QZ_APP_SECRET || '',
  apiBase: (process.env.QZ_API_BASE || 'https://open.qzhuli.com').replace(/\/+$/, ''),
  redirectUri: process.env.QZ_REDIRECT_URI || 'https://ideanote.7373.com.cn/oauth/callback',
  port: Number(process.env.PORT || 3100),
  // 客户端共享密钥：防止第三方白嫖 refresh 代理（空则不校验，仅调试用）
  clientPin: process.env.CLIENT_PIN || '',
  // @ 分享页存储目录（磁盘 JSON，重启不丢）
  notesDir: process.env.NOTES_DIR || path.join(__dirname, 'data', 'notes'),
  // 分享页公开基址（页面 URL 拼域名）
  siteBase: (process.env.SITE_BASE || 'https://ideanote.7373.com.cn').replace(/\/+$/, ''),
  // 授权页停留窗口 / 结果保留窗口
  pendingTtlMs: Number(process.env.PENDING_TTL_MS || 10 * 60 * 1000),
  resultTtlMs: Number(process.env.RESULT_TTL_MS || 5 * 60 * 1000),
  log: process.env.QUIET === '1' ? () => {} : (...a) => console.log(...a)
};

// ---------- 签名（与客户端 qz/open-sign.js 规则一致）----------
function rfc3986(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, (c) =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function fieldValue(value) {
  if (Array.isArray(value)) return JSON.stringify(value.map((v) => String(v)));
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value && typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function createSign(method, apiPath, fields) {
  const canonical = Object.keys(fields)
    .filter((k) => fields[k] !== undefined && fields[k] !== null)
    .sort()
    .map((k) => `${rfc3986(k)}=${rfc3986(fieldValue(fields[k]))}`)
    .join('&');
  const text = `${String(method).toUpperCase()}\n${apiPath}\n${canonical}`;
  return crypto.createHmac('sha256', Buffer.from(CFG.appSecret, 'utf8')).update(text, 'utf8').digest('hex');
}

/** 带签名的开放平台请求；resolve {status, json}，网络异常 reject */
async function qzRequest(method, apiPath, body, accessToken) {
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(24).toString('base64url');

  const fields = { ...body };
  delete fields.app_secret; // app_secret 仅作凭证校验，不参与签名
  fields.app_key = CFG.appKey;
  fields.timestamp = timestamp;
  fields.nonce = nonce;
  if (accessToken) fields.access_token = accessToken;

  const headers = {
    'Content-Type': 'application/json',
    'X-QZ-App-Key': CFG.appKey,
    'X-QZ-Timestamp': timestamp,
    'X-QZ-Nonce': nonce,
    'X-QZ-Sign': createSign(method, apiPath, fields)
  };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const res = await fetch(`${CFG.apiBase}${apiPath}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000)
  });
  let json = null;
  try {
    json = await res.json();
  } catch (err) {
    json = null; // 非 JSON 响应（网关错误页），由调用方按失败处理
  }
  return { status: res.status, json };
}

/** 用一次性 code 换用户 token */
async function exchangeCode(code) {
  if (!code) throw new Error('缺少 code');
  const { status, json } = await qzRequest('POST', '/oauth/access_token', {
    app_secret: CFG.appSecret,
    grant_type: 'authorization_code',
    code,
    redirect_uri: CFG.redirectUri
  });
  if (status !== 200 || !json || json.code !== 200 || !json.data || !json.data.access_token) {
    const err = new Error(`换 token 失败: HTTP ${status} code=${json && json.code} msg=${(json && json.msg) || '-'}`);
    err.qzCode = json && json.code;
    err.httpStatus = status;
    throw err;
  }
  return json.data;
}

/** 用 refresh_token 续期（refresh_token 会轮换） */
async function refreshToken(refreshTokenValue) {
  if (!refreshTokenValue) throw new Error('缺少 refresh_token');
  const { status, json } = await qzRequest('POST', '/oauth/access_token', {
    app_secret: CFG.appSecret,
    grant_type: 'refresh_token',
    refresh_token: refreshTokenValue
  });
  if (status !== 200 || !json || json.code !== 200 || !json.data || !json.data.access_token) {
    const err = new Error(`刷新失败: HTTP ${status} code=${json && json.code} msg=${(json && json.msg) || '-'}`);
    err.qzCode = json && json.code;
    err.httpStatus = status;
    err.invalid = json && (json.code === 40003 || json.code === 40004); // 明确的凭证失效
    throw err;
  }
  return json.data;
}

/** 取用户信息（昵称/头像） */
async function fetchUserInfo(accessToken, qUid) {
  const { status, json } = await qzRequest('POST', '/open/user/info', { q_uid: qUid }, accessToken);
  if (status !== 200 || !json || json.code !== 200 || !json.data || !json.data.q_uid) {
    // 用户信息只用于展示，取不到不应阻断登录
    return null;
  }
  return json.data;
}

/** 业务接口白名单（仅允许这些路径经代理，防止被当通用跳板） */
const ALLOWED_PATHS = new Set([
  '/open/idea_note/list',
  '/open/idea_note/detail',
  '/open/idea_note/create',
  '/open/idea_note/update',
  '/open/idea_note/delete',
  '/open/media/upload',
  '/open/user/info'
]);

/**
 * 业务接口签名代理：用 AppSecret 代客户端签名，原样返回平台 {code,msg,data}。
 * 代理不存 token（access_token 由客户端每次带上），服务端保持无状态。
 */
async function proxyOpen(method, apiPath, query, body, accessToken) {
  if (!accessToken) throw new Error('缺少 access_token');
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(24).toString('base64url');

  const business = method === 'GET' ? (query || {}) : (body || {});
  const fields = { ...business, app_key: CFG.appKey, timestamp, nonce, access_token: accessToken };
  const headers = {
    'X-QZ-App-Key': CFG.appKey,
    'X-QZ-Timestamp': timestamp,
    'X-QZ-Nonce': nonce,
    'X-QZ-Sign': createSign(method, apiPath, fields),
    Authorization: 'Bearer ' + accessToken
  };

  let url = `${CFG.apiBase}${apiPath}`;
  if (method === 'GET' && query && Object.keys(query).length) {
    const qs = new URLSearchParams(
      Object.entries(query).filter(([, v]) => v !== undefined && v !== null)
    ).toString();
    if (qs) url += '?' + qs;
  }
  const init = { method, headers, signal: AbortSignal.timeout(20000) };
  if (method === 'POST' && body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const res = await fetch(url, init);
  let json = null;
  try {
    json = await res.json();
  } catch (err) {
    throw new Error('平台响应非 JSON (HTTP ' + res.status + ')');
  }
  // 平台业务错误也可能 HTTP 200，原样透传给客户端判断
  return json === null ? { code: -1, message: 'empty response' } : json;
}

// ---------- 一次性状态存储 ----------
/** state -> { state, createdAt, status: 'pending'|'ok'|'error', error?, message?, result? } */
const records = new Map();

function sweep(now = Date.now()) {
  for (const [k, r] of records) {
    const ttl = r.status === 'pending' ? CFG.pendingTtlMs : CFG.resultTtlMs;
    if (now - r.createdAt > ttl) records.delete(k);
  }
}

function newState() {
  return crypto.randomBytes(32).toString('base64url');
}

function buildAuthorizeUrl(state) {
  const url = new URL('/oauth/authorize', CFG.apiBase);
  url.searchParams.set('app_key', CFG.appKey);
  url.searchParams.set('redirect_uri', CFG.redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('scope', 'user_info');
  return url.toString();
}

// ---------- 页面 ----------
const page = (title, body, extra = '') => `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
  body{font-family:system-ui,-apple-system,"PingFang SC",sans-serif;display:flex;align-items:center;justify-content:center;
       min-height:100vh;margin:0;background:#f4e9d3;color:#2b2218}
  .card{text-align:center;padding:44px 40px;border-radius:18px;background:#fffdf8;box-shadow:0 10px 34px rgba(90,70,40,.12);max-width:420px}
  .ico{font-size:42px;line-height:1}
  h1{font-size:19px;margin:16px 0 8px}
  p{color:#7a6b58;margin:0;font-size:14px;line-height:1.6}
</style></head>
<body><div class="card"><div class="ico">${body.ico}</div><h1>${body.title}</h1><p>${body.text}</p>${extra}</div></body></html>`;

const successPage = () => page('登录成功', {
  ico: '✓',
  title: '授权成功',
  text: '请返回灵感笔记，正在自动完成登录…'
});

const errorPage = (msg) => page('登录失败', { ico: '!', title: '授权未完成', text: msg });

// ---------- HTTP 处理 ----------
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(html)
  });
  res.end(html);
}

function readJsonBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch (err) {
        reject(new Error('请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

// ---------- @ 分享页（公开展示，只存文本与元信息） ----------
/** 笔记 ID：16 字节随机（URL 安全），不可枚举 */
function newNoteId() {
  return crypto.randomBytes(16).toString('base64url');
}

/** 只允许 [A-Za-z0-9_-]，防路径穿越 */
function isSafeNoteId(id) {
  return /^[A-Za-z0-9_-]{8,64}$/.test(String(id || ''));
}

function notePath(id) {
  return path.join(CFG.notesDir, String(id) + '.json');
}

/** 读分享页记录；不存在/损坏返回 null */
function readNote(id) {
  if (!isSafeNoteId(id)) return null;
  try {
    const raw = fs.readFileSync(notePath(id), 'utf8');
    const note = JSON.parse(raw);
    if (!note || typeof note.text !== 'string') return null;
    return note;
  } catch (e) {
    return null;
  }
}

/** 写分享页记录；目录不存在自动创建 */
function writeNote(note) {
  fs.mkdirSync(CFG.notesDir, { recursive: true });
  fs.writeFileSync(notePath(note.id), JSON.stringify(note), 'utf8');
}

/** HTML 转义（分享页内容来自用户输入，必须转义防 XSS） */
function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** 头像 URL 白名单：只允许 http/https，防 javascript: 等注入 */
function safeAvatarUrl(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.length > 500) return '';
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    return raw;
  } catch (e) {
    return '';
  }
}

/** 分享页 HTML：手机优先，纸感卡片；头像用作者真实头像（无头像回退首字母） */
function renderNotePage(note) {
  const text = escapeHtml(note.text);
  const author = escapeHtml(note.author || '灵感笔记用户');
  const tags = Array.isArray(note.tags) && note.tags.length
    ? note.tags.map((t) => `<span class="tag">#${escapeHtml(t)}</span>`).join('')
    : '';
  const time = note.createdAt
    ? new Date(Number(note.createdAt)).toLocaleString('zh-CN', { hour12: false })
    : '';
  const avatar = safeAvatarUrl(note.avatar);
  const avatarHtml = avatar
    ? `<img class="avatar" src="${escapeHtml(avatar)}" alt="${author}" referrerpolicy="no-referrer">`
    : `<div class="avatar">${author.charAt(0).toUpperCase()}</div>`;
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>灵感笔记 · ${author}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
       margin:0;background:#f4e9d3;color:#2b2116;line-height:1.7}
  .wrap{max-width:680px;margin:0 auto;padding:32px 18px 48px}
  .card{background:#fbf7ee;border-radius:16px;padding:26px 22px;
        border:1px solid #e9dcc0;box-shadow:0 1px 2px rgba(60,40,15,.06),0 12px 32px rgba(120,85,40,.10)}
  .meta{display:flex;align-items:center;gap:10px;margin-bottom:14px;
        padding-bottom:14px;border-bottom:1px solid #e9dcc0;font-size:13px;color:#a08a70}
  .avatar{width:36px;height:36px;border-radius:50%;background:#b6774c;color:#fff;
          display:flex;align-items:center;justify-content:center;font-size:15px;flex:none;
          object-fit:cover}
  .author{font-weight:700;color:#2b2116}
  .time{margin-left:auto;white-space:nowrap}
  .text{font-size:16px;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;color:#5d4430}
  .tags{margin-top:18px;display:flex;flex-wrap:wrap;gap:8px}
  .tag{background:#ecdfc4;color:#a05f35;border-radius:999px;padding:3px 12px;font-size:13px;font-weight:600}
  .foot{margin-top:26px;text-align:center;font-size:12px;color:#a08a70}
  .foot a{color:#b6774c;text-decoration:none}
</style></head>
<body><div class="wrap">
  <div class="card">
    <div class="meta">
      ${avatarHtml}
      <div><div class="author">${author}</div><div>灵感笔记</div></div>
      <div class="time">${time}</div>
    </div>
    <div class="text">${text}</div>
    ${tags ? `<div class="tags">${tags}</div>` : ''}
  </div>
  <div class="foot">来自 <a href="${escapeHtml(CFG.siteBase)}">灵感笔记</a> · 仅通过分享链接访问</div>
</div></body></html>`;
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let path = url.pathname.replace(/\/+$/, '') || '/';
  // nginx 反代保留 /oauth、/api 前缀；服务内部统一按无前缀路由匹配
  if (path.startsWith('/oauth/')) path = path.slice('/oauth'.length);
  else if (path.startsWith('/api/')) path = path.slice('/api'.length);

  if (path === '/health') {
    return sendJson(res, 200, { ok: true, configured: !!(CFG.appKey && CFG.appSecret), pending: records.size });
  }

  // 发起登录
  if (path === '/start' && req.method === 'GET') {
    if (!CFG.appKey || !CFG.appSecret) {
      return sendJson(res, 503, { code: 1, message: '服务端未配置 AppKey / AppSecret' });
    }
    sweep();
    const state = newState();
    records.set(state, { state, createdAt: Date.now(), status: 'pending' });
    CFG.log('[oauth] start state=' + state.slice(0, 8) + '…');
    return sendJson(res, 200, { code: 0, data: { state, authorizeUrl: buildAuthorizeUrl(state) } });
  }

  // 平台回调
  if (path === '/callback' && req.method === 'GET') {
    const state = url.searchParams.get('state') || '';
    const code = url.searchParams.get('code') || '';
    const error = url.searchParams.get('error') || '';
    sweep();

    const rec = records.get(state);
    if (!rec) {
      CFG.log('[oauth] callback state 不存在 state=' + state.slice(0, 8) + '…');
      return sendHtml(res, 200, errorPage('授权会话不存在或已过期，请回到灵感笔记重新发起登录。'));
    }
    if (rec.status !== 'pending') {
      return sendHtml(res, 200, errorPage('该授权已处理过，请回到灵感笔记重新发起登录。'));
    }
    if (error || !code) {
      rec.status = 'error';
      rec.error = error || 'no_code';
      rec.createdAt = Date.now();
      CFG.log('[oauth] callback 用户拒绝或缺少 code: ' + (error || 'no_code'));
      return sendHtml(res, 200, errorPage('你已取消授权，请回到灵感笔记重新扫码。'));
    }

    try {
      const tokenData = await exchangeCode(code);
      const qUid = tokenData.user && tokenData.user.q_uid;
      const info = await fetchUserInfo(tokenData.access_token, qUid);
      rec.status = 'ok';
      rec.createdAt = Date.now();
      rec.result = {
        q_uid: qUid || '',
        nickname: (info && info.nickname) || '',
        avatar: (info && info.avatar) || '',
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token || '',
        token_type: tokenData.token_type || 'Bearer',
        expires_in: Number(tokenData.expires_in) || 7200,
        refresh_expires_in: Number(tokenData.refresh_expires_in) || 0,
        authorized_at: Date.now()
      };
      CFG.log('[oauth] 登录成功 q_uid=' + rec.result.q_uid);
      return sendHtml(res, 200, successPage());
    } catch (err) {
      rec.status = 'error';
      rec.error = 'exchange_failed';
      rec.message = err.message;
      rec.createdAt = Date.now();
      CFG.log('[oauth] 换 token 失败: ' + err.message);
      return sendHtml(res, 200, errorPage('与 Q助理 服务通信失败，请回到灵感笔记重试。'));
    }
  }

  // 客户端轮询取结果（一次性）
  if (path === '/poll' && req.method === 'GET') {
    const state = url.searchParams.get('state') || '';
    sweep();
    const rec = records.get(state);
    if (!rec) {
      return sendJson(res, 200, { code: 0, data: { status: 'expired' } });
    }
    if (rec.status === 'pending') {
      return sendJson(res, 200, { code: 0, data: { status: 'pending' } });
    }
    records.delete(state); // 结果只交付一次
    if (rec.status === 'error') {
      return sendJson(res, 200, { code: 0, data: { status: 'error', error: rec.error || 'unknown' } });
    }
    return sendJson(res, 200, { code: 0, data: Object.assign({ status: 'ok' }, rec.result) });
  }

  // 业务签名代理：AppSecret 只在服务端，客户端不能自己签业务请求
  if (path === '/open' && req.method === 'POST') {
    if (CFG.clientPin && req.headers['x-ideanote-pin'] !== CFG.clientPin) {
      return sendJson(res, 403, { code: 1, message: 'forbidden' });
    }
    let body;
    try {
      body = await readJsonBody(req, 2 * 1024 * 1024); // 单条笔记上限 2MB
    } catch (err) {
      return sendJson(res, 400, { code: 1, message: err.message });
    }
    const target = String((body && body.path) || '');
    const method = String((body && body.method) || 'POST').toUpperCase();
    if (!ALLOWED_PATHS.has(target)) {
      return sendJson(res, 403, { code: 1, message: 'path not allowed' });
    }
    if (method !== 'GET' && method !== 'POST') {
      return sendJson(res, 400, { code: 1, message: 'method not allowed' });
    }
    try {
      const r = await proxyOpen(method, target, body.query, body.body, body.access_token);
      return sendJson(res, 200, r);
    } catch (err) {
      CFG.log('[open] 代理失败 ' + method + ' ' + target + ': ' + err.message);
      return sendJson(res, 502, { code: -1, message: 'upstream error: ' + err.message });
    }
  }

  // @ 分享页发布：PIN 鉴权，存盘后返回公开 URL
  if (path === '/notes/publish' && req.method === 'POST') {
    if (CFG.clientPin && req.headers['x-ideanote-pin'] !== CFG.clientPin) {
      return sendJson(res, 403, { code: 1, message: 'forbidden' });
    }
    let body;
    try {
      body = await readJsonBody(req, 128 * 1024); // 单条分享页上限 128KB
    } catch (err) {
      return sendJson(res, 400, { code: 1, message: err.message });
    }
    const text = String((body && body.text) || '').trim();
    if (!text) {
      return sendJson(res, 400, { code: 1, message: '内容为空' });
    }
    if (text.length > 20000) {
      return sendJson(res, 400, { code: 1, message: '内容过长' });
    }
    const note = {
      id: newNoteId(),
      text,
      author: String((body && body.author) || '').slice(0, 64),
      avatar: safeAvatarUrl(body && body.avatar),
      tags: Array.isArray(body && body.tags)
        ? body.tags.map((t) => String(t)).filter((t) => t && t.length <= 32).slice(0, 20)
        : [],
      createdAt: Number((body && body.createdAt) || Date.now())
    };
    writeNote(note);
    CFG.log('[notes] publish id=' + note.id.slice(0, 8) + '… len=' + note.text.length);
    return sendJson(res, 200, {
      code: 0,
      data: { id: note.id, url: CFG.siteBase + '/notes/' + note.id }
    });
  }

  // @ 分享页展示：公开无鉴权，仅返回渲染好的 HTML
  if (path.startsWith('/notes/')) {
    const id = path.slice('/notes/'.length);
    const note = readNote(id);
    if (!note) {
      return sendHtml(res, 404, renderNotePage({ text: '这条笔记不存在或已过期。', author: '灵感笔记', tags: [], createdAt: 0 }));
    }
    return sendHtml(res, 200, renderNotePage(note));
  }

  // 代刷新
  if (path === '/refresh' && req.method === 'POST') {
    if (CFG.clientPin && req.headers['x-ideanote-pin'] !== CFG.clientPin) {
      return sendJson(res, 403, { code: 1, message: 'forbidden' });
    }
    let body;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      return sendJson(res, 400, { code: 1, message: err.message });
    }
    try {
      const data = await refreshToken(body && body.refresh_token);
      CFG.log('[oauth] refresh ok q_uid=' + (data.user && data.user.q_uid));
      return sendJson(res, 200, {
        code: 0,
        data: {
          access_token: data.access_token,
          refresh_token: data.refresh_token || '',
          token_type: data.token_type || 'Bearer',
          expires_in: Number(data.expires_in) || 7200,
          refresh_expires_in: Number(data.refresh_expires_in) || 0,
          q_uid: (data.user && data.user.q_uid) || ''
        }
      });
    } catch (err) {
      // 只有平台明确判定凭证失效才让客户端退出登录；网络/5xx 一律当瞬时故障
      const status = err.invalid ? 401 : 502;
      CFG.log('[oauth] refresh 失败: ' + err.message + ' -> ' + status);
      return sendJson(res, status, {
        code: 1,
        invalid: !!err.invalid,
        message: err.message
      });
    }
  }

  return sendJson(res, 404, { code: 1, message: 'not found' });
}

function createServer() {
  return http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      CFG.log('[oauth] 未捕获异常: ' + (err && err.stack || err));
      try {
        sendJson(res, 500, { code: 1, message: 'internal error' });
      } catch (e) { /* 响应已发出 */ }
    });
  });
}

if (require.main === module) {
  if (!CFG.appKey || !CFG.appSecret) {
    console.error('[oauth] 缺少 QZ_APP_KEY / QZ_APP_SECRET，拒绝启动');
    process.exit(1);
  }
  createServer().listen(CFG.port, '127.0.0.1', () => {
    CFG.log(`[oauth] listening on 127.0.0.1:${CFG.port} redirect_uri=${CFG.redirectUri}`);
  });
}

module.exports = { createServer, exchangeCode, refreshToken, createSign, CFG, records };
