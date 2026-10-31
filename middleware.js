/**
 * 홍담오가피진 관리 페이지 로그인 · 권한 (Vercel Routing Middleware)
 *
 * 역할
 *   - 관리자(admin)   : 답변 템플릿 + 설정(시트 연동·자동답변) + 설정 가이드
 *   - 부관리자(staff) : 답변 템플릿만
 *
 * Vercel → Settings → Environment Variables 에 아래 값을 넣어야 동작합니다.
 *   ADMIN_ID, ADMIN_PASSWORD         관리자 아이디 / 비밀번호
 *   SUBADMIN_ID, SUBADMIN_PASSWORD   부관리자 아이디 / 비밀번호
 *   SESSION_SECRET                   아무 긴 무작위 문자열(32자 이상)
 * 값이 비어 있으면 아무도 로그인할 수 없습니다(안전하게 잠김).
 */

export const config = {
  matcher: [
    '/admin',
    '/admin/:path*',
    '/admin.html',
    '/admin-settings.html',
    '/setup-guide.html',
  ],
};

const COOKIE = 'hd_session';
const UI_COOKIE = 'hd_role'; // 화면 표시용(권한 판단에는 쓰지 않음)
const SESSION_HOURS = 12;

// 경로별 허용 역할
const ACCESS = {
  '/admin.html': ['admin', 'staff'],
  '/admin-settings.html': ['admin'],
  '/setup-guide.html': ['admin'],
};

const ROLE_LABEL = { admin: '관리자', staff: '부관리자' };

/* ───────── 진입점 ───────── */
export default async function middleware(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const env = readEnv();

  if (path === '/admin/logout') return logout();
  if (path === '/admin/login') {
    if (request.method === 'POST') return handleLogin(request, env);
    return loginPage({ next: safeNext(url.searchParams.get('next')), error: url.searchParams.get('e') });
  }
  if (path === '/admin' || path === '/admin/') return redirect('/admin.html');

  const allowed = ACCESS[path];
  if (!allowed) return redirect('/admin.html');

  const session = env.ok ? await readSession(request, env.secret) : null;
  if (!session) return redirect('/admin/login?next=' + encodeURIComponent(path));
  if (!allowed.includes(session.r)) return forbidden(session);

  return next();
}

/* ───────── 로그인 처리 ───────── */
async function handleLogin(request, env) {
  let id = '', pw = '', nextPath = '/admin.html';
  try {
    const form = await request.formData();
    id = String(form.get('id') || '').trim();
    pw = String(form.get('pw') || '');
    nextPath = safeNext(form.get('next'));
  } catch (_) { /* 빈 값으로 처리 */ }

  if (!env.ok) return redirect('/admin/login?e=setup');

  let role = null;
  for (const acc of env.accounts) {
    const idOk = await safeEqual(id, acc.id, env.secret);
    const pwOk = await safeEqual(pw, acc.pw, env.secret);
    if (idOk && pwOk) role = acc.role;
  }

  if (!role) {
    await sleep(800); // 무차별 대입 속도 늦추기
    return redirect('/admin/login?e=1&next=' + encodeURIComponent(nextPath));
  }

  // 부관리자가 관리자 전용 페이지로 가려던 경우 템플릿 화면으로
  if (!(ACCESS[nextPath] || []).includes(role)) nextPath = '/admin.html';

  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  const token = await signSession({ r: role, u: id, e: exp }, env.secret);
  const maxAge = SESSION_HOURS * 3600;
  const headers = new Headers({ Location: nextPath, 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', `${COOKIE}=${token}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`);
  headers.append('Set-Cookie', `${UI_COOKIE}=${role}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax`);
  return new Response(null, { status: 303, headers });
}

function logout() {
  const headers = new Headers({ Location: '/admin/login', 'Cache-Control': 'no-store' });
  headers.append('Set-Cookie', `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  headers.append('Set-Cookie', `${UI_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Lax`);
  return new Response(null, { status: 303, headers });
}

/* ───────── 세션 서명 ───────── */
async function signSession(payload, secret) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = b64url(await hmac(secret, body));
  return `${body}.${sig}`;
}

async function readSession(request, secret) {
  const token = getCookie(request, COOKIE);
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = b64url(await hmac(secret, body));
  if (!(await safeEqual(sig, expected, secret))) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromB64url(body)));
    if (!data || typeof data.e !== 'number' || data.e < Date.now()) return null;
    if (!ROLE_LABEL[data.r]) return null;
    return data;
  } catch (_) {
    return null;
  }
}

/* ───────── 유틸 ───────── */
function readEnv() {
  const e = (typeof process !== 'undefined' && process.env) || {};
  const secret = e.SESSION_SECRET || '';
  const accounts = [];
  if (e.ADMIN_PASSWORD) accounts.push({ role: 'admin', id: e.ADMIN_ID || 'admin', pw: e.ADMIN_PASSWORD });
  if (e.SUBADMIN_PASSWORD) accounts.push({ role: 'staff', id: e.SUBADMIN_ID || 'staff', pw: e.SUBADMIN_PASSWORD });
  return { ok: secret.length >= 16 && accounts.length > 0, secret, accounts };
}

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(text)));
}

// 길이·내용과 무관하게 같은 시간이 걸리는 비교
async function safeEqual(a, b, secret) {
  const [x, y] = await Promise.all([hmac(secret, 'cmp:' + a), hmac(secret, 'cmp:' + b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

function getCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function safeNext(v) {
  const p = String(v || '');
  return ACCESS[p] ? p : '/admin.html';
}

function next() {
  return new Response(null, { headers: { 'x-middleware-next': '1' } });
}
function redirect(location) {
  return new Response(null, { status: 303, headers: { Location: location, 'Cache-Control': 'no-store' } });
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ───────── 화면 ───────── */
function shell(title, inner, status = 200) {
  const html = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)}</title>
<link rel="icon" href="/favicon-32.png">
<style>
:root{--green:#14291C;--green-mid:#1E3D2A;--gold:#C9A24B;--cream:#F6F1E7;--ink:#1A1A1A;--muted:#6B7280;--surface:#fff;--border:#DDD6C8;--err:#B4432F}
@media(prefers-color-scheme:dark){:root{--cream:#1A2218;--surface:#1E2D1E;--border:#2E4030;--ink:#F0EBE0;--muted:#8FA08A}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Apple SD Gothic Neo',sans-serif;background:var(--cream);color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.box{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden}
.top{background:var(--green);padding:22px 26px;display:flex;align-items:center;gap:12px}
.dot{width:10px;height:10px;border-radius:50%;background:var(--gold)}
.t1{color:#fff;font-weight:700;font-size:17px}.t2{color:rgba(255,255,255,.55);font-size:12px;margin-top:2px}
.body{padding:26px}
label{display:block;font-size:13px;font-weight:700;margin:0 0 6px}
input{width:100%;padding:12px 14px;border:1.5px solid var(--border);border-radius:8px;font-size:15px;background:var(--surface);color:var(--ink);margin-bottom:16px}
input:focus{outline:none;border-color:var(--gold)}
button,.btn{display:block;width:100%;text-align:center;text-decoration:none;background:var(--green);color:#fff;border:none;padding:13px;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer}
button:hover,.btn:hover{background:var(--green-mid)}
.msg{font-size:13px;line-height:1.6;padding:10px 12px;border-radius:8px;margin-bottom:16px;background:rgba(180,67,47,.1);color:var(--err)}
.note{font-size:13px;color:var(--muted);line-height:1.7;margin-bottom:18px}
.link{display:block;text-align:center;margin-top:12px;font-size:13px;color:var(--muted)}
</style></head><body>${inner}</body></html>`;
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' },
  });
}

function loginPage({ next: nextPath, error }) {
  const msg =
    error === 'setup'
      ? '<div class="msg">로그인 설정이 아직 안 되어 있습니다. Vercel 환경변수(ADMIN_PASSWORD 등)를 확인해 주세요.</div>'
      : error
      ? '<div class="msg">아이디 또는 비밀번호가 맞지 않습니다.</div>'
      : '';
  return shell(
    '홍담오가피진 관리 로그인',
    `<div class="box">
  <div class="top"><div class="dot"></div><div><div class="t1">홍담오가피진 관리</div><div class="t2">관리자 · 부관리자 로그인</div></div></div>
  <form class="body" method="POST" action="/admin/login">
    ${msg}
    <input type="hidden" name="next" value="${esc(nextPath)}">
    <label for="id">아이디</label>
    <input id="id" name="id" autocomplete="username" required autofocus>
    <label for="pw">비밀번호</label>
    <input id="pw" name="pw" type="password" autocomplete="current-password" required>
    <button type="submit">로그인</button>
  </form>
</div>`
  );
}

function forbidden(session) {
  return shell(
    '접근 권한 없음',
    `<div class="box">
  <div class="top"><div class="dot"></div><div><div class="t1">접근 권한이 없습니다</div><div class="t2">${esc(ROLE_LABEL[session.r])} · ${esc(session.u)}</div></div></div>
  <div class="body">
    <p class="note">이 화면은 관리자만 볼 수 있습니다.<br>부관리자는 답변 템플릿 화면을 이용해 주세요.</p>
    <a class="btn" href="/admin.html">답변 템플릿으로 가기</a>
    <a class="link" href="/admin/logout">다른 계정으로 로그인</a>
  </div>
</div>`,
    403
  );
}
