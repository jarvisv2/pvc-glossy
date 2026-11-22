const enc = new TextEncoder();
const dec = new TextDecoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const html = (b, status = 200) => new Response(b, { status, headers: { 'content-type': 'text/html;charset=utf-8', 'cache-control': 'no-store' } });
const json = (o, status = 200, h = {}) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...h } });

const hmacKey = (secret) => crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

async function makeSession(env, email) {
  const p = b64u(enc.encode(JSON.stringify({ e: email, x: Date.now() + 7 * 864e5 })));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env.SESSION_SECRET), enc.encode(p));
  return p + '.' + b64u(sig);
}

// Returns the email only if the cookie is valid AND the user is still "approved" in D1
async function readSession(env, request) {
  const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [p, s] = m[1].split('.');
  if (!p || !s) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(env.SESSION_SECRET), unb64u(s), enc.encode(p));
    if (!ok) return null;
    const d = JSON.parse(dec.decode(unb64u(p)));
    if (d.x < Date.now()) return null;
    const row = await env.DB.prepare('SELECT status FROM users WHERE email=?').bind(d.e).first();
    return row && row.status === 'approved' ? d.e : null;
  } catch { return null; }
}

async function verifyGoogle(env, idToken) {
  const [h, p, s] = idToken.split('.');
  const head = JSON.parse(dec.decode(unb64u(h)));
  const claims = JSON.parse(dec.decode(unb64u(p)));
  const jwks = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = jwks.keys.find((k) => k.kid === head.kid);
  if (!jwk || head.alg !== 'RS256') throw new Error('bad key');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(s), enc.encode(h + '.' + p)))) throw new Error('bad signature');
  const issOk = ['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss);
  if (!issOk || claims.aud !== env.GOOGLE_CLIENT_ID || claims.exp * 1000 < Date.now() || !claims.email_verified) throw new Error('bad claims');
  return { email: claims.email.toLowerCase(), name: claims.name || '' };
}

async function authGoogle(request, env) {
  if (request.headers.get('origin') !== new URL(request.url).origin) return json({ error: 'bad origin' }, 403);
  let user;
  try { user = await verifyGoogle(env, (await request.json()).credential); }
  catch { return json({ error: 'Google verification failed' }, 401); }

  const owner = user.email === env.OWNER_EMAIL.toLowerCase();
  const now = new Date().toISOString();
  await env.DB.prepare('INSERT INTO users(email,name,status,created_at,last_login) VALUES(?1,?2,?3,?4,?4) ON CONFLICT(email) DO UPDATE SET name=?2, last_login=?4')
    .bind(user.email, user.name, owner ? 'approved' : 'pending', now).run();
  if (owner) await env.DB.prepare("UPDATE users SET status='approved' WHERE email=?").bind(user.email).run();
  const { status } = await env.DB.prepare('SELECT status FROM users WHERE email=?').bind(user.email).first();

  const cf = request.cf || {};
  await env.DB.prepare('INSERT INTO logins(email,name,result,ip,country,ua,ts) VALUES(?,?,?,?,?,?,?)')
    .bind(user.email, user.name, status, request.headers.get('cf-connecting-ip') || '', cf.country || '', (request.headers.get('user-agent') || '').slice(0, 200), now).run();

  const h = {};
  if (status === 'approved') h['set-cookie'] = `sid=${await makeSession(env, user.email)}; Path=/; Max-Age=604800; Secure; HttpOnly; SameSite=Lax`;
  return json({ status }, 200, h);
}

function loginPage(env) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Card Maker Pro</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#eef4fb;font-family:Inter,Segoe UI,Arial,sans-serif;color:#10243d}
main{width:min(380px,92vw);background:#fff;border:1px solid #d9e2ee;border-radius:14px;padding:32px 28px;box-shadow:0 14px 40px rgba(22,50,85,.10)}
h1{margin:0 0 6px;font-size:24px;color:#17345d}p{margin:0 0 22px;color:#65768d;font-size:14px;line-height:1.5}
.g{display:flex;justify-content:center;min-height:44px}#msg{margin-top:18px;font-size:14px;line-height:1.5;min-height:20px}.ok{color:#0a9b6f}.warn{color:#a96800}.bad{color:#d92d20}
</style></head><body><main>
<h1>Card Maker Pro</h1><p>Sign in with your Google account. Access is limited to approved emails.</p>
<div class="g"><div id="g_id_onload" data-client_id="${esc(env.GOOGLE_CLIENT_ID)}" data-callback="onCred" data-auto_prompt="false"></div>
<div class="g_id_signin" data-type="standard" data-size="large" data-theme="outline" data-text="signin_with" data-shape="pill"></div></div>
<div id="msg" role="status"></div></main>
<script>
function say(t,c){var m=document.getElementById('msg');m.textContent=t;m.className=c}
window.onCred=function(r){say('Checking…','');
fetch('/auth/google',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential:r.credential})})
.then(function(x){return x.json()}).then(function(d){
if(d.status==='approved'){say('Signed in. Opening…','ok');location.href='/'}
else if(d.status==='pending')say('Your email is waiting for approval. Ask the site owner to approve it, then sign in again.','warn');
else if(d.status==='blocked')say('This email does not have access.','bad');
else say('Sign-in failed. Please try again.','bad')}).catch(function(){say('Network error. Please try again.','bad')})};
</script><script src="https://accounts.google.com/gsi/client" async defer></script></body></html>`;
}

async function adminPage(env) {
  const users = (await env.DB.prepare("SELECT * FROM users ORDER BY (status='pending') DESC, last_login DESC").all()).results;
  const logs = (await env.DB.prepare('SELECT * FROM logins ORDER BY id DESC LIMIT 100').all()).results;
  const btn = (e, s, t) => `<button onclick="setS('${esc(e).replace(/'/g, '')}','${s}')">${t}</button>`;
  const rows = users.map((u) => `<tr><td>${esc(u.email)}<br><small>${esc(u.name)}</small></td><td><b class="${esc(u.status)}">${esc(u.status)}</b></td><td>${esc(u.last_login)}</td><td>${btn(u.email, 'approved', 'Approve')} ${btn(u.email, 'blocked', 'Block')}</td></tr>`).join('');
  const lrows = logs.map((l) => `<tr><td>${esc(l.ts)}</td><td>${esc(l.email)}</td><td>${esc(l.result)}</td><td>${esc(l.ip)}</td><td>${esc(l.country)}</td></tr>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin</title><style>
body{font-family:Inter,Segoe UI,Arial,sans-serif;background:#eef4fb;color:#10243d;margin:0;padding:20px}h1,h2{color:#17345d}table{width:100%;border-collapse:collapse;background:#fff;margin-bottom:28px}
td,th{border:1px solid #d9e2ee;padding:8px;font-size:13px;text-align:left;vertical-align:top}.wrap{overflow-x:auto}button{padding:5px 10px;border:0;border-radius:6px;background:#1769ff;color:#fff;cursor:pointer}
.approved{color:#0a9b6f}.pending{color:#a96800}.blocked{color:#d92d20}</style></head><body>
<h1>Who can open the site</h1><p><a href="/">Open site</a> · <a href="/logout">Log out</a></p>
<h2>Users</h2><div class="wrap"><table><tr><th>Email</th><th>Status</th><th>Last sign-in</th><th>Action</th></tr>${rows}</table></div>
<h2>Recent sign-ins</h2><div class="wrap"><table><tr><th>Time (UTC)</th><th>Email</th><th>Result</th><th>IP</th><th>Country</th></tr>${lrows}</table></div>
<script>function setS(e,s){fetch('/admin/set',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:e,status:s})}).then(function(){location.reload()})}</script></body></html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/login') return html(loginPage(env));
    if (path === '/logout') return new Response(null, { status: 302, headers: { location: '/login', 'set-cookie': 'sid=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax' } });
    if (path === '/auth/google' && request.method === 'POST') return authGoogle(request, env);

    const email = await readSession(env, request);
    if (!email) return request.method === 'GET' ? Response.redirect(url.origin + '/login', 302) : new Response('Login required', { status: 401 });

    if (path === '/admin' || path === '/admin/set') {
      if (email !== env.OWNER_EMAIL.toLowerCase()) return new Response('Not allowed', { status: 403 });
      if (path === '/admin') return html(await adminPage(env));
      if (request.method === 'POST' && request.headers.get('origin') === url.origin) {
        const { email: target, status } = await request.json();
        if (['approved', 'blocked', 'pending'].includes(status) && target.toLowerCase() !== env.OWNER_EMAIL.toLowerCase()) {
          await env.DB.prepare('UPDATE users SET status=? WHERE email=?').bind(status, target).run();
        }
        return json({ ok: true });
      }
      return new Response('Bad request', { status: 400 });
    }
    return env.ASSETS.fetch(request);
  },
};
