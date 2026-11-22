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
:root{--bg:#070a14;--tx:#eaf0ff;--mut:#7f8db0;--blue:#1769ff;--vio:#7c5cff;--cy:#22d3ee;--pink:#ff4fd8;--good:#3ddc97;--warn:#ffb454;--bad:#ff6b6b;--ice:#9cc2ff;--mono:ui-monospace,"JetBrains Mono","Fira Code",Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--tx);font-family:Inter,"Segoe UI",Arial,sans-serif;overflow:hidden}
.aurora{position:fixed;inset:-20%;filter:blur(80px);opacity:.42;pointer-events:none}
.aurora i{position:absolute;border-radius:50%;width:46vmax;height:46vmax}
.a1{background:var(--blue);left:-4%;top:-8%;animation:f1 19s ease-in-out infinite alternate}
.a2{background:var(--vio);right:-8%;top:8%;animation:f2 23s ease-in-out infinite alternate}
.a3{background:var(--cy);left:28%;bottom:-30%;opacity:.55;animation:f3 21s ease-in-out infinite alternate}
.a4{background:var(--pink);right:18%;bottom:-22%;width:30vmax;height:30vmax;opacity:.35;animation:f1 26s ease-in-out infinite alternate-reverse}
@keyframes f1{to{transform:translate(12vw,9vh) scale(1.15)}}@keyframes f2{to{transform:translate(-10vw,12vh) scale(.9)}}@keyframes f3{to{transform:translate(8vw,-10vh) scale(1.2)}}
.grid{position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);background-size:46px 46px;-webkit-mask-image:radial-gradient(ellipse at center,#000 20%,transparent 72%);mask-image:radial-gradient(ellipse at center,#000 20%,transparent 72%);animation:drift 30s linear infinite}
@keyframes drift{to{background-position:46px 46px}}
.glow{position:fixed;width:460px;height:460px;border-radius:50%;background:radial-gradient(closest-side,rgba(124,92,255,.28),transparent);left:var(--x,50%);top:var(--y,45%);transform:translate(-50%,-50%);pointer-events:none;transition:left .9s ease-out,top .9s ease-out}
@property --a{syntax:"<angle>";initial-value:0deg;inherits:false}
@keyframes spin{to{--a:360deg}}@keyframes rise{from{opacity:0;transform:translateY(22px) scale(.97)}to{opacity:1;transform:none}}
@keyframes inr{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:none}}@keyframes fade{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes pulse{50%{box-shadow:0 0 34px rgba(124,92,255,.8)}}@keyframes blink{50%{opacity:.25}}
.card{position:relative;width:min(420px,92vw);padding:30px 28px 28px;border-radius:20px;background:rgba(10,14,30,.74);-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px);box-shadow:0 30px 90px rgba(0,0,0,.6);animation:rise .9s cubic-bezier(.2,.8,.2,1) both}
.card::before{content:"";position:absolute;inset:0;border-radius:20px;padding:1.5px;background:conic-gradient(from var(--a),rgba(255,255,255,.08) 0 52%,var(--blue) 66%,var(--vio) 76%,var(--pink) 85%,var(--cy) 93%,rgba(255,255,255,.08));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:spin 8s linear infinite;pointer-events:none}
.hd{display:flex;align-items:center;gap:14px;margin-bottom:22px}
.mk{width:46px;height:46px;border-radius:13px;display:grid;place-items:center;background:linear-gradient(135deg,var(--blue),var(--vio) 60%,var(--pink));box-shadow:0 0 22px rgba(124,92,255,.5);animation:pulse 4s ease-in-out infinite}
h1{margin:0;font-size:22px;letter-spacing:-.2px}.sub{margin:3px 0 0;color:var(--mut);font-size:13.5px}
.kv{font-family:var(--mono);font-size:13px;border:1px solid rgba(255,255,255,.09);border-radius:12px;background:rgba(255,255,255,.025);overflow:hidden}
.r{display:flex;justify-content:space-between;gap:14px;padding:12px 14px;opacity:0;animation:inr .6s cubic-bezier(.2,.8,.2,1) forwards}
.r+.r{border-top:1px dashed rgba(255,255,255,.09)}.r:nth-child(1){animation-delay:.35s}.r:nth-child(2){animation-delay:.5s}.r:nth-child(3){animation-delay:.65s}
.r span{color:var(--mut)}.r b{font-weight:500;color:var(--tx);text-align:right}
#sv{display:inline-flex;align-items:center;gap:8px}#sv::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}
.w{color:var(--warn)!important}.i{color:var(--ice)!important}.i::before{animation:blink 1s infinite}.g{color:var(--good)!important}.b{color:var(--bad)!important}
.gw{display:flex;justify-content:center;margin-top:24px;min-height:44px;opacity:0;animation:fade .7s ease .95s forwards;transition:opacity .3s}
.m{margin:14px 0 0;min-height:20px;font-size:13px;line-height:1.5;text-align:center;color:var(--mut)}.m.w{color:var(--warn)}.m.g{color:var(--good)}.m.b{color:var(--bad)}.m.i{color:var(--ice)}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}.r,.gw{opacity:1}}
</style></head><body><div class="aurora"><i class="a1"></i><i class="a2"></i><i class="a3"></i><i class="a4"></i></div><div class="grid"></div><div class="glow"></div>
<main class="card"><div class="hd"><div class="mk"><svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="M3 10h18M7 15h4"/></svg></div>
<div><h1>Card Maker Pro</h1><p class="sub">Sign in to continue</p></div></div>
<div class="kv"><div class="r"><span>access</span><b>approved emails only</b></div><div class="r"><span>method</span><b>google account</b></div><div class="r"><span>status</span><b id="sv" class="w">locked</b></div></div>
<div class="gw" id="gw"><div id="g_id_onload" data-client_id="${esc(env.GOOGLE_CLIENT_ID)}" data-callback="onCred" data-auto_prompt="false"></div>
<div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_blue" data-text="signin_with" data-shape="pill" data-logo_alignment="left"></div></div>
<p class="m" id="msg" role="status"></p><noscript><p class="m w">Turn on JavaScript to sign in.</p></noscript></main>
<script>
var sv=document.getElementById('sv'),msg=document.getElementById('msg'),gw=document.getElementById('gw');
function setS(c,t,m){sv.className=c;sv.textContent=t;msg.className='m '+c;msg.textContent=m||''}
window.onCred=function(r){
  setS('i','verifying','Checking your account...');gw.style.pointerEvents='none';gw.style.opacity='.35';
  fetch('/auth/google',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential:r.credential})})
  .then(function(x){return x.json()}).then(function(d){
    gw.style.pointerEvents='';gw.style.opacity='1';
    if(d.status==='approved'){setS('g','approved','Access granted. Opening the site...');setTimeout(function(){location.href='/'},600)}
    else if(d.status==='pending')setS('w','pending approval','Your email is waiting for approval. Ask the site owner, then sign in again.');
    else if(d.status==='blocked')setS('b','blocked','This email does not have access.');
    else setS('b','error',d.error||'Sign-in failed. Please try again.')
  }).catch(function(){gw.style.pointerEvents='';gw.style.opacity='1';setS('b','error','Network problem. Please try again.')})
};
document.addEventListener('mousemove',function(e){var s=document.documentElement.style;s.setProperty('--x',e.clientX+'px');s.setProperty('--y',e.clientY+'px')});
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
    if (path === '/auth/google' && request.method === 'POST') {
      try { return await authGoogle(request, env); }
      catch (e) { return json({ error: String((e && e.message) || e) }, 500); }
    }

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
