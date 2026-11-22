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
:root{--bg:#060b16;--panel:#0b1324;--line:#1c2a4a;--blue:#1769ff;--ice:#8fb8ff;--tx:#e6eeff;--mut:#6c7fa6;--good:#3ddc97;--warn:#ffb454;--bad:#ff6b6b;--mono:"JetBrains Mono","Fira Code",ui-monospace,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--tx);font-family:var(--mono);overflow:hidden}
.bg{position:fixed;inset:0;background-image:linear-gradient(#0f1a33 1px,transparent 1px),linear-gradient(90deg,#0f1a33 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse at center,#000 25%,transparent 75%);mask-image:radial-gradient(ellipse at center,#000 25%,transparent 75%);animation:drift 26s linear infinite}
.glow{position:fixed;width:560px;height:560px;border-radius:50%;background:radial-gradient(closest-side,rgba(23,105,255,.30),transparent);left:var(--x,50%);top:var(--y,42%);transform:translate(-50%,-50%);pointer-events:none;transition:left .8s ease-out,top .8s ease-out}
@keyframes drift{to{background-position:44px 44px}}
@property --a{syntax:"<angle>";initial-value:0deg;inherits:false}
@keyframes spin{to{--a:360deg}}
@keyframes rise{from{opacity:0;transform:translateY(18px) scale(.98)}to{opacity:1;transform:none}}
@keyframes blink{50%{opacity:0}}
.win{position:relative;width:min(470px,92vw);background:var(--panel);border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.55),0 0 60px rgba(23,105,255,.12);animation:rise .8s cubic-bezier(.2,.8,.2,1) both}
.win::before{content:"";position:absolute;inset:0;border-radius:14px;padding:1px;background:conic-gradient(from var(--a),var(--line) 0 62%,var(--blue) 82%,var(--ice) 90%,var(--line) 100%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:spin 7s linear infinite;pointer-events:none}
.bar{display:flex;justify-content:space-between;align-items:center;padding:0 18px;height:44px;border-bottom:1px solid var(--line);font-size:12px;color:var(--mut)}
.tab{color:var(--tx);padding:13px 0 12px;border-bottom:2px solid var(--blue);margin-bottom:-1px}
.st{display:flex;align-items:center;gap:8px}.st::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--warn);box-shadow:0 0 10px currentColor;color:var(--warn)}
.win[data-s=ok] .st::before{background:var(--good);color:var(--good)}.win[data-s=bad] .st::before{background:var(--bad);color:var(--bad)}.win[data-s=busy] .st::before{background:var(--ice);color:var(--ice);animation:blink 1s infinite}
.code{padding:22px 18px 8px;font-size:13.5px;line-height:2;min-height:170px}
.ln{display:flex;gap:16px;white-space:pre-wrap;word-break:break-word}.ln i{color:#34456b;font-style:normal;min-width:1.4em;text-align:right;user-select:none}
.k{color:#7aa7ff}.s{color:#7ee0b5}.c{color:var(--mut)}.n{color:var(--tx)}.g{color:var(--good)}.w{color:var(--warn)}.b{color:var(--bad)}
.caret{display:inline-block;width:8px;height:1.1em;background:var(--ice);vertical-align:-3px;margin-left:2px;animation:blink 1s steps(1) infinite}
.gw{padding:6px 18px 26px 52px;opacity:0;transform:translateY(10px);pointer-events:none;transition:opacity .6s ease,transform .6s ease;min-height:76px}
.gw.on{opacity:1;transform:none;pointer-events:auto}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media (max-width:420px){.code{font-size:12.5px}.gw{padding-left:18px}}
</style></head><body><div class="bg"></div><div class="glow" id="glow"></div>
<main class="win" id="win" data-s="lock"><div class="bar"><span class="tab">access.js</span><span class="st" id="st">locked</span></div>
<div class="code" id="code" aria-live="polite"></div>
<div class="gw" id="gw"><div id="g_id_onload" data-client_id="${esc(env.GOOGLE_CLIENT_ID)}" data-callback="onCred" data-auto_prompt="false"></div>
<div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_black" data-text="signin_with" data-shape="rectangular" data-logo_alignment="left"></div></div>
<noscript><p style="padding:0 18px 20px;color:#ffb454">Turn on JavaScript to sign in.</p></noscript></main>
<script>
var code=document.getElementById('code'),win=document.getElementById('win'),st=document.getElementById('st'),gw=document.getElementById('gw');
var RM=window.matchMedia('(prefers-reduced-motion: reduce)').matches,n=0,caret=document.createElement('span');caret.className='caret';
function state(s,t){win.setAttribute('data-s',s);st.textContent=t}
function line(tokens,done){
  n++;var row=document.createElement('div');row.className='ln';
  var g=document.createElement('i');g.textContent=n;var t=document.createElement('span');
  row.appendChild(g);row.appendChild(t);code.appendChild(row);
  var i=0,j=0,cur=null;
  (function step(){
    if(i>=tokens.length){if(done)done();return}
    var tk=tokens[i];
    if(j===0){cur=document.createElement('span');cur.className=tk[1];t.appendChild(cur)}
    if(RM){cur.textContent=tk[0];i++;j=0;return step()}
    j++;cur.textContent=tk[0].slice(0,j);t.appendChild(caret);
    if(j>=tk[0].length){i++;j=0}
    setTimeout(step,12+Math.random()*20)
  })()
}
function seq(list,done){(function next(k){if(k>=list.length){if(done)done();return}line(list[k],function(){next(k+1)})})(0)}
seq([
  [['// card-maker-pro / access control','c']],
  [['const ','k'],['site','n'],[' = ','n'],['"Card Maker Pro"','s'],[';','n']],
  [['const ','k'],['access','n'],[' = ','n'],['"approved emails only"','s'],[';','n']],
  [['await ','k'],['signIn','n'],['(','n'],['"google"','s'],[');','n']]
],function(){gw.className='gw on';state('lock','waiting for sign-in')});
window.onCred=function(r){
  gw.className='gw';state('busy','verifying');
  seq([[['> verifying token...','c']]],function(){
    fetch('/auth/google',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential:r.credential})})
    .then(function(x){return x.json()}).then(function(d){
      if(d.status==='approved'){state('ok','access granted');seq([[['> status: ','n'],['"approved"','g']],[['> opening site...','c']]],function(){location.href='/'})}
      else if(d.status==='pending'){state('lock','pending approval');seq([[['> status: ','n'],['"pending"','w']],[['// your email is waiting for approval.','c']],[['// ask the site owner, then sign in again.','c']]],function(){gw.className='gw on'})}
      else if(d.status==='blocked'){state('bad','access denied');seq([[['> status: ','n'],['"blocked"','b']],[['// this email does not have access.','c']]])}
      else{state('bad','error');seq([[['> error: ','n'],['"'+(d.error||'sign-in failed')+'"','b']]],function(){gw.className='gw on'})}
    }).catch(function(){state('bad','error');seq([[['> error: ','n'],['"network problem, try again"','b']]],function(){gw.className='gw on'})})
  })
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
