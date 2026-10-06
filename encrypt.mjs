// Encrypt source/index.html with a password into index.html (the page GitHub Pages serves).
// Usage:  node encrypt.mjs          -> asks for the password (typing is hidden)
// The plaintext in source/ stays on this computer only (it is in .gitignore).
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const ITER = 310000;
const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = process.env.SRC || join(HERE, "source/index.html");
const OUT = process.env.OUT || join(HERE, "index.html");

function ask(q) {
  if (process.env.TRIP_PASSWORD) return Promise.resolve(process.env.TRIP_PASSWORD); // for automated tests only
  return new Promise(res => {
    process.stdout.write(q);
    let s = "";
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.setEncoding("utf8");
    const on = ch => {
      if (ch === "\r" || ch === "\n") { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off("data", on); process.stdout.write("\n"); res(s); }
      else if (ch === "\u0003") process.exit(1);
      else if (ch === "\b" || ch === "\x7f") { if (s) { s = [...s].slice(0, -1).join(""); process.stdout.write("\b \b"); } }
      else { s += ch; process.stdout.write("*".repeat([...ch].length)); }
    };
    process.stdin.on("data", on);
  });
}

const b64 = u => Buffer.from(u).toString("base64");
// Keep the same salt across rebuilds so "remember on this device" survives updates (salt is not secret).
let salt;
if (existsSync(OUT)) { const m = readFileSync(OUT, "utf8").match(/data-salt="([^"]+)"/); if (m) salt = Buffer.from(m[1], "base64"); }
if (!salt) salt = crypto.getRandomValues(new Uint8Array(16));

const pw = await ask("ตั้งรหัสผ่าน: ");
if (!process.env.TRIP_PASSWORD) {
  const again = await ask("พิมพ์อีกครั้ง: ");
  if (pw !== again) { console.log("รหัสสองครั้งไม่ตรงกัน ลองใหม่"); process.exit(1); }
}
if ([...pw].length < 4) { console.log("รหัสสั้นเกินไป อย่างน้อย 4 ตัว"); process.exit(1); }

const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, true, ["encrypt"]);
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(readFileSync(SRC, "utf8")));

const page = `<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>แผนเที่ยว 🔒</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🍁</text></svg>">
<style>
:root{--bg:#EEF2EE;--surface:#fff;--ink:#18221F;--muted:#5C6B66;--pine:#2C5A4C;--line:#C9D4CF;--stamp:#C8372D;--persimmon:#E4822F}
@media (prefers-color-scheme:dark){:root{--bg:#121816;--surface:#1B2320;--ink:#E7EEEA;--muted:#9AABA4;--pine:#7FC1A8;--line:#2E3B36;--stamp:#F0675C;--persimmon:#F2A15C}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:var(--bg);color:var(--ink);
  font-family:"Sukhumvit Set","Noto Sans Thai","Leelawadee UI","Thonburi",system-ui,sans-serif;font-size:17px;line-height:1.6}
form{width:100%;max-width:360px;background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:28px 22px;text-align:center}
.ic{font-size:3rem;line-height:1}
h1{font-size:1.5rem;margin:8px 0 4px;color:var(--pine)}
p{margin:0 0 18px;color:var(--muted);font-size:.95rem}
input[type=password]{width:100%;font:inherit;font-size:1.2rem;padding:12px 14px;border-radius:12px;border:2px solid var(--line);background:var(--bg);color:var(--ink);text-align:center}
input[type=password]:focus{outline:none;border-color:var(--persimmon)}
label{display:flex;gap:8px;align-items:center;justify-content:center;margin:14px 0;color:var(--muted);font-size:.95rem}
label input{width:20px;height:20px}
button{width:100%;font:inherit;font-size:1.1rem;font-weight:700;padding:12px;border:0;border-radius:12px;background:var(--pine);color:var(--surface);cursor:pointer}
button:disabled{opacity:.6}
.err{color:var(--stamp);font-weight:600;min-height:1.6em;margin-top:10px}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <div class="ic">🍁</div>
  <h1>แผนเที่ยวเกาหลี</h1>
  <p>ใส่รหัสเพื่อเปิดดูแผน</p>
  <input type="password" id="pw" placeholder="รหัสผ่าน" aria-label="รหัสผ่าน" autofocus>
  <label><input type="checkbox" id="rem" checked> จำไว้ในเครื่องนี้ ไม่ต้องใส่อีก</label>
  <button id="go">เปิดแผนเที่ยว</button>
  <div class="err" id="err" role="alert"></div>
</form>
<div id="box" hidden data-salt="${b64(salt)}" data-iv="${b64(iv)}" data-iter="${ITER}" data-ct="${b64(new Uint8Array(ct))}"></div>
<script>
(function(){
  var box=document.getElementById("box"),K="kr-key";
  var u=function(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0)})};
  var store={get:function(){try{return localStorage.getItem(K)}catch(e){return null}},
    set:function(v){try{localStorage.setItem(K,v)}catch(e){}},del:function(){try{localStorage.removeItem(K)}catch(e){}}};
  function open(key){
    return crypto.subtle.decrypt({name:"AES-GCM",iv:u(box.dataset.iv)},key,u(box.dataset.ct)).then(function(buf){
      var html=new TextDecoder().decode(buf);
      // document.open() only replaces the page once this lock page has finished loading
      var swap=function(){document.open();document.write(html);document.close();};
      if(document.readyState==="complete")swap();else window.addEventListener("load",swap);
    });
  }
  function derive(pw){
    return crypto.subtle.importKey("raw",new TextEncoder().encode(pw.normalize("NFC")),"PBKDF2",false,["deriveKey"]).then(function(b){
      return crypto.subtle.deriveKey({name:"PBKDF2",salt:u(box.dataset.salt),iterations:+box.dataset.iter,hash:"SHA-256"},b,{name:"AES-GCM",length:256},true,["decrypt"]);
    });
  }
  var saved=store.get();
  if(saved){
    crypto.subtle.importKey("raw",u(saved),"AES-GCM",true,["decrypt"]).then(open).catch(function(){store.del();});
  }
  var f=document.getElementById("f"),err=document.getElementById("err"),go=document.getElementById("go");
  f.onsubmit=function(e){
    e.preventDefault();
    var pw=document.getElementById("pw").value;
    if(!pw)return;
    go.disabled=true;go.textContent="กำลังเปิด...";err.textContent="";
    var rem=document.getElementById("rem").checked,key;
    derive(pw).then(function(k){
      key=k;
      // decrypt first so a wrong password is never remembered
      return crypto.subtle.decrypt({name:"AES-GCM",iv:u(box.dataset.iv)},k,u(box.dataset.ct));
    }).then(function(){
      if(rem)return crypto.subtle.exportKey("raw",key).then(function(r){store.set(btoa(String.fromCharCode.apply(null,new Uint8Array(r))));});
    }).then(function(){return open(key);}).catch(function(){
      go.disabled=false;go.textContent="เปิดแผนเที่ยว";err.textContent="รหัสไม่ถูก ลองใหม่อีกครั้ง";
    });
  };
})();
</script>
</body>
</html>
`;
writeFileSync(OUT, page);
console.log(`เข้ารหัสแล้ว -> ${OUT} (${Math.round(page.length / 1024)} KB)`);
