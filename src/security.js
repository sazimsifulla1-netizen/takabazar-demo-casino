import crypto from "node:crypto";
export function hashPassword(password){
  const salt=crypto.randomBytes(16).toString("hex");
  const hash=crypto.scryptSync(password,salt,64).toString("hex");
  return `${salt}:${hash}`;
}
export function verifyPassword(password, stored){
  try{
    const [salt,hex]=String(stored).split(":");
    const a=Buffer.from(hex,"hex"), b=crypto.scryptSync(password,salt,64);
    return a.length===b.length && crypto.timingSafeEqual(a,b);
  }catch{return false}
}
export function randomToken(){return crypto.randomBytes(32).toString("hex")}
export function tokenHash(token){return crypto.createHash("sha256").update(String(token)).digest("hex")}
export function safeText(v,max=200){return String(v??"").replace(/[\u0000-\u001f\u007f]/g," ").trim().slice(0,max)}
export function bdPhone(v){const x=String(v??"").replace(/\D/g,"");return /^01\d{9}$/.test(x)?x:""}
