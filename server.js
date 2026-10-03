import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { db, getUserById, getGame, audit } from "./src/db.js";
import { hashPassword, verifyPassword, randomToken, tokenHash, safeText, bdPhone } from "./src/security.js";
import { gameHandlers } from "./src/gameRegistry.js";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=Number(process.env.PORT||3000);
const ADMIN_PIN=String(process.env.ADMIN_PIN||"64686123");
const SESSION_DAYS=Math.max(1,Number(process.env.SESSION_DAYS||7));
const START_BALANCE=Math.max(0,Math.floor(Number(process.env.DEMO_START_BALANCE||1000)));

app.disable("x-powered-by");
app.set("trust proxy",1);
app.use(express.json({limit:"250kb"}));
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options","DENY");
  if(req.path.startsWith("/api/"))res.setHeader("Cache-Control","no-store");
  next();
});

const rateBuckets=new Map();
function rateLimit(name,limit,windowMs){
  return (req,res,next)=>{
    const now=Date.now(),key=`${name}:${req.ip||"unknown"}`;
    let b=rateBuckets.get(key);
    if(!b||b.reset<=now)b={count:0,reset:now+windowMs};
    b.count++;rateBuckets.set(key,b);
    if(b.count>limit)return res.status(429).json({success:false,message:"Too many requests. Try again shortly."});
    next();
  };
}
const authLimit=rateLimit("auth",30,15*60*1000);
const betLimit=rateLimit("bet",120,10*60*1000);
const adminLimit=rateLimit("admin",20,15*60*1000);

function bearer(req){const h=String(req.headers.authorization||"");return h.startsWith("Bearer ")?h.slice(7):""}
function userAuth(req,res,next){
  const raw=bearer(req);
  if(!raw)return res.status(401).json({success:false,message:"Please login"});
  const row=db.prepare(`SELECT s.id session_id,s.user_id,s.expires_at,u.name,u.phone,u.demo_balance FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(tokenHash(raw));
  if(!row||Number(row.expires_at)<Date.now()){
    if(row)db.prepare("DELETE FROM sessions WHERE id=?").run(row.session_id);
    return res.status(401).json({success:false,message:"Session expired. Please login again."});
  }
  req.user=row;next();
}

const adminSessions=new Map();
function adminAuth(req,res,next){
  const t=String(req.headers["x-admin-token"]||""),s=adminSessions.get(t);
  if(!s||s.expires<Date.now())return res.status(401).json({success:false,message:"Admin login required"});
  s.expires=Date.now()+6*60*60*1000;next();
}

function publicUser(row){return{id:row.id,name:row.name,phone:row.phone,balance:Number(row.demo_balance||0)}}
function validStake(v){const n=Number(v);return Number.isInteger(n)&&n>0?n:0}
function addLedger(userId,type,amount,balance,note){db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,note,created_at) VALUES(?,?,?,?,?,?)").run(userId,type,amount,balance,note,new Date().toISOString())}

app.get("/api/config",(req,res)=>res.json({success:true,brand:"TakaBazar Demo Casino",currency:"DEMO",demoOnly:true}));
app.get("/api/games",(req,res)=>{const games=db.prepare("SELECT slug,name,type,enabled,min_bet,max_bet FROM games WHERE enabled=1 ORDER BY name").all();res.json({success:true,games})});

app.post("/api/register",authLimit,(req,res)=>{
  try{
    const name=safeText(req.body.name,80),phone=bdPhone(req.body.phone),password=String(req.body.password||"");
    if(name.length<2)return res.status(400).json({success:false,message:"Enter your name"});
    if(!phone)return res.status(400).json({success:false,message:"Enter a valid 11-digit Bangladesh mobile number"});
    if(password.length<6)return res.status(400).json({success:false,message:"Password must be at least 6 characters"});
    if(db.prepare("SELECT id FROM users WHERE phone=?").get(phone))return res.status(409).json({success:false,message:"This mobile number is already registered"});
    const now=new Date().toISOString();
    const r=db.prepare("INSERT INTO users(name,phone,password_hash,demo_balance,created_at) VALUES(?,?,?,?,?)").run(name,phone,hashPassword(password),START_BALANCE,now);
    addLedger(Number(r.lastInsertRowid),"WELCOME",START_BALANCE,START_BALANCE,"Welcome demo credits");
    const token=randomToken(),expires=Date.now()+SESSION_DAYS*86400000;
    db.prepare("INSERT INTO sessions(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)").run(Number(r.lastInsertRowid),tokenHash(token),expires,now);
    res.json({success:true,token,user:publicUser(getUserById(Number(r.lastInsertRowid)))});
  }catch(e){console.error(e);res.status(500).json({success:false,message:"Registration failed"})}
});

app.post("/api/login",authLimit,(req,res)=>{
  const phone=bdPhone(req.body.phone),password=String(req.body.password||""),u=db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
  if(!u||!verifyPassword(password,u.password_hash))return res.status(401).json({success:false,message:"Mobile or password is incorrect"});
  const token=randomToken(),expires=Date.now()+SESSION_DAYS*86400000;
  db.prepare("INSERT INTO sessions(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)").run(u.id,tokenHash(token),expires,new Date().toISOString());
  res.json({success:true,token,user:publicUser(u)});
});

app.post("/api/logout",userAuth,(req,res)=>{db.prepare("DELETE FROM sessions WHERE id=?").run(req.user.session_id);res.json({success:true})});
app.get("/api/me",userAuth,(req,res)=>res.json({success:true,user:publicUser(getUserById(req.user.user_id))}));
app.get("/api/ledger",userAuth,(req,res)=>res.json({success:true,rows:db.prepare("SELECT id,type,amount,balance_after,note,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.user_id)}));
app.get("/api/bets",userAuth,(req,res)=>{
  const rows=db.prepare("SELECT id,game_slug,stake,outcome,payout,details_json,created_at FROM bets WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.user_id).map(x=>({...x,details:JSON.parse(x.details_json||"{}")}));
  res.json({success:true,rows});
});

app.post("/api/bet/:slug",betLimit,userAuth,(req,res)=>{
  const game=getGame(req.params.slug);
  if(!game||!game.enabled)return res.status(404).json({success:false,message:"Game is unavailable"});
  const handler=gameHandlers[game.slug];
  if(!handler)return res.status(501).json({success:false,message:"Game handler is not installed"});
  const stake=validStake(req.body.stake);
  if(!stake||stake<game.min_bet||stake>game.max_bet)return res.status(400).json({success:false,message:`Bet must be ${game.min_bet}-${game.max_bet} demo credits`});
  db.exec("BEGIN IMMEDIATE");
  try{
    const u=db.prepare("SELECT * FROM users WHERE id=?").get(req.user.user_id);
    if(!u)throw new Error("User not found");
    if(Number(u.demo_balance)<stake){db.exec("ROLLBACK");return res.status(400).json({success:false,message:"Not enough demo credits"})}
    const result=handler(req.body),payout=Math.floor(stake*Number(result.payoutMultiplier||0)),newBalance=Number(u.demo_balance)-stake+payout;
    db.prepare("UPDATE users SET demo_balance=? WHERE id=?").run(newBalance,u.id);
    const now=new Date().toISOString();
    const br=db.prepare("INSERT INTO bets(user_id,game_slug,stake,outcome,payout,details_json,created_at) VALUES(?,?,?,?,?,?,?)").run(u.id,game.slug,stake,result.outcome,payout,JSON.stringify(result.details),now);
    addLedger(u.id,"BET",-stake,Number(u.demo_balance)-stake,`${game.name} stake`);
    if(payout>0)addLedger(u.id,"WIN",payout,newBalance,`${game.name} payout`);
    db.exec("COMMIT");
    res.json({success:true,betId:Number(br.lastInsertRowid),game:game.slug,stake,outcome:result.outcome,payout,win:Boolean(result.details.win),balance:newBalance,details:result.details});
  }catch(e){try{db.exec("ROLLBACK")}catch{};res.status(400).json({success:false,message:e?.message||"Bet failed"})}
});

app.post("/api/support",userAuth,(req,res)=>{
  const subject=safeText(req.body.subject,120),message=safeText(req.body.message,1200);
  if(subject.length<3||message.length<5)return res.status(400).json({success:false,message:"Write a subject and message"});
  const now=new Date().toISOString();
  const r=db.prepare("INSERT INTO support_tickets(user_id,subject,message,status,created_at,updated_at) VALUES(?,?,?,?,?,?)").run(req.user.user_id,subject,message,"Open",now,now);
  res.json({success:true,ticketId:Number(r.lastInsertRowid)});
});
app.get("/api/support",userAuth,(req,res)=>res.json({success:true,rows:db.prepare("SELECT id,subject,message,status,created_at,updated_at FROM support_tickets WHERE user_id=? ORDER BY id DESC").all(req.user.user_id)}));

app.post("/api/admin/login",adminLimit,(req,res)=>{
  if(String(req.body.pin||"")!==ADMIN_PIN)return res.status(401).json({success:false,message:"Wrong admin PIN"});
  const token=crypto.randomBytes(24).toString("hex");adminSessions.set(token,{expires:Date.now()+6*60*60*1000});audit("ADMIN_LOGIN",{ip:req.ip});res.json({success:true,token});
});
app.get("/api/admin/dashboard",adminAuth,(req,res)=>{
  const users=db.prepare("SELECT COUNT(*) n FROM users").get().n,bets=db.prepare("SELECT COUNT(*) n FROM bets").get().n,tickets=db.prepare("SELECT COUNT(*) n FROM support_tickets WHERE status!='Closed'").get().n,wagered=db.prepare("SELECT COALESCE(SUM(stake),0) n FROM bets").get().n;
  res.json({success:true,stats:{users,bets,openTickets:tickets,wagered}});
});
app.get("/api/admin/users",adminAuth,(req,res)=>res.json({success:true,rows:db.prepare("SELECT id,name,phone,demo_balance,created_at FROM users ORDER BY id DESC LIMIT 300").all()}));
app.post("/api/admin/users/:id/adjust",adminAuth,(req,res)=>{
  const amount=Number(req.body.amount),note=safeText(req.body.note,160)||"Admin adjustment";
  if(!Number.isInteger(amount)||amount===0||Math.abs(amount)>100000)return res.status(400).json({success:false,message:"Enter a valid whole-number adjustment"});
  db.exec("BEGIN IMMEDIATE");
  try{
    const u=db.prepare("SELECT * FROM users WHERE id=?").get(Number(req.params.id));
    if(!u){db.exec("ROLLBACK");return res.status(404).json({success:false,message:"User not found"})}
    const balance=Number(u.demo_balance)+amount;
    if(balance<0){db.exec("ROLLBACK");return res.status(400).json({success:false,message:"Balance cannot go below zero"})}
    db.prepare("UPDATE users SET demo_balance=? WHERE id=?").run(balance,u.id);addLedger(u.id,"ADMIN",amount,balance,note);audit("BALANCE_ADJUST",{userId:u.id,amount,note});db.exec("COMMIT");res.json({success:true,balance});
  }catch(e){try{db.exec("ROLLBACK")}catch{};res.status(500).json({success:false,message:"Adjustment failed"})}
});
app.get("/api/admin/games",adminAuth,(req,res)=>res.json({success:true,rows:db.prepare("SELECT slug,name,type,enabled,min_bet,max_bet FROM games ORDER BY name").all()}));
app.patch("/api/admin/games/:slug",adminAuth,(req,res)=>{
  const g=getGame(req.params.slug);if(!g)return res.status(404).json({success:false,message:"Game not found"});
  const enabled=req.body.enabled===undefined?g.enabled:(req.body.enabled?1:0),minBet=Math.max(1,Math.floor(Number(req.body.minBet??g.min_bet))),maxBet=Math.max(minBet,Math.floor(Number(req.body.maxBet??g.max_bet)));
  db.prepare("UPDATE games SET enabled=?,min_bet=?,max_bet=? WHERE slug=?").run(enabled,minBet,maxBet,g.slug);audit("GAME_UPDATE",{slug:g.slug,enabled,minBet,maxBet});res.json({success:true});
});
app.get("/api/admin/bets",adminAuth,(req,res)=>res.json({success:true,rows:db.prepare(`SELECT b.id,b.game_slug,b.stake,b.outcome,b.payout,b.created_at,u.name,u.phone FROM bets b JOIN users u ON u.id=b.user_id ORDER BY b.id DESC LIMIT 300`).all()}));
app.get("/api/admin/support",adminAuth,(req,res)=>res.json({success:true,rows:db.prepare(`SELECT t.id,t.subject,t.message,t.status,t.created_at,t.updated_at,u.name,u.phone FROM support_tickets t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 300`).all()}));
app.patch("/api/admin/support/:id",adminAuth,(req,res)=>{
  const status=["Open","In Progress","Closed"].includes(req.body.status)?req.body.status:"Open";
  db.prepare("UPDATE support_tickets SET status=?,updated_at=? WHERE id=?").run(status,new Date().toISOString(),Number(req.params.id));audit("SUPPORT_STATUS",{ticketId:Number(req.params.id),status});res.json({success:true});
});
app.get("/api/admin/audit",adminAuth,(req,res)=>res.json({success:true,rows:db.prepare("SELECT id,action,details_json,created_at FROM admin_audit ORDER BY id DESC LIMIT 200").all()}));

app.use(express.static(path.join(__dirname,"public"),{extensions:["html"]}));
app.get("/{*splat}",(req,res)=>{
  if(req.path.startsWith("/api/"))return res.status(404).json({success:false,message:"API not found"});
  res.sendFile(path.join(__dirname,"public","index.html"));
});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({success:false,message:"Server error"})});
app.listen(PORT,()=>{
  console.log(`TakaBazar Demo Casino running on http://localhost:${PORT}`);
  if(process.env.ADMIN_PIN===undefined)console.warn("WARNING: using default demo ADMIN_PIN. Change it in production.");
});
