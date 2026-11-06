const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_BEFORE_PRODUCTION";
const OWNER_EMAIL = process.env.OWNER_EMAIL || "admin@example.com";
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "ChangeMoi123!";
const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify({ users: [], clients: [], dossiers: [] }, null, 2)
  );
}

app.use(express.json());
app.use(express.static(path.join(__dirname, ".")));

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [], clients: [], dossiers: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users: [], clients: [], dossiers: [] }; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

async function ensureOwner() {
  const db = loadDB();
  if (!db.users.find(u => u.email.toLowerCase() === OWNER_EMAIL.toLowerCase())) {
    db.users.push({
      id: "admin-1", email: OWNER_EMAIL.toLowerCase(),
      passwordHash: await bcrypt.hash(OWNER_PASSWORD, 12),
      role: "admin", name: "Administratrice"
    });
    saveDB(db);
  }
}
function auth(req,res,next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({error:"Non authentifiée"});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"Session expirée"}); }
}
function admin(req,res,next) {
  if (req.user.role !== "admin") return res.status(403).json({error:"Accès réservé"});
  next();
}

app.post("/api/login", async (req,res) => {
  const {email,password} = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.email === String(email||"").toLowerCase());
  if (!user || !(await bcrypt.compare(String(password||""), user.passwordHash)))
    return res.status(401).json({error:"E-mail ou mot de passe incorrect"});
  const token = jwt.sign({id:user.id,email:user.email,role:user.role,name:user.name}, JWT_SECRET, {expiresIn:"12h"});
  res.json({token,user:{name:user.name,email:user.email,role:user.role}});
});

app.get("/api/dashboard", auth, (req,res) => {
  const db=loadDB();
  res.json({
    clients: db.clients.length,
    dossiers: db.dossiers.length,
    dossiersOuverts: db.dossiers.filter(d=>d.status!=="Terminé").length
  });
});
app.get("/api/clients", auth, admin, (req,res)=>res.json(loadDB().clients));
app.post("/api/clients", auth, admin, (req,res)=>{
  const {name,email,phone}=req.body||{};
  if(!name || !email) return res.status(400).json({error:"Nom et e-mail obligatoires"});
  const db=loadDB(); const id="c-"+Date.now();
  db.clients.push({id,name,email,phone:phone||"",createdAt:new Date().toISOString()});
  saveDB(db); res.status(201).json({id,name,email,phone:phone||""});
});
app.get("/api/dossiers", auth, (req,res)=>{
  const db=loadDB();
  if(req.user.role==="admin") return res.json(db.dossiers);
  res.json(db.dossiers.filter(d=>d.clientEmail===req.user.email));
});
app.post("/api/dossiers", auth, admin, (req,res)=>{
  const {title,clientEmail,status,notes}=req.body||{};
  if(!title || !clientEmail) return res.status(400).json({error:"Titre et cliente obligatoires"});
  const db=loadDB();
  const d={id:"d-"+Date.now(),title,clientEmail,status:status||"Nouveau",notes:notes||"",createdAt:new Date().toISOString()};
  db.dossiers.push(d); saveDB(db); res.status(201).json(d);
});

ensureOwner().then(()=>app.listen(PORT,()=>console.log(`Ma Conciergerie lancée sur le port ${PORT}`)));
