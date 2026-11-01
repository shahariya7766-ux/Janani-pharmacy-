const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const dbFile = process.env.DATABASE_FILE || "./data/janani.sqlite";
fs.mkdirSync(path.dirname(path.resolve(dbFile)), { recursive: true });
const db = new Database(dbFile);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('owner','employee')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS medicines (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 generic_name TEXT DEFAULT '',
 category TEXT DEFAULT '',
 batch TEXT NOT NULL,
 expiry TEXT NOT NULL,
 purchase_price REAL NOT NULL DEFAULT 0,
 selling_price REAL NOT NULL DEFAULT 0,
 stock INTEGER NOT NULL DEFAULT 0,
 low_stock INTEGER NOT NULL DEFAULT 5,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL CHECK(kind IN ('purchase','sale','adjustment')),
 medicine_id INTEGER NOT NULL REFERENCES medicines(id),
 quantity INTEGER NOT NULL,
 unit_price REAL NOT NULL,
 total REAL NOT NULL,
 note TEXT DEFAULT '',
 created_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER REFERENCES users(id),
 action TEXT NOT NULL,
 details TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function log(userId, action, details) {
 db.prepare("INSERT INTO activity(user_id,action,details) VALUES(?,?,?)")
   .run(userId || null, action, details);
}
function ensureOwner() {
 const count = db.prepare("SELECT COUNT(*) n FROM users").get().n;
 if (!count && process.env.OWNER_PASSWORD) {
   const hash = bcrypt.hashSync(process.env.OWNER_PASSWORD, 12);
   db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'owner')")
     .run(process.env.OWNER_NAME || "Owner", process.env.OWNER_USERNAME || "owner", hash);
 }
}
ensureOwner();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(session({
 secret: process.env.SESSION_SECRET || "development-only-change-me",
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

function auth(req,res,next) {
 if (!req.session.user) return res.status(401).json({error:"লগইন প্রয়োজন"});
 next();
}
function ownerOnly(req,res,next) {
 if (req.session.user?.role !== "owner") return res.status(403).json({error:"এই কাজটি শুধু Owner করতে পারবেন"});
 next();
}
function userSafe(u) { return {id:u.id,name:u.name,username:u.username,role:u.role}; }

app.post("/api/login", (req,res) => {
 const {username,password} = req.body || {};
 const u = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(String(username||"").trim());
 if (!u || !bcrypt.compareSync(String(password||""), u.password_hash)) return res.status(401).json({error:"ইউজারনেম বা পাসওয়ার্ড সঠিক নয়"});
 req.session.user = userSafe(u);
 log(u.id,"LOGIN","লগইন করেছেন");
 res.json({user:req.session.user});
});
app.post("/api/logout", auth, (req,res) => {
 log(req.session.user.id,"LOGOUT","লগআউট করেছেন");
 req.session.destroy(()=>res.json({ok:true}));
});
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.get("/api/dashboard",auth,(req,res)=>{
 const stock = db.prepare("SELECT COUNT(*) n, COALESCE(SUM(stock),0) units FROM medicines").get();
 const low = db.prepare("SELECT COUNT(*) n FROM medicines WHERE stock<=low_stock").get().n;
 const expired = db.prepare("SELECT COUNT(*) n FROM medicines WHERE expiry < date('now')").get().n;
 const today = db.prepare("SELECT COALESCE(SUM(CASE WHEN kind='sale' THEN total ELSE 0 END),0) sales, COALESCE(SUM(CASE WHEN kind='purchase' THEN total ELSE 0 END),0) purchases FROM transactions WHERE date(created_at)=date('now','localtime')").get();
 res.json({stock,low,expired,today});
});
app.get("/api/medicines",auth,(req,res)=>{
 res.json(db.prepare("SELECT * FROM medicines ORDER BY name,batch").all());
});
app.post("/api/medicines",auth,(req,res)=>{
 const d=req.body||{};
 if(!d.name||!d.batch||!d.expiry) return res.status(400).json({error:"ওষুধের নাম, Batch ও Expiry দিন"});
 const vals=[String(d.name).trim(),String(d.generic_name||""),String(d.category||""),String(d.batch).trim(),String(d.expiry),Number(d.purchase_price),Number(d.selling_price),Number(d.stock),Number(d.low_stock||5)];
 if(vals.some((v,i)=>[5,6,7,8].includes(i)&&(!Number.isFinite(v)||v<0))) return res.status(400).json({error:"দাম ও স্টকের সংখ্যা সঠিক দিন"});
 const info=db.prepare("INSERT INTO medicines(name,generic_name,category,batch,expiry,purchase_price,selling_price,stock,low_stock) VALUES(?,?,?,?,?,?,?,?,?)").run(...vals);
 log(req.session.user.id,"MEDICINE_ADD",`${vals[0]} / Batch ${vals[3]}`);
 res.json({id:info.lastInsertRowid});
});
app.put("/api/medicines/:id",auth,(req,res)=>{
 const d=req.body||{}, id=Number(req.params.id);
 const old=db.prepare("SELECT * FROM medicines WHERE id=?").get(id);
 if(!old) return res.status(404).json({error:"পণ্য পাওয়া যায়নি"});
 const fields=["name","generic_name","category","batch","expiry","purchase_price","selling_price","stock","low_stock"];
 const merged={...old,...d};
 if(!merged.name||!merged.batch||!merged.expiry) return res.status(400).json({error:"নাম, Batch ও Expiry প্রয়োজন"});
 db.prepare(`UPDATE medicines SET name=?,generic_name=?,category=?,batch=?,expiry=?,purchase_price=?,selling_price=?,stock=?,low_stock=? WHERE id=?`)
 .run(merged.name,merged.generic_name||"",merged.category||"",merged.batch,merged.expiry,Number(merged.purchase_price),Number(merged.selling_price),Number(merged.stock),Number(merged.low_stock),id);
 log(req.session.user.id,"MEDICINE_EDIT",`${old.name} আপডেট করেছেন`);
 res.json({ok:true});
});
app.delete("/api/medicines/:id",ownerOnly,(req,res)=>{
 const id=Number(req.params.id);
 const m=db.prepare("SELECT name FROM medicines WHERE id=?").get(id);
 if(!m) return res.status(404).json({error:"পণ্য পাওয়া যায়নি"});
 const tx=db.prepare("SELECT COUNT(*) n FROM transactions WHERE medicine_id=?").get(id).n;
 if(tx) return res.status(400).json({error:"লেনদেনের ইতিহাস আছে, তাই মুছতে পারবেন না"});
 db.prepare("DELETE FROM medicines WHERE id=?").run(id);
 log(req.session.user.id,"MEDICINE_DELETE",`${m.name} মুছে দিয়েছেন`);
 res.json({ok:true});
});

app.post("/api/transactions",auth,(req,res)=>{
 const d=req.body||{}, kind=d.kind, id=Number(d.medicine_id), qty=Number(d.quantity);
 if(!["purchase","sale"].includes(kind)||!Number.isInteger(qty)||qty<1) return res.status(400).json({error:"লেনদেনের তথ্য সঠিক নয়"});
 const m=db.prepare("SELECT * FROM medicines WHERE id=?").get(id);
 if(!m) return res.status(404).json({error:"ওষুধ পাওয়া যায়নি"});
 if(kind==="sale" && m.stock<qty) return res.status(400).json({error:"পর্যাপ্ত স্টক নেই"});
 const price=Number(d.unit_price ?? (kind==="sale"?m.selling_price:m.purchase_price));
 if(!Number.isFinite(price)||price<0) return res.status(400).json({error:"দাম সঠিক নয়"});
 const total=price*qty;
 const update=kind==="sale"?m.stock-qty:m.stock+qty;
 const insert=db.prepare("INSERT INTO transactions(kind,medicine_id,quantity,unit_price,total,note,created_by) VALUES(?,?,?,?,?,?,?)");
 const updateStock=db.prepare("UPDATE medicines SET stock=? WHERE id=?");
 const run=db.transaction(()=>{insert.run(kind,id,qty,price,total,String(d.note||""),req.session.user.id);updateStock.run(update,id);});
 run();
 log(req.session.user.id,kind==="sale"?"SALE":"PURCHASE",`${m.name}: ${qty} × ${price}`);
 res.json({ok:true,total,stock:update});
});
app.get("/api/reports",auth,(req,res)=>{
 const rows=db.prepare(`
 SELECT
 COALESCE(SUM(CASE WHEN kind='sale' THEN total ELSE 0 END),0) sales,
 COALESCE(SUM(CASE WHEN kind='purchase' THEN total ELSE 0 END),0) purchases,
 COALESCE(SUM(CASE WHEN kind='sale' THEN quantity*(unit_price-(SELECT purchase_price FROM medicines WHERE id=medicine_id)) ELSE 0 END),0) estimated_profit
 FROM transactions
 WHERE date(created_at)>=date('now','-30 days')
 `).get();
 const recent=db.prepare(`SELECT t.*,m.name medicine,u.name user_name FROM transactions t JOIN medicines m ON m.id=t.medicine_id LEFT JOIN users u ON u.id=t.created_by ORDER BY t.id DESC LIMIT 100`).all();
 res.json({summary:rows,recent});
});
app.get("/api/activity",auth,(req,res)=>{
 res.json(db.prepare("SELECT a.*,u.name user_name FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 150").all());
});
app.get("/api/users",auth,(req,res)=>{
 res.json(db.prepare("SELECT id,name,username,role,active,created_at FROM users ORDER BY id").all());
});
app.post("/api/users",auth,(req,res)=>{
 const {name,username,password}=req.body||{};
 if(!name||!username||!password||String(password).length<10) return res.status(400).json({error:"নাম, ইউজারনেম ও কমপক্ষে ১০ অক্ষরের পাসওয়ার্ড দিন"});
 try{
  const hash=bcrypt.hashSync(String(password),12);
  const info=db.prepare("INSERT INTO users(name,username,password_hash,role) VALUES(?,?,?,'employee')").run(String(name).trim(),String(username).trim(),hash);
  log(req.session.user.id,"USER_ADD",`${username} কর্মচারী অ্যাকাউন্ট তৈরি`);
  res.json({id:info.lastInsertRowid});
 }catch(e){res.status(400).json({error:"এই ইউজারনেম আগে ব্যবহার হয়েছে"});}
});
app.patch("/api/users/:id/active",ownerOnly,(req,res)=>{
 const id=Number(req.params.id), active=req.body.active?1:0;
 if(id===req.session.user.id && !active) return res.status(400).json({error:"নিজের অ্যাকাউন্ট বন্ধ করা যাবে না"});
 db.prepare("UPDATE users SET active=? WHERE id=? AND role='employee'").run(active,id);
 log(req.session.user.id,"USER_STATUS",`কর্মচারী ${id} ${active?"চালু":"বন্ধ"} করেছেন`);
 res.json({ok:true});
});
app.delete("/api/users/:id",ownerOnly,(req,res)=>{
 const id=Number(req.params.id);
 db.prepare("UPDATE users SET active=0 WHERE id=? AND role='employee'").run(id);
 log(req.session.user.id,"USER_DISABLE",`কর্মচারী ${id} নিষ্ক্রিয় করেছেন`);
 res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`Janani Pharmacy running on port ${PORT}`));
