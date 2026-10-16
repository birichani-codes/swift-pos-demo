import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const app=express();
app.use(express.json({limit:'1mb'}));
app.use(cors({origin:process.env.CORS_ORIGIN?process.env.CORS_ORIGIN.split(',').map(x=>x.trim()):true}));
const dir=path.dirname(fileURLToPath(import.meta.url));
const file=path.join(dir,'data','demo.json');
const seed={products:[
{id:'p1',sku:'SKU-001',barcode:'6161100123456',name:'Fresh Milk 500ml',category:'Dairy',price:75,cost:54,stock:64,reorder:15,unit:'pcs',icon:'🥛'},
{id:'p2',sku:'SKU-002',barcode:'6161100123457',name:'White Bread 400g',category:'Bakery',price:70,cost:48,stock:32,reorder:12,unit:'pcs',icon:'🍞'},
{id:'p3',sku:'SKU-003',barcode:'6161100123458',name:'Rice Premium 2kg',category:'Groceries',price:420,cost:340,stock:85,reorder:20,unit:'bags',icon:'🍚'},
{id:'p4',sku:'SKU-004',barcode:'6161100123459',name:'Sugar 1kg',category:'Groceries',price:180,cost:145,stock:56,reorder:15,unit:'bags',icon:'🛍️'},
{id:'p5',sku:'SKU-005',barcode:'6161100123460',name:'Cooking Oil 1L',category:'Groceries',price:325,cost:270,stock:11,reorder:15,unit:'bottles',icon:'🫗'},
{id:'p6',sku:'SKU-006',barcode:'6161100123461',name:'Mineral Water 500ml',category:'Beverages',price:50,cost:28,stock:120,reorder:24,unit:'bottles',icon:'💧'},
{id:'p7',sku:'SKU-007',barcode:'6161100123462',name:'Black Tea 250g',category:'Beverages',price:210,cost:160,stock:8,reorder:12,unit:'packs',icon:'🍵'},
{id:'p8',sku:'SKU-008',barcode:'6161100123463',name:'Laundry Soap 800g',category:'Household',price:155,cost:112,stock:43,reorder:15,unit:'bars',icon:'🧼'}
],sales:[],movements:[],shifts:[],settings:{store:'Swift POS Mart',branch:'Main Branch',currency:'KES',receiptFooter:'Thank you for shopping with us!'}};
function read(){if(!fs.existsSync(file)){fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,JSON.stringify(seed,null,2));}return JSON.parse(fs.readFileSync(file,'utf8'));}
function write(data){fs.writeFileSync(file,JSON.stringify(data,null,2));}
const bad=(res,msg,code=400)=>res.status(code).json({error:msg});
const validMoney=n=>Number.isSafeInteger(n)&&n>=0&&n<=1000000000;

// Development authentication. Session state is intentionally in-memory and not production durable.
const sessionTokens=new Map();
const roleCapabilities={admin:['state','products','stock','sales','shifts','staff','reset'],manager:['state','products','stock','sales','shifts'],cashier:['state','sales','shifts'],storekeeper:['state','products','stock'],accountant:['state']};
const hashPassword=password=>{const salt=crypto.randomBytes(16).toString('hex');return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`};
const matchesPassword=(pass,hash)=>{try{const [salt,value]=hash.split(':');const actual=crypto.scryptSync(pass,salt,64);return crypto.timingSafeEqual(actual,Buffer.from(value,'hex'))}catch{return false}};
function ensureAdmin(){const d=read();d.staff ||= [];if(d.staff.length===0){
 const password=process.env.SWIFT_ADMIN_PASSWORD;
 if(!password||password.length<12)throw Error('Set SWIFT_ADMIN_PASSWORD to a unique password of at least 12 characters before running the server');
 d.staff.push({id:crypto.randomUUID(),username:'admin',displayName:'Administrator',role:'admin',passwordHash:hashPassword(password),active:true});write(d);
}return d;}
function safeStaff(u){return {id:u.id,username:u.username,displayName:u.displayName,role:u.role,active:u.active}};
app.post('/api/auth/login',(req,res)=>{const {username,password}=req.body||{};const u=(read().staff||[]).find(x=>x.username===String(username||'').trim().toLowerCase()&&x.active);if(!u||!matchesPassword(String(password||''),u.passwordHash))return bad(res,'Invalid credentials',401);const token=crypto.randomBytes(32).toString('hex');sessionTokens.set(token,{id:u.id,expires:Date.now()+8*60*60*1000});res.json({token,user:safeStaff(u)});});
// One-click identities are restricted to explicit local demo mode. Never enable this on the public API.
const demoAccess=process.env.SWIFT_DEMO_QUICK_LOGIN==='true' && process.env.NODE_ENV!=='production' && process.env.RENDER!=='true';
const demoRoles=['admin','manager','cashier','storekeeper','accountant'];
app.get('/api/auth/demo-roles',(_req,res)=>res.json({enabled:demoAccess,roles:demoAccess?demoRoles:[]}));
app.post('/api/auth/demo-login',(req,res)=>{if(!demoAccess)return bad(res,'Demo access is disabled',403);const role=String(req.body?.role||'');if(!demoRoles.includes(role))return bad(res,'Invalid demo role');const d=read();d.staff||=[];const username='demo_'+role;let u=d.staff.find(x=>x.username===username);if(!u){u={id:crypto.randomUUID(),username,displayName:'Demo '+role[0].toUpperCase()+role.slice(1),role,active:true,passwordHash:hashPassword(crypto.randomBytes(24).toString('hex'))};d.staff.push(u);write(d);}const token=crypto.randomBytes(32).toString('hex');sessionTokens.set(token,{id:u.id,expires:Date.now()+2*60*60*1000});res.json({token,user:safeStaff(u)});});
app.post('/api/auth/logout',(req,res)=>{const token=(req.headers.authorization||'').replace(/^Bearer /i,'');sessionTokens.delete(token);res.json({ok:true})});
app.use('/api',(req,res,next)=>{
 if(req.path==='/health'||req.path==='/auth/login'||req.path==='/auth/logout'||req.path==='/auth/demo-roles'||req.path==='/auth/demo-login')return next();
 const token=(req.headers.authorization||'').replace(/^Bearer /i,'');const session=sessionTokens.get(token);
 if(!session||session.expires<Date.now())return bad(res,'Login required',401);
 const user=(read().staff||[]).find(u=>u.id===session.id&&u.active);if(!user)return bad(res,'Account inactive',403);
 req.staff=user;
 const capability=req.path.startsWith('/products')?'products':req.path.startsWith('/stock')?'stock':req.path.startsWith('/sales')?'sales':req.path.startsWith('/shifts')?'shifts':req.path.startsWith('/staff')?'staff':req.path==='/reset'?'reset':'state';
 if(!roleCapabilities[user.role]?.includes(capability))return bad(res,'Insufficient permissions',403);
 if(user.role==='cashier'&&req.path==='/shifts/close')return bad(res,'Manager approval required to close shifts',403);
 next();
});
app.get('/api/staff',(_req,res)=>res.json((read().staff||[]).map(safeStaff)));
app.post('/api/staff',(req,res)=>{const d=read();const username=String(req.body?.username||'').trim().toLowerCase();const displayName=String(req.body?.displayName||'').trim();const password=String(req.body?.password||'');const role=String(req.body?.role||'');if(!/^[a-z0-9._-]{3,32}$/.test(username)||!displayName||!roleCapabilities[role]||password.length<12)return bad(res,'Enter a valid username, name, role and password (12+ characters)');if(d.staff.some(x=>x.username===username))return bad(res,'Username already exists',409);const u={id:crypto.randomUUID(),username,displayName:displayName.slice(0,80),passwordHash:hashPassword(password),role,active:true};d.staff.push(u);write(d);res.status(201).json(safeStaff(u))});
app.get('/',(_req,res)=>res.json({name:'Swift POS API',mode:'DEMO',status:'online'}));
app.get('/api/health',(_req,res)=>res.json({ok:true,mode:'DEMO',payments:'simulated',storage:'local-json'}));
app.get('/api/state',(req,res)=>{const d=read();if(req.staff.role==='cashier'){d.products=d.products.map(({cost,...p})=>p);d.sales=d.sales.map(s=>({...s,items:s.items.map(({cost,...i})=>i)}));d.movements=[];}res.json({...d,staff:undefined,mode:'DEMO',currentUser:safeStaff(req.staff)});});
app.post('/api/products',(req,res)=>{const {name,sku,barcode,category,price,cost,stock,reorder,unit}=req.body;const d=read();if(!String(name||'').trim())return bad(res,'Product name is required');if(!String(sku||'').trim())return bad(res,'SKU is required');if(d.products.some(p=>p.sku.toLowerCase()===String(sku).trim().toLowerCase()))return bad(res,'SKU already exists');if(!validMoney(price)||!validMoney(cost)||!validMoney(stock)||!validMoney(reorder))return bad(res,'Enter valid nonnegative whole numbers');const p={id:crypto.randomUUID(),name:String(name).trim().slice(0,100),sku:String(sku).trim().slice(0,40),barcode:String(barcode||'').trim().slice(0,60),category:String(category||'Other').slice(0,60),price,cost,stock,reorder,unit:String(unit||'pcs').slice(0,20),icon:'📦'};d.products.push(p);if(stock)d.movements.unshift({id:crypto.randomUUID(),productId:p.id,product:p.name,quantity:stock,type:'opening',note:'Opening stock',date:new Date().toISOString()});write(d);res.status(201).json(p);});
// v0.2: bulk product import. Preview is client-side; the API validates again and writes atomically.
app.post('/api/products/import',(req,res)=>{
 const rows=req.body?.products;
 if(!Array.isArray(rows)||rows.length===0||rows.length>500)return bad(res,'Submit 1 to 500 products per batch');
 const d=read(),existing=new Set(d.products.map(p=>p.sku.toLowerCase()));
 const seen=new Set(),barcodes=new Set(d.products.map(p=>p.barcode).filter(Boolean));
 const failures=[],prepared=[];
 rows.forEach((r,i)=>{
  const name=String(r?.name??'').trim(),sku=String(r?.sku??'').trim(),barcode=String(r?.barcode??'').trim();
  const category=String(r?.category??'Other').trim()||'Other',unit=String(r?.unit??'pcs').trim()||'pcs';
  const numeric=['price','cost','stock','reorder'].map(k=>Number(r?.[k]));
  const why=[];
  if(!name||name.length>100)why.push('Invalid name');
  if(!sku||sku.length>40)why.push('Invalid SKU');
  if(existing.has(sku.toLowerCase())||seen.has(sku.toLowerCase()))why.push('Duplicate SKU');
  if(barcode.length>60||(barcode&&barcodes.has(barcode)))why.push('Duplicate or invalid barcode');
  if(category.length>60||unit.length>20)why.push('Category or unit too long');
  if(numeric.some(n=>!validMoney(n)))why.push('Invalid price, cost, stock or reorder value');
  if(why.length){failures.push({row:i+2,errors:why});return;}
  seen.add(sku.toLowerCase());if(barcode)barcodes.add(barcode);
  prepared.push({id:crypto.randomUUID(),name,sku,barcode,category,unit,price:numeric[0],cost:numeric[1],stock:numeric[2],reorder:numeric[3],icon:'📦'});
 });
 if(failures.length)return res.status(422).json({error:'Import validation failed; no products imported',failures});
 const date=new Date().toISOString();
 for(const product of prepared){d.products.push(product);if(product.stock)d.movements.unshift({id:crypto.randomUUID(),productId:product.id,product:product.name,quantity:product.stock,type:'opening',note:'CSV bulk import',date});}
 write(d);res.status(201).json({imported:prepared.length});
});
app.post('/api/stock/adjust',(req,res)=>{const {productId,quantity,note}=req.body;const d=read();const p=d.products.find(x=>x.id===productId);if(!p)return bad(res,'Product not found',404);if(!Number.isSafeInteger(quantity)||quantity===0||Math.abs(quantity)>1000000)return bad(res,'Quantity must be a nonzero whole number');if(p.stock+quantity<0)return bad(res,'Insufficient stock');p.stock+=quantity;d.movements.unshift({id:crypto.randomUUID(),productId:p.id,product:p.name,quantity,type:'adjustment',note:String(note||'Manual adjustment').slice(0,150),date:new Date().toISOString()});write(d);res.json(p);});
app.post('/api/sales',(req,res)=>{
 const {items,paymentMethod='cash',amountTendered,discount=0,payments,requestId}=req.body||{};
 if(!Array.isArray(items)||!items.length||items.length>100)return bad(res,'A sale must contain products');
 if(!Number.isSafeInteger(discount)||discount<0)return bad(res,'Invalid discount');
 const d=read();d.shifts||=[];d.sales||=[];d.movements||=[];
 if(requestId&&d.sales.some(x=>x.requestId===requestId))return res.json(d.sales.find(x=>x.requestId===requestId));
 const shift=d.shifts.find(s=>s.status==='open'&&s.cashierId===req.staff.id);
 if(!shift)return bad(res,'Open your own cashier shift before checkout',409);
 const consolidated=new Map();for(const item of items){if(!Number.isSafeInteger(item.qty)||item.qty<1||item.qty>10000)return bad(res,'Invalid quantity');consolidated.set(item.productId,(consolidated.get(item.productId)||0)+item.qty)}
 const saleItems=[];for(const [id,qty] of consolidated){const p=d.products.find(x=>x.id===id);if(!p)return bad(res,'Unknown product');if(p.stock<qty)return bad(res,`Insufficient stock: ${p.name}`);saleItems.push({productId:id,name:p.name,sku:p.sku,qty,price:p.price,cost:p.cost,lineTotal:p.price*qty})}
 const subtotal=saleItems.reduce((n,x)=>n+x.lineTotal,0);if(discount>subtotal)return bad(res,'Discount exceeds subtotal');if(discount>0&&!['admin','manager'].includes(req.staff.role))return bad(res,'Manager role required for discount',403);
 const total=subtotal-discount;const allocations=Array.isArray(payments)?payments:[{method:paymentMethod,amount:paymentMethod==='cash'?amountTendered:total}];
 if(!allocations.length||allocations.length>3||allocations.some(x=>!['cash','mpesa','card'].includes(x.method)||!validMoney(x.amount)))return bad(res,'Invalid payment allocations');
 const cash=allocations.filter(x=>x.method==='cash').reduce((n,x)=>n+x.amount,0);const noncash=allocations.filter(x=>x.method!=='cash').reduce((n,x)=>n+x.amount,0);
 if(noncash>total||cash+noncash<total)return bad(res,'Payments do not cover the total');if(cash+noncash>total&&cash===0)return bad(res,'Only cash tender can create change');
 const now=new Date().toISOString();const sale={id:crypto.randomUUID(),requestId:String(requestId||crypto.randomUUID()),receiptNumber:`SP-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`,date:now,items:saleItems,subtotal,discount,total,payments:allocations,paymentMethod:allocations.length>1?'split':allocations[0].method,paymentStatus:'DEMO_SIMULATED',amountTendered:cash+noncash,change:cash+noncash-total,branch:d.settings.branch,shiftId:shift.id,cashier:shift.cashier,cashierId:req.staff.id,registerId:shift.registerId||'REG-01',refunded:false};
 for(const x of saleItems){d.products.find(p=>p.id===x.productId).stock-=x.qty;d.movements.unshift({id:crypto.randomUUID(),productId:x.productId,product:x.name,quantity:-x.qty,type:'sale',note:sale.receiptNumber,date:now})}d.sales.unshift(sale);write(d);res.status(201).json(sale);
});
app.post('/api/sales/:id/refund',(req,res)=>{if(!['admin','manager'].includes(req.staff.role))return bad(res,'Manager permission required',403);const d=read();const sale=(d.sales||[]).find(x=>x.id===req.params.id);if(!sale)return bad(res,'Sale not found',404);if(sale.refunded)return bad(res,'Sale already refunded',409);const reason=String(req.body?.reason||'').trim();if(reason.length<5)return bad(res,'Give a refund reason (at least 5 characters)');sale.refunded=true;sale.refundedAt=new Date().toISOString();sale.refundReason=reason;sale.refundBy=req.staff.displayName;for(const x of sale.items){const p=d.products.find(p=>p.id===x.productId);if(p){p.stock+=x.qty;d.movements.unshift({id:crypto.randomUUID(),productId:p.id,product:p.name,quantity:x.qty,type:'refund',note:sale.receiptNumber,date:sale.refundedAt})}}write(d);res.json(sale)});
// DEMO cashier shift lifecycle. This is not authentication or production-grade RBAC.
app.post('/api/shifts/open',(req,res)=>{
 const d=read();d.shifts ||= [];
 if(d.shifts.some(s=>s.status==='open'))return bad(res,'Close the current shift before opening another',409);
 const cashier=req.staff.displayName;
 const openingFloat=req.body?.openingFloat;
 if(!cashier||cashier.length>60||!validMoney(openingFloat))return bad(res,'Valid cashier name and opening float are required');
 const shift={id:crypto.randomUUID(),cashier,cashierId:req.staff.id,registerId:'REG-01',cashMovements:[],status:'open',openingFloat,openedAt:new Date().toISOString(),closedAt:null,declaredCash:null,expectedCash:null,variance:null};
 d.shifts.unshift(shift);write(d);res.status(201).json(shift);
});
app.post('/api/shifts/close',(req,res)=>{
 const d=read();d.shifts ||= [];
 const shift=d.shifts.find(s=>s.status==='open');if(!shift)return bad(res,'No open shift',409);
 const declaredCash=req.body?.declaredCash;
 if(!validMoney(declaredCash))return bad(res,'Enter a valid counted cash amount');
 const cashSales=d.sales.filter(s=>s.shiftId===shift.id&&!s.refunded).reduce((a,s)=>a+(s.payments?Math.min(s.total,s.payments.filter(p=>p.method==='cash').reduce((n,p)=>n+p.amount,0)):s.paymentMethod==='cash'?s.total:0),0);
 const cashMovements=(shift.cashMovements||[]).reduce((sum,m)=>sum+(m.type==='pay-in'?m.amount:-m.amount),0);const expectedCash=shift.openingFloat+cashSales+cashMovements;
 Object.assign(shift,{status:'closed',closedAt:new Date().toISOString(),declaredCash,expectedCash,variance:declaredCash-expectedCash,notes:String(req.body?.notes||'').slice(0,300)});
 write(d);res.json(shift);
});
// Demo register cash movements: these change the drawer expectation, not sales revenue.
app.post('/api/shifts/cash-movement',(req,res)=>{
 const d=read();const sh=(d.shifts||[]).find(s=>s.status==='open');
 if(!sh)return bad(res,'Open a shift first',409);
 if(req.staff.role==='cashier'&&sh.cashierId!==req.staff.id)return bad(res,'This register belongs to another cashier',403);
 const {type,amount,reason}=req.body||{};
 if(!['pay-in','pay-out'].includes(type)||!validMoney(amount)||amount===0||!String(reason||'').trim())return bad(res,'Type, positive amount and reason are required');
 const entry={id:crypto.randomUUID(),type,amount,reason:String(reason).trim().slice(0,160),staffId:req.staff.id,staff:req.staff.displayName,date:new Date().toISOString()};
 sh.cashMovements ||= [];sh.cashMovements.push(entry);write(d);res.status(201).json(entry);
});
app.post('/api/sales/:id/print',(req,res)=>{
 const d=read();const sale=d.sales.find(x=>x.id===req.params.id);if(!sale)return bad(res,'Sale not found',404);
 d.printEvents ||= [];const event={id:crypto.randomUUID(),saleId:sale.id,receiptNumber:sale.receiptNumber,staffId:req.staff.id,staff:req.staff.displayName,date:new Date().toISOString(),kind:'browser-print-request'};
 d.printEvents.unshift(event);write(d);res.status(201).json(event);
});
app.post('/api/reset',(_req,res)=>{const d=read();const restored={...seed,staff:d.staff};write(restored);res.json({ok:true});});
ensureAdmin();
app.listen(process.env.PORT||4000,'0.0.0.0',()=>console.log(`Swift POS DEMO API running on port ${process.env.PORT||4000}`));
