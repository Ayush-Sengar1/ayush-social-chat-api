require('dotenv').config();
const express=require('express');
const http=require('http');
const cors=require('cors');
const jwt=require('jsonwebtoken');
const bcrypt=require('bcryptjs');
const {Server}=require('socket.io');

const app=express();
const server=http.createServer(app);
const allowedOrigins=(process.env.CLIENT_URL||process.env.CLIENT_ORIGIN||'http://localhost:5173').split(',').map(value=>value.trim()).filter(Boolean);
const corsOptions={origin:(origin,callback)=>{if(!origin||allowedOrigins.includes('*')||allowedOrigins.includes(origin))return callback(null,true);return callback(new Error('Origin is not allowed'));},credentials:true};
const io=new Server(server,{cors:corsOptions});
const PORT=Number(process.env.PORT||4000);
const HOST=process.env.HOST||'0.0.0.0';
const SECRET=process.env.JWT_SECRET||'dev-only-secret';
const users=new Map();
const messages=[];

app.disable('x-powered-by');
app.use(cors(corsOptions));
app.use(express.json({limit:'100kb'}));
app.get('/health',(req,res)=>res.json({ok:true,service:'social-chat-api'}));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'social-chat-api'}));

const safeUser=user=>({id:user.id,name:user.name,email:user.email});
const sign=user=>jwt.sign({id:user.id,name:user.name},SECRET,{expiresIn:'7d'});
const auth=(req,res,next)=>{try{const raw=String(req.headers.authorization||'');const token=raw.startsWith('Bearer ')?raw.slice(7):'';req.user=jwt.verify(token,SECRET);next()}catch{res.status(401).json({error:'Please log in'})}};

app.post('/api/auth/register',async(req,res)=>{const name=String(req.body.name||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(name.length<2||!email.includes('@')||password.length<6)return res.status(400).json({error:'Enter a name, valid email, and a 6+ character password'});if(users.has(email))return res.status(409).json({error:'Account already exists'});const user={id:Date.now().toString(),name,email,hash:await bcrypt.hash(password,12)};users.set(email,user);return res.status(201).json({token:sign(user),user:safeUser(user)})});
app.post('/api/auth/login',async(req,res)=>{const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||''),user=users.get(email);if(!user||!(await bcrypt.compare(password,user.hash)))return res.status(401).json({error:'Invalid email or password'});return res.json({token:sign(user),user:safeUser(user)})});
app.get('/api/messages',auth,(req,res)=>res.json(messages));

io.use((socket,next)=>{try{const token=String(socket.handshake.auth?.token||'');socket.user=jwt.verify(token,SECRET);next()}catch{next(new Error('Unauthorized'))}});
io.on('connection',socket=>{socket.on('message:send',text=>{const value=String(text||'').trim();if(!value||value.length>1000)return;const message={id:Date.now().toString(),userId:socket.user.id,name:socket.user.name,text:value,createdAt:new Date().toISOString()};messages.push(message);io.emit('message:new',message)})});

server.listen(PORT,HOST,()=>console.log(`Social chat server listening on ${HOST}:${PORT}`));
