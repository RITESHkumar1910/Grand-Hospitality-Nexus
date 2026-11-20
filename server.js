const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { Server } = require('socket.io');

const app = express();
app.set('trust proxy', 1); // Render runs behind a proxy, needed for correct req.ip
const server = http.createServer(app);
const io = new Server(server);

const isProd = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (isProd ? null : 'dev_secret_change_me');
const MONGO = process.env.MONGO_URI || (isProd ? null : 'mongodb://127.0.0.1:27017/ghn');
const PORT = process.env.PORT || 5000;
const VERSION = 3;
if (!SECRET || !MONGO) {
  console.error('JWT_SECRET and MONGO_URI must be set in production');
  process.exit(1);
}
if (!process.env.JWT_SECRET) console.warn('Warning: JWT_SECRET missing, using dev default.');

process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));

app.disable('x-powered-by');
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
app.use(cors());
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------------- HELPERS ---------------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg, status = 400) => { throw new HttpError(status, msg); };
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const isId = (id) => mongoose.isValidObjectId(id);
const DAY = 86400000;
const todayUTC = () => { const d = new Date(); return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())); };
const parseDate = (s) => { const d = new Date(s); return s && !isNaN(d) ? d : null; };
const nightsBetween = (a, b) => Math.max(1, Math.round((b - a) / DAY));
const billOf = (b) => {
  const room = b.roomTotal || 0, food = b.folio || 0;
  return { nights: b.nights || 0, roomCharges: room, foodCharges: food, total: room + food };
};

const hits = new Map();
const limiter = (max, windowMs) => (req, res, next) => {
  const key = req.ip + req.path, now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  if (arr.length > max) return res.status(429).json({ error: 'Too many attempts. Please try again in a few minutes.' });
  next();
};

/* ---------------- MODELS ---------------- */
const { ObjectId } = mongoose.Schema.Types;
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['guest', 'chef', 'admin'], default: 'guest' }
}));
const Room = mongoose.model('Room', new mongoose.Schema({
  number: { type: String, required: true, unique: true },
  type: String,
  price: { type: Number, min: 0 }
}));
const bookingSchema = new mongoose.Schema({
  user: { type: ObjectId, ref: 'User', required: true },
  room: { type: ObjectId, ref: 'Room', required: true },
  checkIn: { type: Date, required: true },
  checkOut: { type: Date, required: true },
  nights: Number,
  roomTotal: { type: Number, default: 0 },
  status: { type: String, enum: ['booked', 'checked-in', 'checked-out', 'cancelled'], default: 'booked' },
  folio: { type: Number, default: 0 }
}, { timestamps: true });
bookingSchema.index({ room: 1, checkIn: 1, checkOut: 1 });
const Booking = mongoose.model('Booking', bookingSchema);
const MenuItem = mongoose.model('MenuItem', new mongoose.Schema({
  name: { type: String, required: true },
  category: String,
  price: { type: Number, min: 0 },
  veg: Boolean,
  inStock: { type: Boolean, default: true }
}));
const orderSchema = new mongoose.Schema({
  user: { type: ObjectId, ref: 'User' },
  booking: { type: ObjectId, ref: 'Booking' },
  roomNumber: String,
  items: [{ name: String, price: Number, qty: Number }],
  total: Number,
  payment: { type: String, enum: ['room', 'online'] },
  paid: { type: Boolean, default: false },
  status: { type: String, enum: ['placed', 'cooking', 'ready', 'delivered'], default: 'placed' }
}, { timestamps: true });
orderSchema.index({ status: 1, createdAt: 1 });
const Order = mongoose.model('Order', orderSchema);
async function withFood(list) {
  const rows = await Order.aggregate([
    { $match: { booking: { $in: list.map((b) => b._id) }, payment: 'room' } },
    { $group: { _id: '$booking', sum: { $sum: '$total' } } }
  ]);
  const sums = new Map(rows.map((r) => [String(r._id), r.sum]));
  return list.map((b) => ({ ...b, folio: sums.get(String(b._id)) || 0 }));
}
const Setting = mongoose.model('Setting', new mongoose.Schema({ key: { type: String, unique: true } }));

/* ---------------- AUTH ---------------- */
const auth = (...roles) => (req, res, next) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Please sign in first' });
  try { req.user = jwt.verify(token, SECRET); }
  catch (e) { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
  if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'You are not allowed to do this' });
  next();
};
const makeToken = (u) => jwt.sign({ id: String(u._id), name: u.name, role: u.role }, SECRET, { expiresIn: '1d' });
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

app.post('/api/register', limiter(10, 10 * 60000), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2) bad('Please enter your full name');
  if (!emailOk(email)) bad('Please enter a valid email address');
  if (password.length < 6) bad('Password must be at least 6 characters');
  if (await User.findOne({ email })) bad('This email is already registered', 409);
  const u = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
  res.json({ token: makeToken(u), name: u.name, role: u.role });
}));

app.post('/api/login', limiter(15, 10 * 60000), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = await User.findOne({ email });
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password))) bad('Wrong email or password');
  res.json({ token: makeToken(u), name: u.name, role: u.role });
}));

/* ---------------- ROOMS & BOOKINGS ---------------- */
const ACTIVE = { $nin: ['checked-out', 'cancelled'] };

app.get('/api/rooms', wrap(async (req, res) => {
  const rooms = await Room.find().sort('number').lean();
  const { checkIn, checkOut } = req.query;
  if (!checkIn || !checkOut) return res.json(rooms);
  const a = parseDate(checkIn), b = parseDate(checkOut);
  if (!a || !b || a >= b) bad('Please select valid dates');
  const busy = (await Booking.find({ status: ACTIVE, checkIn: { $lt: b }, checkOut: { $gt: a } }).distinct('room')).map(String);
  res.json(rooms.filter((r) => !busy.includes(String(r._id))));
}));

app.post('/api/bookings', auth('guest'), wrap(async (req, res) => {
  const { roomId } = req.body;
  const a = parseDate(req.body.checkIn), b = parseDate(req.body.checkOut);
  if (!isId(roomId)) bad('Invalid room');
  if (!a || !b) bad('Please select valid dates');
  if (a < todayUTC()) bad('Check-in date cannot be in the past');
  if (a >= b) bad('Check-out must be after check-in');
  const nights = nightsBetween(a, b);
  if (nights > 30) bad('Maximum stay is 30 nights');
  const room = await Room.findById(roomId);
  if (!room) bad('Room not found', 404);
  const clash = await Booking.findOne({ room: room._id, status: ACTIVE, checkIn: { $lt: b }, checkOut: { $gt: a } });
  if (clash) bad('This room is already booked for the selected dates', 409);
  const booking = await Booking.create({
    user: req.user.id, room: room._id, checkIn: a, checkOut: b, nights, roomTotal: nights * room.price
  });
  res.json({ booking, bill: billOf(booking) });
}));

app.get('/api/bookings/my', auth('guest'), wrap(async (req, res) => {
  const list = await withFood(await Booking.find({ user: req.user.id }).populate('room').sort('-createdAt').lean());
  res.json(list.map((b) => ({ ...b, bill: billOf(b) })));
}));

app.get('/api/bookings', auth('admin'), wrap(async (req, res) => {
  res.json(await withFood(await Booking.find().populate('room').populate('user', 'name email').sort('-createdAt').limit(200).lean()));
}));

app.patch('/api/bookings/:id/:action', auth(), wrap(async (req, res) => {
  const { id, action } = req.params;
  if (!isId(id)) bad('Invalid booking');
  const b = await Booking.findById(id).populate('room');
  if (!b) bad('Booking not found', 404);
  const admin = req.user.role === 'admin';

  if (action === 'cancel') {
    if (!admin && String(b.user) !== req.user.id) bad('You are not allowed to do this', 403);
    if (b.status !== 'booked') bad('Only upcoming bookings can be cancelled');
    b.status = 'cancelled';
  } else if (action === 'checkin') {
    if (!admin) bad('You are not allowed to do this', 403);
    if (b.status !== 'booked') bad('This booking is not waiting for check-in');
    if (await Booking.findOne({ room: b.room._id, status: 'checked-in' })) bad('This room is currently occupied');
    b.status = 'checked-in';
  } else if (action === 'checkout') {
    if (!admin) bad('You are not allowed to do this', 403);
    if (b.status !== 'checked-in') bad('This guest is not checked in');
    const pending = await Order.countDocuments({ booking: b._id, status: { $ne: 'delivered' } });
    if (pending) bad(`Cannot check out: ${pending} food order(s) not delivered yet`);
    b.status = 'checked-out';
  } else bad('Unknown action');

  const [fb] = await withFood([b.toObject()]);
  b.folio = fb.folio;
  await b.save();
  io.emit('orders:changed');
  res.json({ booking: b, bill: billOf(fb) });
}));

/* ---------------- MENU ---------------- */
app.get('/api/menu', wrap(async (req, res) => res.json(await MenuItem.find().lean())));

app.patch('/api/menu/:id/stock', auth('chef', 'admin'), wrap(async (req, res) => {
  if (!isId(req.params.id)) bad('Invalid item');
  const item = await MenuItem.findById(req.params.id);
  if (!item) bad('Item not found', 404);
  item.inStock = !item.inStock;
  await item.save();
  io.emit('menu:changed');
  res.json(item);
}));

const dishFields = (b) => {
  const name = String(b.name || '').trim(), category = String(b.category || '').trim(), price = Number(b.price);
  if (name.length < 2 || name.length > 60) bad('Dish name must be 2 to 60 characters');
  if (!category || category.length > 30) bad('Please enter a category');
  if (!(price > 0 && price <= 10000)) bad('Please enter a valid price');
  return { name, category, price, veg: b.veg !== false && b.veg !== 'false' };
};
app.post('/api/menu', auth('chef', 'admin'), wrap(async (req, res) => {
  const d = await MenuItem.create(dishFields(req.body));
  io.emit('menu:changed'); res.json(d);
}));
app.put('/api/menu/:id', auth('chef', 'admin'), wrap(async (req, res) => {
  if (!isId(req.params.id)) bad('Invalid item');
  const d = await MenuItem.findByIdAndUpdate(req.params.id, dishFields(req.body), { new: true });
  if (!d) bad('Item not found', 404);
  io.emit('menu:changed'); res.json(d);
}));
app.delete('/api/menu/:id', auth('chef', 'admin'), wrap(async (req, res) => {
  if (!isId(req.params.id)) bad('Invalid item');
  await MenuItem.deleteOne({ _id: req.params.id });
  io.emit('menu:changed'); res.json({ ok: true });
}));

/* ---------------- ORDERS ---------------- */
app.post('/api/orders', auth('guest'), wrap(async (req, res) => {
  const { items, payment } = req.body;
  if (!['room', 'online'].includes(payment)) bad('Please choose a payment method');
  if (!Array.isArray(items) || !items.length) bad('Your cart is empty');
  if (items.length > 30) bad('Too many items in one order');

  const qtyById = new Map();
  for (const it of items) {
    const qty = parseInt(it.qty, 10);
    if (!isId(it.id) || !(qty >= 1 && qty <= 20)) bad('Invalid item in cart');
    qtyById.set(String(it.id), (qtyById.get(String(it.id)) || 0) + qty);
  }

  const booking = await Booking.findOne({ user: req.user.id, status: 'checked-in' }).populate('room');
  if (!booking) bad('You can order after the front desk checks you in');

  const dishes = await MenuItem.find({ _id: { $in: [...qtyById.keys()] } });
  if (dishes.length !== qtyById.size) bad('Some items are no longer on the menu');
  const lines = []; let total = 0;
  for (const d of dishes) {
    if (!d.inStock) bad(`${d.name} is sold out`);
    const qty = qtyById.get(String(d._id));
    lines.push({ name: d.name, price: d.price, qty });
    total += d.price * qty; // price always comes from the database
  }

  const order = await Order.create({
    user: req.user.id, booking: booking._id, roomNumber: booking.room.number,
    items: lines, total, payment, paid: payment === 'online'
  });
  const [fb] = await withFood([booking.toObject()]);
  await Booking.updateOne({ _id: booking._id }, { folio: fb.folio });
  io.emit('orders:changed');
  res.json({ ...order.toObject(), folio: fb.folio });
}));

app.get('/api/orders/my', auth('guest'), wrap(async (req, res) => {
  res.json(await Order.find({ user: req.user.id }).sort('-createdAt').limit(30).lean());
}));

app.get('/api/orders', auth('chef', 'admin'), wrap(async (req, res) => {
  res.json(await Order.find({ status: { $ne: 'delivered' } }).sort('createdAt').limit(100).lean());
}));

app.get('/api/orders/history', auth('chef', 'admin'), wrap(async (req, res) => {
  res.json(await Order.find({ status: 'delivered' }).sort('-updatedAt').limit(15).lean());
}));

const FLOW = { placed: 'cooking', cooking: 'ready', ready: 'delivered' };
app.patch('/api/orders/:id/status', auth('chef', 'admin'), wrap(async (req, res) => {
  if (!isId(req.params.id)) bad('Invalid order');
  const o = await Order.findById(req.params.id);
  if (!o) bad('Order not found', 404);
  if (FLOW[o.status] !== req.body.status) bad(`Order cannot move from ${o.status} to ${req.body.status}`);
  o.status = req.body.status;
  await o.save();
  io.emit('orders:changed');
  res.json(o);
}));

/* ---------------- MISC ---------------- */
app.get('/api/health', (req, res) => res.json({ ok: true, db: mongoose.connection.readyState === 1, version: VERSION }));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request data' });
  if (err.name === 'CastError' || err.name === 'ValidationError') return res.status(400).json({ error: 'Invalid data' });
  if (err.code === 11000) return res.status(409).json({ error: 'Already exists' });
  console.error(err);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

io.on('connection', (socket) => console.log('Live client connected:', socket.id));

/* ---------------- SEED ---------------- */
async function seed() {
  if (!(await Room.countDocuments())) {
    await Room.insertMany([
      { number: '101', type: 'Standard', price: 2500 }, { number: '102', type: 'Standard', price: 2500 },
      { number: '201', type: 'Deluxe', price: 4000 }, { number: '202', type: 'Deluxe', price: 4000 },
      { number: '301', type: 'Suite', price: 7500 }
    ]);
  }
  if (!(await MenuItem.countDocuments())) {
    await MenuItem.insertMany([
      { name: 'Masala Dosa', category: 'Breakfast', price: 120, veg: true },
      { name: 'Paneer Sandwich', category: 'Snacks', price: 150, veg: true },
      { name: 'Chicken Biryani', category: 'Main Course', price: 280, veg: false },
      { name: 'Dal Tadka + Rice', category: 'Main Course', price: 180, veg: true },
      { name: 'Cold Coffee', category: 'Beverages', price: 90, veg: true },
      { name: 'Brownie', category: 'Dessert', price: 110, veg: true }
    ]);
  }
  if (!(await User.countDocuments({ role: { $in: ['admin', 'chef'] } }))) {
    const staffPass = process.env.ADMIN_PASSWORD || (isProd ? null : 'admin123');
    if (!staffPass) {
      console.warn('ADMIN_PASSWORD not set, staff accounts skipped');
      return;
    }
    const hash = await bcrypt.hash(staffPass, 10);
    await User.insertMany([
      { name: 'Admin', email: 'admin@ghn.com', password: hash, role: 'admin' },
      { name: 'Chef', email: 'chef@ghn.com', password: hash, role: 'chef' }
    ]);
    console.log('Staff accounts created: admin@ghn.com and chef@ghn.com');
  }
}

async function seedV2() {
  if (await Setting.findOne({ key: 'seed_v2' })) return;
  const rooms = [['101','Standard',2500],['102','Standard',2500],['103','Economy',1800],['104','Economy',1800],
    ['201','Deluxe',4000],['202','Deluxe',4000],['203','Family Room',5200],['204','Family Room',5200],
    ['301','Executive Suite',7500],['302','Executive Suite',8500],['401','Presidential Suite',12000],['501','Penthouse',18000]];
  await Room.bulkWrite(rooms.map((r) => ({ updateOne: { filter: { number: r[0] }, update: { $set: { type: r[1], price: r[2] } }, upsert: true } })));
  const dishes = [['Idli Sambar','Breakfast',90,true],['Aloo Paratha','Breakfast',110,true],['Veg Club Sandwich','Snacks',160,true],
    ['French Fries','Snacks',120,true],['Chicken Wings','Snacks',240,false],['Paneer Butter Masala','Main Course',260,true],
    ['Butter Chicken','Main Course',320,false],['Veg Fried Rice','Main Course',190,true],['Margherita Pizza','Main Course',280,true],
    ['Fresh Lime Soda','Beverages',70,true],['Masala Chai','Beverages',50,true],['Mango Shake','Beverages',120,true],
    ['Gulab Jamun','Dessert',90,true],['Ice Cream Sundae','Dessert',140,true]];
  await MenuItem.bulkWrite(dishes.map((d) => ({ updateOne: { filter: { name: d[0] }, update: { $setOnInsert: { category: d[1], price: d[2], veg: d[3], inStock: true } }, upsert: true } })));
  await Setting.create({ key: 'seed_v2' });
  console.log('Added more room categories and menu items');
}

/* ---------------- START ---------------- */
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') console.error(`Port ${PORT} is already in use. Close the other server or change PORT in .env`);
  else console.error(e);
  process.exit(1);
});

mongoose.connect(MONGO, { serverSelectionTimeoutMS: 10000 }).then(async () => {
  console.log('MongoDB connected');
  await seed();
  await seedV2();
  server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch((e) => {
  console.error('Database connection failed:', e.message);
  console.error('Check MONGO_URI in .env and (for Atlas) Network Access > Allow access from anywhere.');
  process.exit(1);
});
