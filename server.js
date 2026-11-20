require('dotenv').config();
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const MONGO = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ghn';
const { ObjectId } = mongoose.Schema.Types;

/* ---------------- MODELS ---------------- */
const User = mongoose.model('User', new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['guest', 'chef', 'admin'], default: 'guest' }
}));

const Room = mongoose.model('Room', new mongoose.Schema({
  number: String,
  type: String, // Standard, Deluxe, Suite
  price: Number // per night
}));

const Booking = mongoose.model('Booking', new mongoose.Schema({
  user: { type: ObjectId, ref: 'User' },
  room: { type: ObjectId, ref: 'Room' },
  checkIn: Date,
  checkOut: Date,
  status: { type: String, enum: ['booked', 'checked-in', 'checked-out'], default: 'booked' },
  folio: { type: Number, default: 0 } // food charges added to room bill
}, { timestamps: true }));

const MenuItem = mongoose.model('MenuItem', new mongoose.Schema({
  name: String,
  category: String,
  price: Number,
  veg: Boolean,
  inStock: { type: Boolean, default: true }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  user: { type: ObjectId, ref: 'User' },
  booking: { type: ObjectId, ref: 'Booking' },
  roomNumber: String,
  items: [{ name: String, price: Number, qty: Number }],
  total: Number,
  payment: { type: String, enum: ['room', 'online'] },
  paid: { type: Boolean, default: false },
  status: { type: String, enum: ['placed', 'cooking', 'ready', 'delivered'], default: 'placed' }
}, { timestamps: true }));

/* ---------------- AUTH MIDDLEWARE ---------------- */
const auth = (...roles) => (req, res, next) => {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (roles.length && !roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Not allowed' });
  }
  next();
};

const makeToken = (u) =>
  jwt.sign({ id: u._id, name: u.name, role: u.role }, SECRET, { expiresIn: '1d' });

/* ---------------- AUTH ROUTES ---------------- */
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    const hash = await bcrypt.hash(password, 10);
    const u = await User.create({ name, email, password: hash }); // role always guest
    res.json({ token: makeToken(u), name: u.name, role: u.role });
  } catch (e) {
    res.status(400).json({ error: 'Email already used' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email });
  if (!u || !(await bcrypt.compare(password, u.password))) {
    return res.status(400).json({ error: 'Wrong email or password' });
  }
  res.json({ token: makeToken(u), name: u.name, role: u.role });
});

/* ---------------- ROOMS & BOOKINGS ---------------- */
// available rooms for given dates
app.get('/api/rooms', async (req, res) => {
  const { checkIn, checkOut } = req.query;
  const rooms = await Room.find();
  if (!checkIn || !checkOut) return res.json(rooms);
  const busy = await Booking.find({
    status: { $ne: 'checked-out' },
    checkIn: { $lt: new Date(checkOut) },
    checkOut: { $gt: new Date(checkIn) }
  }).distinct('room');
  const busyIds = busy.map(String);
  res.json(rooms.filter((r) => !busyIds.includes(String(r._id))));
});

app.post('/api/bookings', auth('guest'), async (req, res) => {
  const { roomId, checkIn, checkOut } = req.body;
  const inD = new Date(checkIn), outD = new Date(checkOut);
  if (!(inD < outD)) return res.status(400).json({ error: 'Check-out must be after check-in' });
  // double-booking check
  const clash = await Booking.findOne({
    room: roomId,
    status: { $ne: 'checked-out' },
    checkIn: { $lt: outD },
    checkOut: { $gt: inD }
  });
  if (clash) return res.status(400).json({ error: 'Room already booked for these dates' });
  const b = await Booking.create({ user: req.user.id, room: roomId, checkIn: inD, checkOut: outD });
  res.json(b);
});

app.get('/api/bookings/my', auth('guest'), async (req, res) => {
  res.json(await Booking.find({ user: req.user.id }).populate('room').sort('-createdAt'));
});

app.get('/api/bookings', auth('admin'), async (req, res) => {
  res.json(await Booking.find().populate('room').populate('user', 'name email').sort('-createdAt'));
});

app.patch('/api/bookings/:id/:action', auth('admin'), async (req, res) => {
  const map = { checkin: 'checked-in', checkout: 'checked-out' };
  const status = map[req.params.action];
  if (!status) return res.status(400).json({ error: 'Bad action' });
  const b = await Booking.findByIdAndUpdate(req.params.id, { status }, { new: true });
  res.json(b);
});

/* ---------------- MENU ---------------- */
app.get('/api/menu', async (req, res) => res.json(await MenuItem.find()));

app.patch('/api/menu/:id/stock', auth('chef', 'admin'), async (req, res) => {
  const item = await MenuItem.findById(req.params.id);
  item.inStock = !item.inStock;
  await item.save();
  io.emit('menu:changed');
  res.json(item);
});

/* ---------------- ORDERS ---------------- */
app.post('/api/orders', auth('guest'), async (req, res) => {
  const { items, payment } = req.body; // items: [{id, qty}]
  if (!items || !items.length) return res.status(400).json({ error: 'Cart empty' });

  // only checked-in guests can order to room
  const booking = await Booking.findOne({ user: req.user.id, status: 'checked-in' }).populate('room');
  if (!booking) return res.status(400).json({ error: 'You must be checked-in to order' });

  // price is taken from DB, never from client
  const lines = [];
  let total = 0;
  for (const it of items) {
    const m = await MenuItem.findById(it.id);
    if (!m || !m.inStock) return res.status(400).json({ error: `${m ? m.name : 'Item'} not available` });
    const qty = Math.max(1, parseInt(it.qty) || 1);
    lines.push({ name: m.name, price: m.price, qty });
    total += m.price * qty;
  }

  const order = await Order.create({
    user: req.user.id,
    booking: booking._id,
    roomNumber: booking.room.number,
    items: lines,
    total,
    payment,
    paid: payment === 'online' // online payment is mocked for the demo
  });

  if (payment === 'room') {
    booking.folio += total; // charge to room bill
    await booking.save();
  }
  io.emit('orders:changed');
  res.json(order);
});

app.get('/api/orders/my', auth('guest'), async (req, res) => {
  res.json(await Order.find({ user: req.user.id }).sort('-createdAt').limit(20));
});

app.get('/api/orders', auth('chef', 'admin'), async (req, res) => {
  res.json(await Order.find({ status: { $ne: 'delivered' } }).sort('createdAt'));
});

app.patch('/api/orders/:id/status', auth('chef', 'admin'), async (req, res) => {
  const { status } = req.body;
  const o = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
  io.emit('orders:changed');
  res.json(o);
});

/* ---------------- SOCKET ---------------- */
io.on('connection', (socket) => {
  console.log('socket connected', socket.id);
});

/* ---------------- SEED DATA ---------------- */
async function seed() {
  if (await Room.countDocuments()) return;
  await Room.insertMany([
    { number: '101', type: 'Standard', price: 2500 },
    { number: '102', type: 'Standard', price: 2500 },
    { number: '201', type: 'Deluxe', price: 4000 },
    { number: '202', type: 'Deluxe', price: 4000 },
    { number: '301', type: 'Suite', price: 7500 }
  ]);
  await MenuItem.insertMany([
    { name: 'Masala Dosa', category: 'Breakfast', price: 120, veg: true },
    { name: 'Paneer Sandwich', category: 'Snacks', price: 150, veg: true },
    { name: 'Chicken Biryani', category: 'Main Course', price: 280, veg: false },
    { name: 'Dal Tadka + Rice', category: 'Main Course', price: 180, veg: true },
    { name: 'Cold Coffee', category: 'Beverages', price: 90, veg: true },
    { name: 'Brownie', category: 'Dessert', price: 110, veg: true }
  ]);
  const hash = await bcrypt.hash('admin123', 10);
  await User.insertMany([
    { name: 'Admin', email: 'admin@ghn.com', password: hash, role: 'admin' },
    { name: 'Chef', email: 'chef@ghn.com', password: hash, role: 'chef' }
  ]);
  console.log('Seed data added (admin@ghn.com / chef@ghn.com, password: admin123)');
}

mongoose.connect(MONGO).then(async () => {
  console.log('MongoDB connected');
  await seed();
  server.listen(process.env.PORT || 5000, () => console.log('Server on http://localhost:5000'));
}).catch((e) => console.error('DB error:', e.message));
