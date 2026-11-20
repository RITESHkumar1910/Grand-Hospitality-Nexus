# Grand Hospitality Nexus (GHN) - Mini Project

Hotel room booking and cafeteria room-service ordering with a live kitchen display.

## How to Run
1. Install Node.js and MongoDB (or use a MongoDB Atlas connection string).
2. Run `npm install`.
3. Create a `.env` file:
   ```
   MONGO_URI=mongodb://127.0.0.1:27017/ghn
   JWT_SECRET=any_secret_text
   PORT=5000
   ```
4. Run `npm start` and open http://localhost:5000

## Demo Accounts
- Admin (front desk): admin@ghn.com / admin123
- Chef: chef@ghn.com / admin123
- Guest: register a new account

## Demo Flow
1. Guest registers, selects dates, and books a room.
2. Admin logs in and checks the guest in (only checked-in guests can order food).
3. Guest opens Order Food, selects "Charge to Room", and places an order.
4. Chef logs in (second browser or tab). The order appears instantly via Socket.io. Chef marks it Cooking, Ready, then Delivered.
5. The guest screen updates live with the order status.
6. The admin panel shows the room's food bill (folio).

## Tech Stack
Node.js, Express, MongoDB (Mongoose), Socket.io, JWT, bcrypt, HTML/CSS/JavaScript

## Scope Notes
- Uses MongoDB only (no PostgreSQL or microservices). A monolith is enough for a student project.
- Online payment is a demo (no Razorpay or Stripe integration).
- QR code login, courier PWA, analytics, and inventory are listed as future scope.
