// server/index.js
import express from "express";
import cors from "cors";
import fs from "fs";
import { PrismaClient } from "@prisma/client"; 
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
const prisma = new PrismaClient();

const app = express();
const PORT = process.env.PORT || 8000;

// --- Simple admin auth for analytics ---
const ADMIN_KEY = process.env.ADMIN_KEY || "dev-admin-key"; // change for production

function requireAdmin(req, res, next) {
  const key = req.query.key || req.headers["x-admin-key"];
  if (!ADMIN_KEY) return next(); // if you ever unset it
  if (key !== ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized: invalid admin key" });
  }
  next();
}

// --- Auth config ---
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-key"; // change for production

// --- Basic sanitization helper ---
function sanitizeString(value, maxLen = 80) {
  if (!value) return "";
  let s = String(value).trim();
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Missing auth token" });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: payload.id } });
    if (!user) return res.status(401).json({ error: "User not found" });
    req.user = { id: user.id, email: user.email, name: user.name };
    next();
  } catch (e) {
    console.error("Auth error:", e);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// --- Very simple in-memory rate limiting (per IP) ---
const rateBuckets = {};

function rateLimit(windowMs, maxRequests, label = "rate") {
  return (req, res, next) => {
    const ip =
      req.ip ||
      req.headers["x-forwarded-for"] ||
      req.socket?.remoteAddress ||
      "anon";

    const now = Date.now();
    const key = `${label}:${ip}`;

    if (!rateBuckets[key]) {
      rateBuckets[key] = { count: 1, start: now };
      return next();
    }

    const bucket = rateBuckets[key];
    const elapsed = now - bucket.start;

    if (elapsed > windowMs) {
      // reset window
      bucket.count = 1;
      bucket.start = now;
      return next();
    }

    bucket.count += 1;
    if (bucket.count > maxRequests) {
      return res.status(429).json({
        error: "Too many requests",
        hint: `Slow down on ${label} calls`,
      });
    }

    next();
  };
}

const checkoutLimiter = rateLimit(60_000, 10, "checkout"); // 10 checkouts / min / IP
const adminLimiter = rateLimit(60_000, 60, "admin");       // 60 admin calls / min / IP

// --- middleware ---
app.use(cors());
app.use(express.json());

// --- friendly GET for checkout ---
app.get("/api/cart/checkout", (_req, res) => {
  res
    .status(405)
    .send("Use POST /api/cart/checkout to place an order (with JSON body).");
});

// --- Coupon config ---
// Simple hard-coded coupons for UniThrift
const COUPONS = {
  UNISTUDENT10: {
    type: "percent",
    value: 10,
    minTotal: 0,
    label: "10% off for students",
  },
  FREESHIP20: {
    type: "flat",
    value: 20,
    minTotal: 150,
    label: "₱20 off orders ₱150+",
  },
};

// Helper: compute discount based on coupon code
function applyCoupon(total, rawCode) {
  const code = (rawCode || "").toString().trim().toUpperCase();
  const info = COUPONS[code];
  if (!info || total <= 0) {
    return { finalTotal: Math.round(total), discount: 0, code: null };
  }

  if (total < (info.minTotal ?? 0)) {
    return { finalTotal: Math.round(total), discount: 0, code: null };
  }

  let discount = 0;
  if (info.type === "percent") {
    discount = (total * info.value) / 100;
  } else if (info.type === "flat") {
    discount = info.value;
  }

  discount = Math.max(0, Math.round(discount));
  const finalTotal = Math.max(0, Math.round(total - discount));

  return { finalTotal, discount, code };
}
// --- Auth: signup ---
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body || {};

    const cleanEmail = sanitizeString(email, 120).toLowerCase();
    const cleanName = sanitizeString(name, 80);

    if (!cleanEmail || !password || !cleanName) {
      return res
        .status(400)
        .json({ error: "name, email, and password are required" });
    }

    const existing = await prisma.user.findUnique({
      where: { email: cleanEmail },
    });
    if (existing) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email: cleanEmail,
        name: cleanName,
        passwordHash,
      },
    });

    const token = signToken(user);
    return res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (e) {
    console.error("Signup error:", e);
    return res.status(500).json({ error: "Signup failed", message: String(e) });
  }
});
// --- Auth: login ---
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = sanitizeString(email, 120).toLowerCase();

    if (!cleanEmail || !password) {
      return res
        .status(400)
        .json({ error: "email and password are required" });
    }

    const user = await prisma.user.findUnique({
      where: { email: cleanEmail },
    });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signToken(user);
    return res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (e) {
    console.error("Login error:", e);
    return res.status(500).json({ error: "Login failed", message: String(e) });
  }
});

// --- Auth: current user ---
app.get("/api/me", requireAuth, async (req, res) => {
  res.json({ user: req.user });
});
// --- Seller: add product ---
app.post("/api/my/products", requireAuth, async (req, res) => {
  try {
    const { name, price, imageUrl, campus, category } = req.body;

    const cleanName = sanitizeString(name, 80);
    const cleanImage = sanitizeString(imageUrl, 200);
    const cleanCampus = sanitizeString(campus, 40);
    const cleanCategory = sanitizeString(category, 40);
    const numericPrice = Number(price);

    if (!cleanName || !numericPrice) {
      return res.status(400).json({ error: "name and price are required" });
    }

    const product = await prisma.product.create({
      data: {
        name: cleanName,
        price: numericPrice,
        imageUrl: cleanImage || null,
        campus: cleanCampus || "ADMU",
        category: cleanCategory || "General",
        sellerId: req.user.id,
      },
    });

    res.json({ product });
  } catch (e) {
    console.error("Add product error:", e);
    res.status(500).json({ error: "Failed to create product" });
  }
});

// --- Seller: view my products ---
app.get("/api/my/products", requireAuth, async (req, res) => {
  const products = await prisma.product.findMany({
    where: { sellerId: req.user.id },
    orderBy: { createdAt: "desc" },
  });

  res.json({ products });
});

// --- Seller: delete product ---
app.delete("/api/my/products/:id", requireAuth, async (req, res) => {
  try {
    const id = req.params.id;

    // ensure the product belongs to the user
    const product = await prisma.product.findUnique({
      where: { id },
    });

    if (!product || product.sellerId !== req.user.id) {
      return res.status(403).json({ error: "Not allowed" });
    }

    await prisma.product.delete({ where: { id } });

    res.json({ ok: true });
  } catch (e) {
    console.error("Delete product error:", e);
    res.status(500).json({ error: "Failed to delete product" });
  }
});
// --- Buyer: my orders ---
app.get("/api/my/orders", requireAuth, async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { buyerId: req.user.id },
    include: { items: true },
    orderBy: { createdAt: "desc" },
  });

  res.json({ orders });
});
// --- Seller: my sales (orders containing my products) ---
app.get("/api/my/sales", requireAuth, async (req, res) => {
  const products = await prisma.product.findMany({
    where: { sellerId: req.user.id },
    select: { id: true },
  });

  const ids = products.map(p => p.id);

  if (ids.length === 0) {
    return res.json({ orders: [] });
  }

  const orders = await prisma.order.findMany({
    where: {
      items: {
        some: { productId: { in: ids } }
      }
    },
    include: { items: true },
    orderBy: { createdAt: "desc" },
  });

  res.json({ orders });
});
// --- Checkout (tolerant to client ids / snapshots)
app.post("/api/cart/checkout", checkoutLimiter, requireAuth, async (req, res) => {
  try {
    console.log("POST /api/cart/checkout headers:", req.headers);
    console.log("POST /api/cart/checkout body:", req.body);

    const campus = sanitizeString(req.body?.campus || "ADMU", 40);
    const pickup = sanitizeString(req.body?.pickup || "Gate 2.5", 80);
    const couponCodeRaw = sanitizeString(req.body?.couponCode || "", 32);

    const phoneRaw = req.body?.phone;
    const buyerPhone = sanitizeString(phoneRaw || "", 32);
    if (!buyerPhone) {
      return res.status(400).json({ error: "Phone number is required" });
    }

    // Accept multiple payload shapes:
    // { items: [...] }  OR  [...]  OR  { cart: [...] }
    let items = [];
    if (Array.isArray(req.body)) items = req.body;
    else if (Array.isArray(req.body?.items)) items = req.body.items;
    else if (Array.isArray(req.body?.cart)) items = req.body.cart;

    const norm = (items || [])
      .filter((i) => i)
      .map((i) => ({
        productId: (i.productId || i.id || "CLIENT-ID").toString(),
        name: (i.name || "Item").toString(),
        qty: Number.isFinite(Number(i.qty)) ? Number(i.qty) : 1,
        priceSnap: Number.isFinite(Number(i.price)) ? Number(i.price) : 0,
      }));

    if (norm.length === 0) {
      return res.status(422).json({
        error: "No items received",
        hint: "Check Content-Type: application/json and request body shape",
        received: req.body,
      });
    }

    // Pull DB prices where possible
    const ids = norm.filter((i) => i.productId).map((i) => i.productId);
    const found = await prisma.product.findMany({
      where: { id: { in: ids } },
    });
    const priceMap = Object.fromEntries(found.map((p) => [p.id, p.price]));

    const baseTotal = norm.reduce((sum, i) => {
      const dbPrice = Number.isFinite(priceMap[i.productId])
        ? priceMap[i.productId]
        : null;
      const unit = dbPrice ?? (Number.isFinite(i.priceSnap) ? i.priceSnap : 0);
      const qty = Number.isFinite(i.qty) && i.qty > 0 ? i.qty : 1;
      return sum + unit * qty;
    }, 0);

    // apply coupon
    const { finalTotal, discount, code: normalizedCode } = applyCoupon(
      baseTotal,
      couponCodeRaw
    );

    const order = await prisma.order.create({
      data: {
        campus,
        pickup,
        total: finalTotal,
        couponCode: normalizedCode,
        discount,
        buyerPhone,
        buyerId: req.user.id,
        items: {
          create: norm.map((it) => ({
            productId: it.productId,
            qty: it.qty,
            price: priceMap[it.productId] ?? it.priceSnap ?? 0,
          })),
        },
      },
      include: { items: true },
    });

    // Response includes totals & pickup info for the UI
    return res.json({
      orderId: order.id,
      total: order.total,
      discount: order.discount || 0,
      couponCode: order.couponCode || null,
      pickup: { etaMins: 15, fee: 0 },
    });
  } catch (e) {
    console.error("Checkout server error:", e);
    return res
      .status(500)
      .json({ error: "Checkout failed", message: String(e?.message || e) });
  }
});
// --- Admin analytics summary ---
// --- Admin analytics summary (no auth for dev/demo) ---
app.get("/api/admin/summary", async (req, res) => {
  try {
    const range = req.query.range || "7d"; // "7d", "30d", "all"
    const now = new Date();
    let from;

    if (range === "7d") {
      from = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    } else if (range === "30d") {
      from = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    } else {
      from = new Date(0); // all time
    }

    const orders = await prisma.order.findMany({
      where: {
        createdAt: {
          gte: from,
          lte: now,
        },
      },
      orderBy: { createdAt: "asc" },
    });

    // totals
    const totalSales = orders.reduce((sum, o) => sum + (o.total || 0), 0);
    const totalOrders = orders.length;
    const totalDiscount = orders.reduce(
      (sum, o) => sum + (o.discount || 0),
      0
    );
    const avgOrder =
      totalOrders > 0 ? Math.round(totalSales / totalOrders) : 0;

    // by campus
    const byCampusMap = {};
    orders.forEach((o) => {
      const campus = o.campus || "Unknown";
      if (!byCampusMap[campus]) {
        byCampusMap[campus] = { campus, sales: 0, orders: 0 };
      }
      byCampusMap[campus].sales += o.total || 0;
      byCampusMap[campus].orders += 1;
    });
    const byCampus = Object.values(byCampusMap);

    // by coupon
    const couponMap = {};
    orders.forEach((o) => {
      if (!o.couponCode) return;
      const code = o.couponCode;
      if (!couponMap[code]) {
        couponMap[code] = { code, uses: 0, totalDiscount: 0 };
      }
      couponMap[code].uses += 1;
      couponMap[code].totalDiscount += o.discount || 0;
    });
    const byCoupon = Object.values(couponMap);

    // daily series
    const dailyMap = {};
    orders.forEach((o) => {
      const key = o.createdAt.toISOString().slice(0, 10); // YYYY-MM-DD
      if (!dailyMap[key]) {
        dailyMap[key] = { date: key, sales: 0, orders: 0 };
      }
      dailyMap[key].sales += o.total || 0;
      dailyMap[key].orders += 1;
    });
    const daily = Object.values(dailyMap).sort((a, b) =>
      a.date.localeCompare(b.date)
    );

    res.json({
      range,
      from: from.toISOString(),
      to: now.toISOString(),
      totals: {
        sales: totalSales,
        orders: totalOrders,
        avgOrder,
        discount: totalDiscount,
      },
      byCampus,
      byCoupon,
      daily,
    });
  } catch (e) {
    console.error("Admin summary error:", e);
    res
      .status(500)
      .json({ error: "Failed to load admin summary", message: String(e) });
  }
});
// --- Admin: recent orders list ---
// --- Admin: recent orders list (no auth for dev/demo) ---
app.get("/api/admin/orders", async (req, res) => {
  try {
    const limit = Number(req.query.limit) || 50;
    const orders = await prisma.order.findMany({
      orderBy: { createdAt: "desc" },
      take: limit,
      include: { items: true },
    });
    res.json({ orders });
  } catch (e) {
    console.error("Admin orders error:", e);
    res
      .status(500)
      .json({ error: "Failed to load orders", message: String(e) });
  }
});
// --- API: View all orders (for testing) ---
app.get("/api/orders", (_req, res) => {
  try {
    if (!fs.existsSync("orders.json")) return res.json([]);
    const data = JSON.parse(fs.readFileSync("orders.json", "utf8"));
    res.json(data);
  } catch (err) {
    console.error("Error reading orders:", err);
    res.status(500).json({ error: "Failed to read orders." });
  }
});
// Public: list all products for the shop
app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      orderBy: { createdAt: "desc" },
    });
    res.json(products); // send as plain array
  } catch (e) {
    console.error("List products error:", e);
    res.status(500).json({ error: "Failed to load products" });
  }
});


app.listen(PORT, () => {
  console.log(`UniThrift backend running at http://localhost:${PORT}`);
});
