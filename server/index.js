
import express from "express";
import cors from "cors";
import crypto from "node:crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ==========================================
// 1. ISOLATED DEMO CONFIGURATION
// ==========================================

const demoConfigured =
  process.env.SWIFT_DEMO_INSTANCE === "isolated-demo" &&
  process.env.SWIFT_DEMO_CONFIRM === "YES_PUBLIC_SANDBOX";

if (!demoConfigured) {
  throw new Error(
    "This demo requires SWIFT_DEMO_INSTANCE=isolated-demo and SWIFT_DEMO_CONFIRM=YES_PUBLIC_SANDBOX"
  );
}

const forbiddenSecrets = [
  "DATABASE_URL",
  "MPESA_CONSUMER_SECRET",
  "MPESA_PASSKEY",
  "PAYMENT_SECRET_KEY"
];

if (forbiddenSecrets.some(key => process.env[key])) {
  throw new Error(
    "Do not connect production databases or payment credentials to the demo."
  );
}

const origins = (
  process.env.CORS_ORIGIN || "http://localhost:5173"
).split(",").map(x => x.trim()).filter(Boolean);

app.use(cors({ origin: origins }));

app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  res.set("X-Robots-Tag", "noindex, nofollow");
  next();
});

// ==========================================
// 2. DEMONSTRATION PRODUCTS AND STORE
// ==========================================

const seed = {
  products: [
    {
      id: "p1", sku: "SKU-001",
      barcode: "6161100123456",
      name: "Fresh Milk 500ml",
      category: "Dairy",
      price: 75, cost: 54,
      stock: 64, reorder: 15,
      unit: "pcs", icon: "🥛"
    },
    {
      id: "p2", sku: "SKU-002",
      barcode: "6161100123457",
      name: "White Bread 400g",
      category: "Bakery",
      price: 70, cost: 48,
      stock: 32, reorder: 12,
      unit: "pcs", icon: "🍞"
    },
    {
      id: "p3", sku: "SKU-003",
      barcode: "6161100123458",
      name: "Rice Premium 2kg",
      category: "Groceries",
      price: 420, cost: 340,
      stock: 85, reorder: 20,
      unit: "bags", icon: "🍚"
    },
    {
      id: "p4", sku: "SKU-004",
      barcode: "6161100123459",
      name: "Sugar 1kg",
      category: "Groceries",
      price: 180, cost: 145,
      stock: 56, reorder: 15,
      unit: "bags", icon: "🛍️"
    },
    {
      id: "p5", sku: "SKU-005",
      barcode: "6161100123460",
      name: "Cooking Oil 1L",
      category: "Groceries",
      price: 325, cost: 270,
      stock: 11, reorder: 15,
      unit: "bottles", icon: "🫗"
    },
    {
      id: "p6", sku: "SKU-006",
      barcode: "6161100123461",
      name: "Mineral Water 500ml",
      category: "Beverages",
      price: 50, cost: 28,
      stock: 120, reorder: 24,
      unit: "bottles", icon: "💧"
    },
    {
      id: "p7", sku: "SKU-007",
      barcode: "6161100123462",
      name: "Black Tea 250g",
      category: "Beverages",
      price: 210, cost: 160,
      stock: 8, reorder: 12,
      unit: "packs", icon: "🍵"
    },
    {
      id: "p8", sku: "SKU-008",
      barcode: "6161100123463",
      name: "Laundry Soap 800g",
      category: "Household",
      price: 155, cost: 112,
      stock: 43, reorder: 15,
      unit: "bars", icon: "🧼"
    }
  ],
  sales: [],
  movements: [],
  shifts: [],
  settings: {
    store: "Swift POS Mart",
    branch: "Main Branch",
    currency: "KES",
    receiptFooter: "Thank you for shopping with us!"
  }
};

// ==========================================
// 3. DISPOSABLE DEMO STORAGE
// ==========================================

const sessionTokens = new Map();

let sandboxData = structuredClone(seed);
let resetAt = Date.now() + 60 * 60 * 1000;

function read() {
  if (Date.now() >= resetAt) {
    sandboxData = structuredClone(seed);
    sessionTokens.clear();
    resetAt = Date.now() + 60 * 60 * 1000;
  }

  return structuredClone(sandboxData);
}

function write(data) {
  sandboxData = structuredClone(data);
}

const bad = (res, message, code = 400) =>
  res.status(code).json({ error: message });

const validMoney = n =>
  Number.isSafeInteger(n) &&
  n >= 0 &&
  n <= 1000000000;

// ==========================================
// 4. DEMO ROLES AND PERMISSIONS
// ==========================================

const demoRoles = [
  "admin",
  "manager",
  "cashier",
  "storekeeper",
  "accountant"
];

const roleCapabilities = {
  admin: [
    "state", "products", "stock",
    "sales", "shifts", "staff", "reset"
  ],
  manager: [
    "state", "products", "stock",
    "sales", "shifts"
  ],
  cashier: [
    "state", "sales", "shifts"
  ],
  storekeeper: [
    "state", "products", "stock"
  ],
  accountant: [
    "state"
  ]
};

const hashPassword = password => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(
    password, salt, 64
  ).toString("hex");

  return salt + ":" + hash;
};

const matchesPassword = (password, hash) => {
  try {
    const [salt, value] = hash.split(":");
    const actual = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(
      actual,
      Buffer.from(value, "hex")
    );
  } catch {
    return false;
  }
};

const safeStaff = user => ({
  id: user.id,
  username: user.username,
  displayName: user.displayName,
  role: user.role,
  active: user.active
});

function ensureAdmin() {
  const data = read();
  data.staff ||= [];

  if (data.staff.length === 0) {
    // Inaccessible random password: demo uses role buttons.
    const password = crypto.randomBytes(32).toString("hex");

    data.staff.push({
      id: crypto.randomUUID(),
      username: "admin",
      displayName: "Administrator",
      role: "admin",
      passwordHash: hashPassword(password),
      active: true
    });

    write(data);
  }

  return data;
}

// ==========================================
// 5. RATE LIMIT FOR DEMO LOGIN
// ==========================================

const attempts = new Map();

app.use("/api/auth/demo-login", (req, res, next) => {
  const ip = req.ip || "unknown";
  const now = Date.now();

  const previous = attempts.get(ip) || {
    count: 0,
    until: now + 60000
  };

  const current = previous.until < now
    ? { count: 0, until: now + 60000 }
    : previous;

  current.count++;
  attempts.set(ip, current);

  if (current.count > 30) {
    return bad(res, "Too many demo sign-ins.", 429);
  }

  next();
});

// ==========================================
// 6. AUTHENTICATION
// ==========================================

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};

  const user = (read().staff || []).find(
    x =>
      x.username === String(username || "").trim().toLowerCase() &&
      x.active
  );

  if (
    !user ||
    !matchesPassword(
      String(password || ""),
      user.passwordHash
    )
  ) {
    return bad(res, "Invalid credentials", 401);
  }

  const token = crypto.randomBytes(32).toString("hex");

  sessionTokens.set(token, {
    id: user.id,
    expires: Date.now() + 8 * 60 * 60 * 1000
  });

  res.json({ token, user: safeStaff(user) });
});

// Enabled only in this isolated demo build.
const demoAccess = demoConfigured;

app.get("/api/auth/demo-roles", (req, res) => {
  res.json({
    enabled: demoAccess,
    roles: demoAccess ? demoRoles : []
  });
});

app.post("/api/auth/demo-login", (req, res) => {
  if (!demoAccess) {
    return bad(res, "Demo access is disabled", 403);
  }

  const role = String(req.body?.role || "");

  if (!demoRoles.includes(role)) {
    return bad(res, "Invalid demo role");
  }

  const data = read();
  data.staff ||= [];

  const username = "demo_" + role;

  let user = data.staff.find(
    x => x.username === username
  );

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      username,
      displayName:
        "Demo " + role[0].toUpperCase() + role.slice(1),
      role,
      active: true,
      passwordHash: hashPassword(
        crypto.randomBytes(24).toString("hex")
      )
    };

    data.staff.push(user);
    write(data);
  }

  const token = crypto.randomBytes(32).toString("hex");

  sessionTokens.set(token, {
    id: user.id,
    expires: Date.now() + 2 * 60 * 60 * 1000
  });

  res.json({
    token,
    user: safeStaff(user)
  });
});

app.post("/api/auth/logout", (req, res) => {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer /i, "");

  sessionTokens.delete(token);
  res.json({ ok: true });
});

// ==========================================
// 7. PROTECTED API MIDDLEWARE
// ==========================================

app.use("/api", (req, res, next) => {
  const publicPaths = [
    "/health",
    "/auth/login",
    "/auth/logout",
    "/auth/demo-roles",
    "/auth/demo-login"
  ];

  if (publicPaths.includes(req.path)) {
    return next();
  }

  const token = (req.headers.authorization || "")
    .replace(/^Bearer /i, "");

  const session = sessionTokens.get(token);

  if (!session || session.expires < Date.now()) {
    return bad(res, "Login required", 401);
  }

  const user = (read().staff || []).find(
    x => x.id === session.id && x.active
  );

  if (!user) {
    return bad(res, "Account inactive", 403);
  }

  req.staff = user;

  const capability =
    req.path.startsWith("/products") ? "products" :
    req.path.startsWith("/stock") ? "stock" :
    req.path.startsWith("/sales") ? "sales" :
    req.path.startsWith("/shifts") ? "shifts" :
    req.path.startsWith("/staff") ? "staff" :
    req.path === "/reset" ? "reset" :
    "state";

  if (!roleCapabilities[user.role]?.includes(capability)) {
    return bad(res, "Insufficient permissions", 403);
  }

  if (
    user.role === "cashier" &&
    req.path === "/shifts/close"
  ) {
    return bad(res, "Manager approval required", 403);
  }

  next();
});

// ==========================================
// 8. STAFF MANAGEMENT
// ==========================================

app.get("/api/staff", (req, res) => {
  res.json(
    (read().staff || []).map(safeStaff)
  );
});

app.post("/api/staff", (req, res) => {
  const data = read();

  const username = String(
    req.body?.username || ""
  ).trim().toLowerCase();

  const displayName = String(
    req.body?.displayName || ""
  ).trim();

  const password = String(req.body?.password || "");
  const role = String(req.body?.role || "");

  if (
    !/^[a-z0-9._-]{3,32}$/.test(username) ||
    !displayName ||
    !roleCapabilities[role] ||
    password.length < 12
  ) {
    return bad(
      res,
      "Enter a valid username, name, role and password (12+ characters)"
    );
  }

  if (data.staff.some(x => x.username === username)) {
    return bad(res, "Username already exists", 409);
  }

  const user = {
    id: crypto.randomUUID(),
    username,
    displayName: displayName.slice(0, 80),
    passwordHash: hashPassword(password),
    role,
    active: true
  };

  data.staff.push(user);
  write(data);

  res.status(201).json(safeStaff(user));
});

// ==========================================
// 9. SYSTEM HEALTH AND STATE
// ==========================================

app.get("/", (req, res) => {
  res.json({
    name: "Swift POS Isolated Demo API",
    mode: "DEMO ONLY",
    status: "online"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    mode: "ISOLATED_PUBLIC_DEMO",
    payments: "simulated",
    storage: "disposable-memory",
    resetAt: new Date(resetAt).toISOString()
  });
});

app.get("/api/state", (req, res) => {
  const data = read();

  if (req.staff.role === "cashier") {
    data.products = data.products.map(
      ({ cost, ...product }) => product
    );

    data.sales = data.sales.map(sale => ({
      ...sale,
      items: sale.items.map(
        ({ cost, ...item }) => item
      )
    }));

    data.movements = [];
  }

  res.json({
    ...data,
    staff: undefined,
    mode: "DEMO",
    resetAt: new Date(resetAt).toISOString(),
    currentUser: safeStaff(req.staff)
  });
});

// ==========================================
// 10. PRODUCT MANAGEMENT
// ==========================================

app.post("/api/products", (req, res) => {
  const {
    name, sku, barcode, category,
    price, cost, stock, reorder, unit
  } = req.body || {};

  const data = read();

  if (!String(name || "").trim()) {
    return bad(res, "Product name is required");
  }

  if (!String(sku || "").trim()) {
    return bad(res, "SKU is required");
  }

  if (
    data.products.some(
      p => p.sku.toLowerCase() ===
        String(sku).trim().toLowerCase()
    )
  ) {
    return bad(res, "SKU already exists");
  }

  if (![price, cost, stock, reorder].every(validMoney)) {
    return bad(res, "Invalid price or stock quantity");
  }

  const product = {
    id: crypto.randomUUID(),
    name: String(name).trim().slice(0, 100),
    sku: String(sku).trim().slice(0, 40),
    barcode: String(barcode || "").trim().slice(0, 60),
    category: String(category || "Other").slice(0, 60),
    price, cost, stock, reorder,
    unit: String(unit || "pcs").slice(0, 20),
    icon: "📦"
  };

  data.products.push(product);

  if (stock) {
    data.movements.unshift({
      id: crypto.randomUUID(),
      productId: product.id,
      product: product.name,
      quantity: stock,
      type: "opening",
      note: "Opening stock",
      date: new Date().toISOString()
    });
  }

  write(data);
  res.status(201).json(product);
});

// ==========================================
// 11. EXCEL / CSV BULK PRODUCT IMPORT API
// ==========================================

app.post("/api/products/import", (req, res) => {
  const rows = req.body?.products;

  if (
    !Array.isArray(rows) ||
    rows.length === 0 ||
    rows.length > 500
  ) {
    return bad(res, "Submit 1 to 500 products per batch");
  }

  const data = read();

  const existing = new Set(
    data.products.map(p => p.sku.toLowerCase())
  );

  const seen = new Set();

  const barcodes = new Set(
    data.products.map(p => p.barcode).filter(Boolean)
  );

  const failures = [];
  const prepared = [];

  rows.forEach((row, index) => {
    const name = String(row?.name ?? "").trim();
    const sku = String(row?.sku ?? "").trim();
    const barcode = String(row?.barcode ?? "").trim();
    const category = String(row?.category ?? "Other").trim() || "Other";
    const unit = String(row?.unit ?? "pcs").trim() || "pcs";

    const numeric = [
      "price", "cost", "stock", "reorder"
    ].map(key => Number(row?.[key]));

    const errors = [];

    if (!name || name.length > 100) {
      errors.push("Invalid product name");
    }

    if (!sku || sku.length > 40) {
      errors.push("Invalid SKU");
    }

    if (
      existing.has(sku.toLowerCase()) ||
      seen.has(sku.toLowerCase())
    ) {
      errors.push("Duplicate SKU");
    }

    if (
      barcode.length > 60 ||
      (barcode && barcodes.has(barcode))
    ) {
      errors.push("Duplicate or invalid barcode");
    }

    if (category.length > 60 || unit.length > 20) {
      errors.push("Invalid category or unit");
    }

    if (numeric.some(n => !validMoney(n))) {
      errors.push("Invalid price or stock value");
    }

    if (errors.length) {
      failures.push({
        row: index + 2,
        errors
      });
      return;
    }

    seen.add(sku.toLowerCase());
    if (barcode) barcodes.add(barcode);

    prepared.push({
      id: crypto.randomUUID(),
      name, sku, barcode, category, unit,
      price: numeric[0],
      cost: numeric[1],
      stock: numeric[2],
      reorder: numeric[3],
      icon: "📦"
    });
  });

  if (failures.length) {
    return res.status(422).json({
      error: "Import validation failed; no products imported",
      failures
    });
  }

  const date = new Date().toISOString();

  for (const product of prepared) {
    data.products.push(product);

    if (product.stock) {
      data.movements.unshift({
        id: crypto.randomUUID(),
        productId: product.id,
        product: product.name,
        quantity: product.stock,
        type: "opening",
        note: "Bulk product import",
        date
      });
    }
  }

  write(data);

  res.status(201).json({
    imported: prepared.length
  });
});

// ==========================================
// 12. STOCK ADJUSTMENTS
// ==========================================

app.post("/api/stock/adjust", (req, res) => {
  const { productId, quantity, note } = req.body || {};

  const data = read();
  const product = data.products.find(p => p.id === productId);

  if (!product) return bad(res, "Product not found", 404);

  if (
    !Number.isSafeInteger(quantity) ||
    quantity === 0 ||
    Math.abs(quantity) > 1000000
  ) {
    return bad(res, "Invalid stock quantity");
  }

  if (product.stock + quantity < 0) {
    return bad(res, "Insufficient stock");
  }

  product.stock += quantity;

  data.movements.unshift({
    id: crypto.randomUUID(),
    productId,
    product: product.name,
    quantity,
    type: "adjustment",
    note: String(note || "Manual adjustment").slice(0, 150),
    date: new Date().toISOString()
  });

  write(data);
  res.json(product);
});

// ==========================================
// 13. POS CHECKOUT
// ==========================================

app.post("/api/sales", (req, res) => {
  const {
    items,
    paymentMethod = "cash",
    amountTendered,
    discount = 0,
    payments,
    requestId
  } = req.body || {};

  if (
    !Array.isArray(items) ||
    items.length === 0 ||
    items.length > 100
  ) {
    return bad(res, "A sale must contain products");
  }

  if (!validMoney(discount)) {
    return bad(res, "Invalid discount");
  }

  const data = read();

  data.shifts ||= [];
  data.sales ||= [];
  data.movements ||= [];

  if (requestId) {
    const existing = data.sales.find(
      sale => sale.requestId === requestId
    );
    if (existing) return res.json(existing);
  }

  const shift = data.shifts.find(
    x => x.status === "open" &&
      x.cashierId === req.staff.id
  );

  if (!shift) {
    return bad(
      res,
      "Open your own cashier shift before checkout",
      409
    );
  }

  const quantities = new Map();

  for (const item of items) {
    if (
      !Number.isSafeInteger(item.qty) ||
      item.qty < 1 ||
      item.qty > 10000
    ) {
      return bad(res, "Invalid quantity");
    }

    quantities.set(
      item.productId,
      (quantities.get(item.productId) || 0) + item.qty
    );
  }

  const saleItems = [];

  for (const [id, qty] of quantities) {
    const product = data.products.find(p => p.id === id);

    if (!product) return bad(res, "Unknown product");

    if (product.stock < qty) {
      return bad(res, "Insufficient stock: " + product.name);
    }

    saleItems.push({
      productId: id,
      name: product.name,
      sku: product.sku,
      qty,
      price: product.price,
      cost: product.cost,
      lineTotal: qty * product.price
    });
  }

  const subtotal = saleItems.reduce(
    (sum, item) => sum + item.lineTotal, 0
  );

  if (discount > subtotal) {
    return bad(res, "Discount exceeds subtotal");
  }

  if (
    discount > 0 &&
    !["admin", "manager"].includes(req.staff.role)
  ) {
    return bad(res, "Manager permission required for discount", 403);
  }

  const total = subtotal - discount;

  const allocations = Array.isArray(payments)
    ? payments
    : [{
        method: paymentMethod,
        amount: paymentMethod === "cash"
          ? amountTendered
          : total
      }];

  if (
    !allocations.length ||
    allocations.length > 3 ||
    allocations.some(
      p =>
        !["cash", "mpesa", "card"].includes(p.method) ||
        !validMoney(p.amount)
    )
  ) {
    return bad(res, "Invalid payment allocations");
  }

  const cash = allocations
    .filter(p => p.method === "cash")
    .reduce((sum, p) => sum + p.amount, 0);

  const noncash = allocations
    .filter(p => p.method !== "cash")
    .reduce((sum, p) => sum + p.amount, 0);

  if (noncash > total || cash + noncash < total) {
    return bad(res, "Payments do not cover the total");
  }

  if (cash + noncash > total && cash === 0) {
    return bad(res, "Only cash tender can create change");
  }

  const now = new Date().toISOString();

  const sale = {
    id: crypto.randomUUID(),
    requestId: String(requestId || crypto.randomUUID()),
    receiptNumber:
      "SP-" +
      Date.now().toString(36).toUpperCase() +
      "-" +
      crypto.randomBytes(2).toString("hex").toUpperCase(),
    date: now,
    items: saleItems,
    subtotal,
    discount,
    total,
    payments: allocations,
    paymentMethod:
      allocations.length > 1 ? "split" : allocations[0].method,
    paymentStatus: "DEMO_SIMULATED",
    amountTendered: cash + noncash,
    change: cash + noncash - total,
    branch: data.settings.branch,
    shiftId: shift.id,
    cashier: shift.cashier,
    cashierId: req.staff.id,
    registerId: shift.registerId || "REG-01",
    refunded: false
  };

  for (const item of saleItems) {
    const product = data.products.find(
      p => p.id === item.productId
    );

    product.stock -= item.qty;

    data.movements.unshift({
      id: crypto.randomUUID(),
      productId: item.productId,
      product: item.name,
      quantity: -item.qty,
      type: "sale",
      note: sale.receiptNumber,
      date: now
    });
  }

  data.sales.unshift(sale);
  write(data);

  res.status(201).json(sale);
});

// ==========================================
// 14. REFUNDS
// ==========================================

app.post("/api/sales/:id/refund", (req, res) => {
  if (!["admin", "manager"].includes(req.staff.role)) {
    return bad(res, "Manager permission required", 403);
  }

  const data = read();

  const sale = data.sales.find(
    x => x.id === req.params.id
  );

  if (!sale) return bad(res, "Sale not found", 404);

  if (sale.refunded) {
    return bad(res, "Sale already refunded", 409);
  }

  const reason = String(req.body?.reason || "").trim();

  if (reason.length < 5) {
    return bad(res, "Provide a refund reason");
  }

  sale.refunded = true;
  sale.refundedAt = new Date().toISOString();
  sale.refundReason = reason;
  sale.refundBy = req.staff.displayName;

  for (const item of sale.items) {
    const product = data.products.find(
      p => p.id === item.productId
    );

    if (product) {
      product.stock += item.qty;

      data.movements.unshift({
        id: crypto.randomUUID(),
        productId: product.id,
        product: product.name,
        quantity: item.qty,
        type: "refund",
        note: sale.receiptNumber,
        date: sale.refundedAt
      });
    }
  }

  write(data);
  res.json(sale);
});

// ==========================================
// 15. CASHIER SHIFTS
// ==========================================

app.post("/api/shifts/open", (req, res) => {
  const data = read();
  data.shifts ||= [];

  if (data.shifts.some(s => s.status === "open")) {
    return bad(res, "Close the current shift first", 409);
  }

  const cashier = req.staff.displayName;
  const openingFloat = req.body?.openingFloat;

  if (!cashier || !validMoney(openingFloat)) {
    return bad(res, "Invalid opening cash float");
  }

  const shift = {
    id: crypto.randomUUID(),
    cashier,
    cashierId: req.staff.id,
    registerId: "REG-01",
    cashMovements: [],
    status: "open",
    openingFloat,
    openedAt: new Date().toISOString(),
    closedAt: null,
    declaredCash: null,
    expectedCash: null,
    variance: null
  };

  data.shifts.unshift(shift);
  write(data);

  res.status(201).json(shift);
});

app.post("/api/shifts/close", (req, res) => {
  const data = read();

  const shift = data.shifts.find(
    s => s.status === "open"
  );

  if (!shift) return bad(res, "No open shift", 409);

  const declaredCash = req.body?.declaredCash;

  if (!validMoney(declaredCash)) {
    return bad(res, "Invalid counted cash amount");
  }

  const cashSales = data.sales
    .filter(s => s.shiftId === shift.id && !s.refunded)
    .reduce((total, sale) => {
      if (sale.payments) {
        const cashTendered = sale.payments
          .filter(p => p.method === "cash")
          .reduce((sum, p) => sum + p.amount, 0);

        return total + Math.max(
          0,
          cashTendered - (sale.change || 0)
        );
      }

      return total +
        (sale.paymentMethod === "cash" ? sale.total : 0);
    }, 0);

  const movements = (shift.cashMovements || [])
    .reduce(
      (sum, m) =>
        sum + (m.type === "pay-in" ? m.amount : -m.amount),
      0
    );

  const expectedCash =
    shift.openingFloat + cashSales + movements;

  Object.assign(shift, {
    status: "closed",
    closedAt: new Date().toISOString(),
    declaredCash,
    expectedCash,
    variance: declaredCash - expectedCash,
    notes: String(req.body?.notes || "").slice(0, 300)
  });

  write(data);
  res.json(shift);
});

// ==========================================
// 16. CASH DRAWER MOVEMENTS
// ==========================================

app.post("/api/shifts/cash-movement", (req, res) => {
  const data = read();

  const shift = data.shifts.find(
    s => s.status === "open"
  );

  if (!shift) {
    return bad(res, "Open a shift first", 409);
  }

  if (
    req.staff.role === "cashier" &&
    shift.cashierId !== req.staff.id
  ) {
    return bad(res, "Register belongs to another cashier", 403);
  }

  const { type, amount, reason } = req.body || {};

  if (
    !["pay-in", "pay-out"].includes(type) ||
    !validMoney(amount) ||
    amount === 0 ||
    !String(reason || "").trim()
  ) {
    return bad(res, "Invalid cash movement");
  }

  const entry = {
    id: crypto.randomUUID(),
    type,
    amount,
    reason: String(reason).trim().slice(0, 160),
    staffId: req.staff.id,
    staff: req.staff.displayName,
    date: new Date().toISOString()
  };

  shift.cashMovements ||= [];
  shift.cashMovements.push(entry);

  write(data);
  res.status(201).json(entry);
});

// ==========================================
// 17. RECEIPT PRINT HISTORY
// ==========================================

app.post("/api/sales/:id/print", (req, res) => {
  const data = read();

  const sale = data.sales.find(
    x => x.id === req.params.id
  );

  if (!sale) return bad(res, "Sale not found", 404);

  data.printEvents ||= [];

  const event = {
    id: crypto.randomUUID(),
    saleId: sale.id,
    receiptNumber: sale.receiptNumber,
    staffId: req.staff.id,
    staff: req.staff.displayName,
    date: new Date().toISOString(),
    kind: "browser-print-request"
  };

  data.printEvents.unshift(event);
  write(data);

  res.status(201).json(event);
});

// ==========================================
// 18. RESET DISPOSABLE DEMO RECORDS
// ==========================================

app.post("/api/reset", (req, res) => {
  sandboxData = structuredClone(seed);
  sessionTokens.clear();
  resetAt = Date.now() + 60 * 60 * 1000;

  ensureAdmin();

  res.json({
    ok: true,
    message: "Demo data reset. Please sign in again."
  });
});

// ==========================================
// 19. START SERVER
// ==========================================

ensureAdmin();

const PORT = process.env.PORT || 4000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "Swift POS Isolated Demo API running on port " + PORT
  );
});
