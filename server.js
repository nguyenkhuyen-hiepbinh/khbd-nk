// ============================================================================
// KHBD Server (bản đơn giản — KHÔNG có thanh toán tự động):
//   1. AI Proxy: giữ ANTHROPIC_API_KEY bí mật, chuyển tiếp request tới Anthropic.
//      Yêu cầu header X-Access-Code hợp lệ mới cho gọi.
//   2. Hệ thống mã truy cập: bạn (admin) tự tạo mã sau khi nhận tiền bằng cách
//      nào đó ngoài hệ thống (chuyển khoản, tiền mặt...), qua trang admin.html
//      đi kèm hoặc gọi trực tiếp API /admin/codes.
//
// Biến môi trường cần cấu hình trên Render:
//   ANTHROPIC_API_KEY      - key Anthropic thật
//   SUPABASE_URL           - URL project Supabase, dạng https://xxxx.supabase.co
//   SUPABASE_SERVICE_KEY   - service_role key của Supabase (KHÔNG dùng anon key)
//   ADMIN_SECRET            - mật khẩu quản trị tự đặt, dùng để tạo/xem/thu hồi mã
// ============================================================================
const express = require("express");
const crypto = require("crypto");
const app = express();
app.use(express.json({ limit: "2mb" }));

const ALLOWED_ORIGIN = "*";
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, X-Access-Code, X-Admin-Secret");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ----------------------------------------------------------------------------
// Helper: gọi Supabase REST API (PostgREST)
// ----------------------------------------------------------------------------
async function supabase(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error("Chưa cấu hình SUPABASE_URL / SUPABASE_SERVICE_KEY trên server.");
  }
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      Prefer: options.prefer || "return=representation",
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    throw new Error(`Supabase lỗi ${res.status}: ${typeof data === "string" ? data : JSON.stringify(data)}`);
  }
  return data;
}

function randomCode(prefix, len = 6) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // bỏ ký tự dễ nhầm (0,O,1,I)
  let s = "";
  for (let i = 0; i < len; i++) s += chars[crypto.randomInt(chars.length)];
  return `${prefix}-${s}`;
}

async function validateAccessCode(code, deviceId) {
  if (!code) return { valid: false, reason: "missing" };
  const rows = await supabase(`khbd_access_codes?code=eq.${encodeURIComponent(code)}&select=*`);
  const entry = rows && rows[0];
  if (!entry) return { valid: false, reason: "not_found" };
  if (!entry.active) return { valid: false, reason: "revoked" };
  if (new Date(entry.expires_at) < new Date()) return { valid: false, reason: "expired" };

  if (!entry.device_id) {
    // Lần đầu dùng mã này -> gắn vào thiết bị hiện tại
    if (deviceId) {
      await supabase(`khbd_access_codes?code=eq.${encodeURIComponent(code)}`, {
        method: "PATCH",
        body: JSON.stringify({ device_id: deviceId }),
      });
      entry.device_id = deviceId;
    }
    return { valid: true, entry };
  }
  if (deviceId && entry.device_id !== deviceId) {
    return { valid: false, reason: "device_mismatch" };
  }
  return { valid: true, entry };
}

function checkAdmin(req, res) {
  const secret = req.header("X-Admin-Secret") || "";
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    res.status(401).json({ error: "Sai mật khẩu quản trị." });
    return false;
  }
  return true;
}

// ----------------------------------------------------------------------------
// 1) AI PROXY — bắt buộc có X-Access-Code hợp lệ
// ----------------------------------------------------------------------------
app.post("/", async (req, res) => {
  const accessCode = (req.header("X-Access-Code") || "").trim().toUpperCase();
  const deviceId = (req.header("X-Device-Id") || "").trim();
  try {
    const check = await validateAccessCode(accessCode, deviceId);
    if (!check.valid) {
      const messages = {
        missing: "Thiếu mã truy cập. Liên hệ quản trị để được cấp mã.",
        not_found: "Mã truy cập không tồn tại.",
        revoked: "Mã truy cập đã bị thu hồi.",
        expired: "Mã truy cập đã hết hạn. Liên hệ quản trị để gia hạn.",
        device_mismatch: "Mã này đã được dùng trên một thiết bị khác.",
      };
      return res.status(401).json({ error: messages[check.reason] || "Mã truy cập không hợp lệ." });
    }
  } catch (e) {
    return res.status(500).json({ error: "Không kiểm tra được mã truy cập: " + e.message });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "Server chưa cấu hình ANTHROPIC_API_KEY." });
  }
  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(req.body),
    });
    const data = await upstream.text();
    res.status(upstream.status).type("application/json").send(data);
  } catch (e) {
    res.status(502).json({ error: "Không gọi được tới Anthropic API: " + e.message });
  }
});

app.get("/", (req, res) => res.send("KHBD server đang chạy."));

// ----------------------------------------------------------------------------
// 2) APP KIỂM TRA MÃ TRUY CẬP (dùng khi mở khoá app)
// ----------------------------------------------------------------------------
app.post("/access/validate", async (req, res) => {
  try {
    const code = String((req.body && req.body.code) || "").trim().toUpperCase();
    const deviceId = String((req.body && req.body.deviceId) || "").trim();
    const check = await validateAccessCode(code, deviceId);
    res.json(check.valid
      ? { valid: true, expiresAt: check.entry.expires_at, buyerName: check.entry.buyer_name }
      : { valid: false, reason: check.reason });
  } catch (e) {
    res.status(500).json({ error: "Lỗi kiểm tra mã: " + e.message });
  }
});

// ----------------------------------------------------------------------------
// 3) API QUẢN TRỊ — tạo / xem / thu hồi mã (dùng trang admin.html đi kèm)
// ----------------------------------------------------------------------------
app.post("/admin/codes", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const buyerName = String((req.body && req.body.buyerName) || "").slice(0, 100);
    const note = String((req.body && req.body.note) || "").slice(0, 200);
    const days = Math.max(1, parseInt((req.body && req.body.days) || "365", 10));
    const code = randomCode("HTL");
    const expiresAt = new Date(Date.now() + days * 24 * 3600 * 1000).toISOString();
    const rows = await supabase("khbd_access_codes", {
      method: "POST",
      body: JSON.stringify({ code, buyer_name: buyerName, note, expires_at: expiresAt, active: true }),
    });
    res.json({ ok: true, code, expiresAt, entry: rows && rows[0] });
  } catch (e) {
    res.status(500).json({ error: "Không tạo được mã: " + e.message });
  }
});

app.get("/admin/codes", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const rows = await supabase("khbd_access_codes?select=*&order=created_at.desc");
    res.json({ ok: true, codes: rows });
  } catch (e) {
    res.status(500).json({ error: "Không lấy được danh sách mã: " + e.message });
  }
});

app.post("/admin/codes/:code/revoke", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const code = req.params.code;
    await supabase(`khbd_access_codes?code=eq.${encodeURIComponent(code)}`, {
      method: "PATCH",
      body: JSON.stringify({ active: false }),
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Không thu hồi được mã: " + e.message });
  }
});

app.post("/admin/codes/:code/reactivate", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const code = req.params.code;
    await supabase(`khbd_access_codes?code=eq.${encodeURIComponent(code)}`, {
      method: "PATCH",
      body: JSON.stringify({ active: true }),
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Không kích hoạt lại được mã: " + e.message });
  }
});

app.post("/admin/codes/:code/reset-device", async (req, res) => {
  if (!checkAdmin(req, res)) return;
  try {
    const code = req.params.code;
    await supabase(`khbd_access_codes?code=eq.${encodeURIComponent(code)}`, {
      method: "PATCH",
      body: JSON.stringify({ device_id: null }),
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "Không reset được thiết bị: " + e.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("KHBD server listening on port " + port));

