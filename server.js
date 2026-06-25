// ============================================================================
// KHBD AI Proxy — server Node.js/Express (dùng cho Render.com hoặc bất kỳ
// nền tảng Node nào chạy ở MỘT khu vực cố định — khác với Cloudflare Worker
// vốn định tuyến request qua mạng edge toàn cầu, dễ vô tình đi qua vùng bị
// Anthropic chặn và trả lỗi 403 "Request not allowed").
//
// CHẠY THỬ Ở MÁY (tuỳ chọn, không bắt buộc):
//   npm install
//   ANTHROPIC_API_KEY=sk-ant-... node server.js
//
// DEPLOY LÊN RENDER.COM — xem hướng dẫn chi tiết đi kèm.
// ============================================================================
const express = require("express");
const app = express();
app.use(express.json({ limit: "2mb" }));

const ALLOWED_ORIGIN = "*"; // có thể giới hạn lại thành domain bạn host file HTML
const APP_SHARED_SECRET = process.env.APP_SHARED_SECRET || ""; // để trống = không kiểm tra

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, X-App-Secret");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.get("/", (req, res) => {
  res.send("KHBD AI proxy đang chạy. Dùng phương thức POST để gọi mô hình.");
});

app.post("/", async (req, res) => {
  if (APP_SHARED_SECRET) {
    const provided = req.header("X-App-Secret") || "";
    if (provided !== APP_SHARED_SECRET) {
      return res.status(401).json({ error: "Sai mã truy cập của ứng dụng (X-App-Secret)." });
    }
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: "Server chưa cấu hình ANTHROPIC_API_KEY. Vào Environment Variables trên Render để thêm." });
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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("KHBD AI proxy listening on port " + port));
