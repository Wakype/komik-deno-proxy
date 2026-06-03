const BYPASS_SECRET = Deno.env.get("BYPASS_SECRET");
const TARGET_HOST = "be.komikcast.cc";
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 menit

// ─── Deno KV Cache ────────────────────────────────────────────────────────────
const kv = await Deno.openKv();

async function getCachedKV(url: string) {
  const res = await kv.get<{ body: number[]; contentType: string }>(["cache", url]);
  if (!res.value) return null;
  return {
    body: new Uint8Array(res.value.body).buffer,
    contentType: res.value.contentType,
  };
}

async function setCacheKV(url: string, body: ArrayBuffer, contentType: string) {
  await kv.set(
    ["cache", url],
    { body: [...new Uint8Array(body)], contentType },
    { expireIn: CACHE_TTL_MS },
  );
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────
const rateLimitMap = new Map<string, { count: number; ts: number }>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 menit per IP

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.ts > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { count: 1, ts: now });
    return false;
  }

  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) return true;
  return false;
}

// ─── Input Sanitizer ──────────────────────────────────────────────────────────
function sanitizeParam(input: string): string {
  return input.replace(/[<>"'\\`;]/g, "").trim();
}

function isValidTargetUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return (
      parsed.hostname === TARGET_HOST &&
      (parsed.protocol === "https:" || parsed.protocol === "http:")
    );
  } catch {
    return false;
  }
}

// ─── User Agents ──────────────────────────────────────────────────────────────
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
];

// ─── Headers Builder ──────────────────────────────────────────────────────────
function buildHeaders(ua: string): Record<string, string> {
  return {
    "User-Agent": ua,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": `https://${TARGET_HOST}/`,
    "Origin": `https://${TARGET_HOST}`,
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Ch-Ua": '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
  };
}

// ─── Server ───────────────────────────────────────────────────────────────────
Deno.serve(async (req, info) => {
  const url = new URL(req.url);
  const start = Date.now();

  // IP dari remoteAddr (akurat di Deno Deploy)
  const ip = info.remoteAddr.hostname ?? "unknown";
  const userAgentHeader = req.headers.get("user-agent") ?? "unknown";

  const log = (status: number, note = "", target = "") => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${target || url.pathname} - ${status} - ${Date.now() - start}ms - ip:${ip} ${note}`,
  );
};

  // ── Health check / IP test ──
  if (url.pathname === "/ip") {
    const ipRes = await fetch("https://api.ipify.org?format=json");
    const data = await ipRes.json();
    log(200, "health-check");
    return Response.json({ ip: data.ip, platform: "deno-deploy" });
  }

  // ── Auth check ──
  const key = req.headers.get("X-Bypass-Key");
  if (BYPASS_SECRET && key !== BYPASS_SECRET) {
    log(401, "unauthorized");
    return new Response("Unauthorized", { status: 401 });
  }

  // ── Rate limit per IP ──
  if (isRateLimited(ip)) {
    log(429, `rate-limited ip:${ip}`);
    return new Response("Too Many Requests", {
      status: 429,
      headers: { "Retry-After": "60" },
    });
  }

  // ── Validasi & sanitasi target URL ──
  const rawUrl = url.searchParams.get("url");
  if (!rawUrl) {
    log(400, "missing-url");
    return new Response("Missing ?url= param", { status: 400 });
  }

  const targetUrl = sanitizeParam(rawUrl);
  if (!isValidTargetUrl(targetUrl)) {
    log(403, "invalid-target");
    return new Response("Forbidden host", { status: 403 });
  }

  // ── KV Cache hit ──
  const cached = await getCachedKV(targetUrl);
  if (cached) {
    log(200, "cache-hit", targetUrl);
    return new Response(cached.body, {
      status: 200,
      headers: {
        "Content-Type": cached.contentType,
        "Access-Control-Allow-Origin": "*",
        "X-Cache": "HIT",
      },
    });
  }

  // ── Jitter delay 100–500ms ──
  await new Promise((r) => setTimeout(r, 100 + Math.random() * 400));

  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const res = await fetch(targetUrl, { headers: buildHeaders(ua) });
    const body = await res.arrayBuffer();
    const contentType = res.headers.get("Content-Type") ?? "application/json";

    // Simpan ke KV cache hanya kalau sukses
    if (res.ok) {
      await setCacheKV(targetUrl, body, contentType);
    }

    log(res.status, res.ok ? "cache-miss" : "upstream-error", targetUrl);
    return new Response(body, {
      status: res.status,
      headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Origin": "*",
        "X-Cache": "MISS",
      },
    });
  } catch (err) {
    log(500, `error: ${err}`, targetUrl);
    return Response.json({ error: String(err) }, { status: 500 });
  }
});
