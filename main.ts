const BYPASS_SECRET = Deno.env.get("BYPASS_SECRET");
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";
const TARGET_HOSTS = ["be.komikcast.cc"];
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 menit
const FETCH_TIMEOUT_MS = 10 * 1000; // 10 detik
const MAX_RETRIES = 1; // retry sekali kalau upstream gagal/5xx
const KV_CHUNK_SIZE = 60_000; // di bawah limit 64KiB per value Deno KV

// ─── Deno KV Cache (chunked, binary-native) ───────────────────────────────────
const kv = await Deno.openKv();

async function getCachedKV(url: string) {
  const meta = await kv.get<{ contentType: string; size: number; chunks: number }>([
    "cache",
    "meta",
    url,
  ]);
  if (!meta.value) return null;

  const { contentType, size, chunks } = meta.value;
  const buffer = new Uint8Array(size);
  let offset = 0;

  for (let i = 0; i < chunks; i++) {
    const chunk = await kv.get<Uint8Array>(["cache", "chunk", url, i]);
    if (!chunk.value) return null; // chunk expired/hilang → treat sebagai cache miss
    buffer.set(chunk.value, offset);
    offset += chunk.value.length;
  }

  return { body: buffer.buffer, contentType };
}

async function setCacheKV(url: string, body: ArrayBuffer, contentType: string) {
  const bytes = new Uint8Array(body);
  const totalChunks = Math.max(1, Math.ceil(bytes.length / KV_CHUNK_SIZE));

  // Uint8Array disimpan langsung (structured clone), TIDAK di-convert ke array
  for (let i = 0; i < totalChunks; i++) {
    const chunk = bytes.subarray(i * KV_CHUNK_SIZE, (i + 1) * KV_CHUNK_SIZE);
    await kv.set(["cache", "chunk", url, i], chunk, { expireIn: CACHE_TTL_MS });
  }
  // Meta ditulis TERAKHIR, jadi getCachedKV cuma "melihat" entry yang lengkap.
  await kv.set(
    ["cache", "meta", url],
    { contentType, size: bytes.length, chunks: totalChunks },
    { expireIn: CACHE_TTL_MS },
  );
}

// ─── Rate Limiter (in-memory, per isolate) ────────────────────────────────────
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
  return entry.count > RATE_LIMIT_MAX;
}

// ─── Target URL validation (tanpa mutasi) ─────────────────────────────────────
function parseValidTargetUrl(raw: string): URL | null {
  try {
    const parsed = new URL(raw);
    if (
      TARGET_HOSTS.includes(parsed.hostname) &&
      (parsed.protocol === "https:" || parsed.protocol === "http:")
    ) {
      return parsed;
    }
    return null;
  } catch {
    return null;
  }
}

// ─── User Agents ──────────────────────────────────────────────────────────────
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
];

function buildHeaders(ua: string, targetHost: string): Record<string, string> {
  return {
    "User-Agent": ua,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": `https://${targetHost}/`,
    "Origin": `https://${targetHost}`,
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

// ─── Fetch upstream dengan timeout + retry ────────────────────────────────────
async function fetchTarget(target: URL): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    try {
      const res = await fetch(target, {
        headers: buildHeaders(ua, target.hostname),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!res.ok && res.status >= 500 && attempt < MAX_RETRIES) {
        continue; // retry sekali kalau upstream error server-side
      }
      return res;
    } catch (err) {
      clearTimeout(timeout);
      lastErr = err;
      if (attempt === MAX_RETRIES) throw lastErr;
    }
  }
  throw lastErr;
}

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "X-Bypass-Key, Content-Type",
  };
}

// ─── Server ───────────────────────────────────────────────────────────────────
Deno.serve(async (req, info) => {
  const url = new URL(req.url);
  const start = Date.now();
  const ip = info.remoteAddr.hostname ?? "unknown";

  const log = (status: number, note = "", target = "") => {
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${target || url.pathname} - ${status} - ${
        Date.now() - start
      }ms - ip:${ip} ${note}`,
    );
  };

  // ── CORS preflight ──
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // ── Health check / IP test ──
  if (url.pathname === "/ip") {
    const ipRes = await fetch("https://api.ipify.org?format=json");
    const data = await ipRes.json();
    log(200, "health-check");
    return Response.json({ ip: data.ip, platform: "deno-deploy" }, { headers: corsHeaders() });
  }

  // ── Auth check ──
  const key = req.headers.get("X-Bypass-Key");
  if (BYPASS_SECRET && key !== BYPASS_SECRET) {
    log(401, "unauthorized");
    return new Response("Unauthorized", { status: 401, headers: corsHeaders() });
  }

  // ── Rate limit per IP ──
  if (isRateLimited(ip)) {
    log(429, `rate-limited ip:${ip}`);
    return new Response("Too Many Requests", {
      status: 429,
      headers: { ...corsHeaders(), "Retry-After": "60" },
    });
  }

  // ── Validasi target URL (tanpa mutasi) ──
  const rawUrl = url.searchParams.get("url");
  if (!rawUrl) {
    log(400, "missing-url");
    return new Response("Missing ?url= param", { status: 400, headers: corsHeaders() });
  }

  const target = parseValidTargetUrl(rawUrl);
  if (!target) {
    log(403, "invalid-target");
    return new Response("Forbidden host", { status: 403, headers: corsHeaders() });
  }
  const targetKey = target.toString();

  // ── KV Cache hit ──
  const cached = await getCachedKV(targetKey);
  if (cached) {
    log(200, "cache-hit", targetKey);
    return new Response(cached.body, {
      status: 200,
      headers: {
        ...corsHeaders(),
        "Content-Type": cached.contentType,
        "X-Cache": "HIT",
        // biar browser/CDN ikut nge-cache, jadi Deno Deploy nggak perlu
        // ngirim ulang byte yang sama tiap kali (ini yang bikin bandwidth spike)
        "Cache-Control": `public, max-age=${Math.floor(CACHE_TTL_MS / 1000)}`,
      },
    });
  }

  // ── Jitter delay 100–500ms, biar polanya nggak terlalu robotic ──
  await new Promise((r) => setTimeout(r, 100 + Math.random() * 400));

  try {
    const res = await fetchTarget(target);
    const body = await res.arrayBuffer();
    const contentType = res.headers.get("Content-Type") ?? "application/octet-stream";

    if (res.ok) {
      await setCacheKV(targetKey, body, contentType);
    }

    log(res.status, res.ok ? "cache-miss" : "upstream-error", targetKey);
    return new Response(body, {
      status: res.status,
      headers: {
        ...corsHeaders(),
        "Content-Type": contentType,
        "X-Cache": "MISS",
        "Cache-Control": res.ok
          ? `public, max-age=${Math.floor(CACHE_TTL_MS / 1000)}`
          : "no-store",
      },
    });
  } catch (err) {
    log(500, `error: ${err}`, targetKey);
    return Response.json({ error: String(err) }, { status: 500, headers: corsHeaders() });
  }
});
