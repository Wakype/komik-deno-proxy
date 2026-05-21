const BYPASS_SECRET = Deno.env.get("BYPASS_SECRET");
const TARGET_HOST = "be.komikcast.cc";
const CACHE_TTL = 5 * 60 * 1000; // 5 menit

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
];

const cache = new Map<string, {
  body: ArrayBuffer;
  contentType: string;
  ts: number;
}>();

function getCached(url: string) {
  const entry = cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) {
    cache.delete(url);
    return null;
  }
  return entry;
}

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

Deno.serve(async (req) => {
  const url = new URL(req.url);

  // Health check / IP test endpoint
  if (url.pathname === "/ip") {
    const ipRes = await fetch("https://api.ipify.org?format=json");
    const data = await ipRes.json();
    return Response.json({ ip: data.ip, platform: "deno-deploy" });
  }

  // Auth check
  const key = req.headers.get("X-Bypass-Key");
  if (BYPASS_SECRET && key !== BYPASS_SECRET) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Get target URL from query param
  const targetUrl = url.searchParams.get("url");
  if (!targetUrl) {
    return new Response("Missing ?url= param", { status: 400 });
  }

  // Only allow requests to target host
  const target = new URL(targetUrl);
  if (target.hostname !== TARGET_HOST) {
    return new Response("Forbidden host", { status: 403 });
  }

  // Cache hit
  const cached = getCached(targetUrl);
  if (cached) {
    return new Response(cached.body.slice(0), {
      status: 200,
      headers: {
        "Content-Type": cached.contentType,
        "Access-Control-Allow-Origin": "*",
        "X-Cache": "HIT",
      },
    });
  }

  // Jitter delay 100–500ms
  const jitter = 100 + Math.random() * 400;
  await new Promise((r) => setTimeout(r, jitter));

  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const res = await fetch(targetUrl, {
      headers: buildHeaders(ua),
    });

    const body = await res.arrayBuffer();
    const contentType = res.headers.get("Content-Type") ?? "application/json";

    if (res.ok) {
      cache.set(targetUrl, { body, contentType, ts: Date.now() });
    }

    return new Response(body, {
      status: res.status,
      headers: {
        "Content-Type": contentType,
        "Access-Control-Allow-Origin": "*",
        "X-Cache": "MISS",
      },
    });
  } catch (err) {
    return Response.json({ error: String(err) }, { status: 500 });
  }
});
