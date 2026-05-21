const BYPASS_SECRET = Deno.env.get("BYPASS_SECRET");
const TARGET_HOST = "be.komikcast.cc";

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
];

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

  const ua = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

  try {
    const res = await fetch(targetUrl, {
      headers: {
        "User-Agent": ua,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8",
        "Referer": `https://${TARGET_HOST}/`,
        "Origin": `https://${TARGET_HOST}`,
      },
    });

    const body = await res.arrayBuffer();
    return new Response(body, {
      status: res.status,
      headers: {
        "Content-Type": res.headers.get("Content-Type") ?? "application/json",
        "Access-Control-Allow-Origin": "*",
      },
    });
  } catch (err) {
    return Response.json({ error: String(err) }, { status: 500 });
  }
});
