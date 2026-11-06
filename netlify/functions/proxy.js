const ALLOWED_DOMAIN = "sankavollerei.web.id";
const TIMEOUT_MS = 8000;
const SECRET_KEY = ""; // Isi jika ingin dikunci dengan header x-proxy-key

// Blokir bot/crawler langsung di level proxy agar kuota aman
const BOT_UA_REGEX =
  /bot|crawler|spider|crawling|scraper|reflection|claude|anthropic|gpt|chatgpt|oai-search|perplexity|facebookexternalhit|meta-externalagent|bytespider|petalbot|ahrefs|semrush|python|curl|wget|headless/i;

function getNetlifyClientIp(req, context) {
  return (
    req.headers.get("x-nf-client-connection-ip") ||
    context?.ip ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown-ip"
  );
}

export default async (req, context) => {
  const startTime = Date.now();
  const clientIp = getNetlifyClientIp(req, context);
  const clientUA = req.headers.get("user-agent") || "";
  const reqUrl = new URL(req.url);

  // Abaikan request otomatis browser ke /favicon.ico agar tidak memenuhi log
  if (reqUrl.pathname === "/favicon.ico") {
    return new Response(null, { status: 204 });
  }

  // 1. Handle CORS Preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type, User-Agent, Accept, Accept-Language, x-proxy-key",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // 2. Tolak Method selain GET
  if (req.method !== "GET") {
    return new Response(JSON.stringify({ status: "method_not_allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 3. Blokir Bot / Crawler
  if (!clientUA || BOT_UA_REGEX.test(clientUA)) {
    console.warn(`[BOT BLOCKED] IP: ${clientIp} | UA: ${clientUA}`);
    return new Response(JSON.stringify({ status: "forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 4. Cek Kunci Rahasia (Jika diaktifkan)
  if (SECRET_KEY && req.headers.get("x-proxy-key") !== SECRET_KEY) {
    return new Response(JSON.stringify({ status: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const targetUrl = reqUrl.searchParams.get("url");

  // 5. Response default jika diakses tanpa ?url=
  if (!targetUrl) {
    return new Response(
      JSON.stringify({ status: "online", service: "mangnime-komik-node" }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      },
    );
  }

  // 6. Validasi Hostname & Protokol HTTPS
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    return new Response(JSON.stringify({ status: "invalid_request" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const targetHost = parsedTarget.hostname;
  if (
    parsedTarget.protocol !== "https:" ||
    (targetHost !== ALLOWED_DOMAIN &&
      !targetHost.endsWith(`.${ALLOWED_DOMAIN}`))
  ) {
    return new Response(JSON.stringify({ status: "restricted" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 7. Header Standar yang Konsisten
  const requestHeaders = {
    Referer: `https://${targetHost}/`,
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    Accept: "application/json,text/plain,*/*",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(parsedTarget.toString(), {
      method: "GET",
      headers: requestHeaders,
      redirect: "follow",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;

    console.log(
      `[FUNC ${response.status}] (${duration}ms) | IP: ${clientIp} | Akses: ${parsedTarget.pathname}${parsedTarget.search}`,
    );

    // Hanya simpan ke cache jika status 200 OK (agar 403 tidak nyangkut di cache)
    const cacheHeader =
      response.status === 200
        ? "public, max-age=1800, s-maxage=1800, stale-while-revalidate=3600"
        : "no-store, no-cache, must-revalidate";

    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type":
          response.headers.get("Content-Type") || "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Cache-Control": cacheHeader,
      },
    });
  } catch (error) {
    clearTimeout(timeoutId);
    const isTimeout = error.name === "AbortError";

    return new Response(
      JSON.stringify({
        error: true,
        message: isTimeout ? "Gateway Timeout" : error.message,
      }),
      {
        status: isTimeout ? 504 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-store",
        },
      },
    );
  }
};

// Routing untuk Netlify Serverless Functions v2
export const config = {
  path: "/*",
};
