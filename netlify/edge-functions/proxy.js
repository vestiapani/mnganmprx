const ALLOWED_DOMAIN = "sankavollerei.web.id";
const TIMEOUT_MS = 6000;
const SECRET_KEY = ""; // Opsional: Samakan jika ingin dikunci

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
  const clientUA = req.headers.get("user-agent") || "no-user-agent";
  const reqUrl = new URL(req.url);

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
    console.warn(
      `[BLOCKED METHOD] IP: ${clientIp} | Method: ${req.method} | UA: ${clientUA}`
    );
    return new Response(JSON.stringify({ status: "method_not_allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 3. Cek Kunci Rahasia (Jika diaktifkan)
  if (SECRET_KEY && req.headers.get("x-proxy-key") !== SECRET_KEY) {
    console.warn(
      `[UNAUTHORIZED] IP: ${clientIp} | Target: ${reqUrl.search} | UA: ${clientUA}`
    );
    return new Response(JSON.stringify({ status: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const targetUrl = reqUrl.searchParams.get("url");

  // 4. Anti-Suspend Disguise + Log jika diakses tanpa ?url=
  if (!targetUrl) {
    console.log(
      `[PING / ROOT] IP: ${clientIp} | Path: ${reqUrl.pathname} | UA: ${clientUA}`
    );
    return new Response(
      JSON.stringify({ status: "online", service: "mangnime-komik-node" }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }

  // 5. Validasi Ketat Hostname & Protokol HTTPS
  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    console.warn(
      `[INVALID URL] IP: ${clientIp} | Target: ${targetUrl} | UA: ${clientUA}`
    );
    return new Response(JSON.stringify({ status: "invalid_request" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const targetHost = parsedTarget.hostname;
  if (
    parsedTarget.protocol !== "https:" ||
    (targetHost !== ALLOWED_DOMAIN && !targetHost.endsWith(`.${ALLOWED_DOMAIN}`))
  ) {
    console.warn(
      `[FORBIDDEN TARGET] IP: ${clientIp} | Mencoba akses ke: ${targetUrl} | UA: ${clientUA}`
    );
    return new Response(JSON.stringify({ status: "restricted" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 6. Spoofed Headers Chrome 129
  const spoofedHeaders = new Headers({
    Host: targetHost,
    Referer: `https://${targetHost}/`,
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    Accept:
      "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Sec-Ch-Ua":
      '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
  });

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(parsedTarget.toString(), {
      method: "GET",
      headers: spoofedHeaders,
      redirect: "follow",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;

    // LOG LENGKAP DI NETLIFY FUNCTION LOGS
    console.log(
      `[NETLIFY OK ${response.status}] (${duration}ms) | IP: ${clientIp} | Akses: ${parsedTarget.pathname}${parsedTarget.search} | UA: ${clientUA}`
    );

    return new Response(response.body, {
      status: response.status,
      headers: {
        "Content-Type":
          response.headers.get("Content-Type") || "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Cache-Control":
          "public, max-age=1800, s-maxage=1800, stale-while-revalidate=3600",
      },
    });
  } catch (error) {
    clearTimeout(timeoutId);
    const duration = Date.now() - startTime;
    const isTimeout = error.name === "AbortError";

    console.error(
      `[NETLIFY ERR ${isTimeout ? 504 : 502}] (${duration}ms) | IP: ${clientIp} | Akses: ${parsedTarget.pathname}${parsedTarget.search} | Err: ${error.message} | UA: ${clientUA}`
    );

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
        },
      }
    );
  }
};