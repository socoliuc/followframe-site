import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createReadStream, type Stats } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { basename, extname, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import {
  createMetricStore,
  type DownloadInterruptionPhase,
  type DownloadKind,
  type DownloadOutcome,
  type MetricStore,
} from "./metrics.ts";

const DEFAULT_PORT = 3000;
const MAX_HEARTBEAT_BYTES = 2_048;
const MAX_HEARTBEATS_PER_MINUTE = 120;
const DOWNLOAD_FILE_PATTERN = /^FollowFrame-Single-Exe-(\d+\.\d+\.\d+)-win32-x64\.exe(\.sha256)?$/;
const INSTALLATION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

const CONTENT_TYPES: Record<string, string> = {
  ".css": "text/css; charset=utf-8",
  ".exe": "application/octet-stream",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".mp4": "video/mp4",
  ".png": "image/png",
  ".sha256": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".webm": "video/webm",
  ".webp": "image/webp",
  ".xml": "application/xml; charset=utf-8",
};

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; base-uri 'self'; object-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self' https://www.googletagmanager.com; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com; font-src 'self'; media-src 'self'; frame-src 'none'; form-action 'self'",
  "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
};

type FetchLike = typeof fetch;
type StatLike = (path: string) => Promise<Stats>;

export function classifyDownloadInterruptionPhase(bytesRead: number, fileSize: number): DownloadInterruptionPhase {
  const progress = fileSize > 0 ? bytesRead / fileSize : 0;
  if (progress < 0.25) return "early";
  if (progress < 0.75) return "middle";
  return "late";
}

type ServerOptions = {
  staticRoot: string;
  measurementId?: string;
  apiSecret?: string;
  telemetryHashSecret?: string;
  alertCheckToken?: string;
  fetchImpl?: FetchLike;
  now?: () => number;
  metricsDatabasePath?: string;
  metricStore?: MetricStore;
  statImpl?: StatLike;
};

type HeartbeatPayload = {
  installationId: string;
  version: string;
  platform: "win32";
  architecture: "x64";
};

function applySecurityHeaders(response: ServerResponse): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    response.setHeader(name, value);
  }
}

function sendJson(response: ServerResponse, statusCode: number, value: unknown): void {
  applySecurityHeaders(response);
  response.statusCode = statusCode;
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.end(`${JSON.stringify(value)}\n`);
}

function hasValidBearerToken(request: IncomingMessage, expectedToken: string): boolean {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith("Bearer ")) {
    return false;
  }
  const supplied = Buffer.from(authorization.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function canonicalRedirectLocation(request: IncomingMessage, requestUrl: URL): string | null {
  const forwardedHost = request.headers["x-forwarded-host"];
  const rawHost = (Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost) ?? request.headers.host ?? "";
  const host = rawHost.split(",", 1)[0].trim().toLowerCase().replace(/:\d+$/, "");
  if (host !== "followframe.com" && host !== "www.followframe.com") return null;

  const forwardedProto = request.headers["x-forwarded-proto"];
  const proto = ((Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto) ?? "http")
    .split(",", 1)[0]
    .trim()
    .toLowerCase();
  if (host === "followframe.com" && proto === "https") return null;

  return `https://followframe.com${requestUrl.pathname}${requestUrl.search}`;
}

function sendPermanentRedirect(response: ServerResponse, location: string): void {
  applySecurityHeaders(response);
  response.statusCode = 308;
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Location", location);
  response.end();
}

function parseHeartbeat(value: unknown): HeartbeatPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  const payload = value as Record<string, unknown>;
  if (
    typeof payload.installationId !== "string" ||
    !INSTALLATION_ID_PATTERN.test(payload.installationId) ||
    typeof payload.version !== "string" ||
    !VERSION_PATTERN.test(payload.version) ||
    payload.platform !== "win32" ||
    payload.architecture !== "x64"
  ) {
    return null;
  }

  return payload as HeartbeatPayload;
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;

  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.length;
    if (totalBytes > MAX_HEARTBEAT_BYTES) {
      throw new Error("payload-too-large");
    }
    chunks.push(buffer);
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function analyticsClientId(value: string, secret: string): string {
  const digest = createHmac("sha256", secret).update(value).digest();
  return `${digest.readUInt32BE(0)}.${digest.readUInt32BE(4)}`;
}

function telemetryDigest(value: string, secret: string): string {
  return createHmac("sha256", secret).update(value).digest("hex");
}

async function sendAnalyticsEvent({
  measurementId,
  apiSecret,
  clientId,
  eventName,
  params,
  fetchImpl,
}: {
  measurementId: string;
  apiSecret: string;
  clientId: string;
  eventName: string;
  params: Record<string, string | number>;
  fetchImpl: FetchLike;
}): Promise<boolean> {
  const endpoint = new URL("https://www.google-analytics.com/mp/collect");
  endpoint.searchParams.set("measurement_id", measurementId);
  endpoint.searchParams.set("api_secret", apiSecret);

  const analyticsResponse = await fetchImpl(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      non_personalized_ads: true,
      events: [{ name: eventName, params }],
    }),
    signal: AbortSignal.timeout(5_000),
  });

  return analyticsResponse.ok;
}

function cacheControlFor(pathname: string): string {
  if (/\/assets\/[^/]+-[A-Za-z0-9_-]+\.(?:css|js)$/.test(pathname)) {
    return "public, max-age=31536000, immutable";
  }
  if (pathname.endsWith(".html") || pathname === "/") {
    return "no-cache";
  }
  return "public, max-age=3600";
}

function staticFilePath(staticRoot: string, pathname: string): string | null {
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    return null;
  }

  const relativePath = decodedPath === "/"
    ? "index.html"
    : decodedPath.endsWith("/")
      ? `${decodedPath.slice(1)}index.html`
      : decodedPath.slice(1);
  const candidate = resolve(staticRoot, relativePath);
  const rootWithSeparator = `${resolve(staticRoot)}${sep}`;
  return candidate.startsWith(rootWithSeparator) ? candidate : null;
}

function parseSingleRange(rangeHeader: string, fileSize: number): { start: number; end: number } | null {
  const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
  if (!match) {
    return null;
  }

  const [, startValue, endValue] = match;
  if (!startValue && !endValue) {
    return null;
  }

  if (!startValue) {
    const suffixLength = Number(endValue);
    if (!Number.isInteger(suffixLength) || suffixLength <= 0) {
      return null;
    }
    return { start: Math.max(fileSize - suffixLength, 0), end: fileSize - 1 };
  }

  const start = Number(startValue);
  const end = endValue ? Number(endValue) : fileSize - 1;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || start >= fileSize || end < start) {
    return null;
  }
  return { start, end: Math.min(end, fileSize - 1) };
}

async function serveStaticFile({
  request,
  response,
  staticRoot,
  onDownloadStarted,
  onDownloadOutcome,
  statImpl,
}: {
  request: IncomingMessage;
  response: ServerResponse;
  staticRoot: string;
  onDownloadStarted: (kind: DownloadKind, version: string) => void;
  onDownloadOutcome: (
    kind: DownloadKind,
    outcome: DownloadOutcome,
    fileName: string,
    version: string,
    fileSize: number,
    phase?: DownloadInterruptionPhase,
  ) => void;
  statImpl: StatLike;
}): Promise<void> {
  const requestUrl = new URL(request.url ?? "/", "http://localhost");
  const filePath = staticFilePath(staticRoot, requestUrl.pathname);
  if (!filePath) {
    sendJson(response, 400, { error: "invalid_path" });
    return;
  }

  let fileStat;
  try {
    fileStat = await statImpl(filePath);
  } catch {
    sendJson(response, 404, { error: "not_found" });
    return;
  }

  if (fileStat.isDirectory() && !requestUrl.pathname.endsWith("/")) {
    try {
      const indexStat = await statImpl(resolve(filePath, "index.html"));
      if (indexStat.isFile()) {
        sendPermanentRedirect(response, `${requestUrl.pathname}/${requestUrl.search}`);
        return;
      }
    } catch {
      // Directories without an index remain a normal not-found response.
    }
  }

  if (!fileStat.isFile()) {
    sendJson(response, 404, { error: "not_found" });
    return;
  }

  applySecurityHeaders(response);
  response.setHeader("Accept-Ranges", "bytes");
  response.setHeader("Cache-Control", cacheControlFor(requestUrl.pathname));
  response.setHeader("Content-Type", CONTENT_TYPES[extname(filePath).toLowerCase()] ?? "application/octet-stream");

  const rangeHeader = request.headers.range;
  if (rangeHeader) {
    const range = parseSingleRange(rangeHeader, fileStat.size);
    if (!range) {
      response.statusCode = 416;
      response.setHeader("Content-Range", `bytes */${fileStat.size}`);
      response.end();
      return;
    }

    response.statusCode = 206;
    response.setHeader("Content-Range", `bytes ${range.start}-${range.end}/${fileStat.size}`);
    response.setHeader("Content-Length", String(range.end - range.start + 1));
    if (request.method === "HEAD") {
      response.end();
      return;
    }
    createReadStream(filePath, range).pipe(response);
    return;
  }

  response.statusCode = 200;
  response.setHeader("Content-Length", String(fileStat.size));
  if (request.method === "HEAD") {
    response.end();
    return;
  }

  const downloadMatch = DOWNLOAD_FILE_PATTERN.exec(basename(filePath));
  if (!downloadMatch) {
    createReadStream(filePath).pipe(response);
    return;
  }

  const kind: DownloadKind = downloadMatch[2] ? "checksum" : "exe";
  const fileName = downloadMatch[0];
  const version = downloadMatch[1];
  if (response.destroyed) {
    return;
  }
  const stream = createReadStream(filePath);
  let terminalOutcomeRecorded = false;
  const recordOutcome = (outcome: DownloadOutcome) => {
    if (terminalOutcomeRecorded) return;
    terminalOutcomeRecorded = true;
    const phase = kind === "exe" && outcome === "interrupted"
      ? classifyDownloadInterruptionPhase(stream.bytesRead, fileStat.size)
      : undefined;
    onDownloadOutcome(kind, outcome, fileName, version, fileStat.size, phase);
  };

  onDownloadStarted(kind, version);
  response.once("finish", () => recordOutcome("completed"));
  response.once("close", () => recordOutcome("interrupted"));
  stream.once("error", (error) => {
    recordOutcome("failed");
    response.destroy(error);
  });
  stream.pipe(response);
}

export function createProductionServer(options: ServerOptions): Server {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const analyticsConfigured = Boolean(options.measurementId && options.apiSecret && options.telemetryHashSecret);
  const metricsDatabasePath = options.metricsDatabasePath ?? ":memory:";
  const metricsPersistenceConfigured = metricsDatabasePath !== ":memory:";
  const metricStore = options.metricStore ?? createMetricStore(metricsDatabasePath);
  const alertCheckToken = options.alertCheckToken || undefined;
  let heartbeatWindowStartedAt = now();
  let heartbeatWindowCount = 0;

  function emitAnalytics(clientId: string, eventName: string, params: Record<string, string | number>): void {
    if (!analyticsConfigured) {
      return;
    }
    void sendAnalyticsEvent({
      measurementId: options.measurementId!,
      apiSecret: options.apiSecret!,
      clientId,
      eventName,
      params,
      fetchImpl,
    }).catch(() => undefined);
  }

  function onCompletedDownload(fileName: string, version: string, fileSize: number): void {
    try {
      metricStore.recordCompletedDownload(version, now());
    } catch (error) {
      console.error("FollowFrame download metric persistence failed", error);
    }
    if (!analyticsConfigured) {
      return;
    }
    emitAnalytics(analyticsClientId(randomUUID(), options.telemetryHashSecret!), "file_download_completed", {
      file_name: fileName,
      file_extension: "exe",
      app_version: version,
      file_size: fileSize,
      engagement_time_msec: 1,
      session_id: Math.floor(Date.now() / 1_000),
    });
  }

  function onDownloadOutcome(
    kind: DownloadKind,
    outcome: DownloadOutcome,
    fileName: string,
    version: string,
    fileSize: number,
    phase?: DownloadInterruptionPhase,
  ): void {
    try {
      metricStore.recordDownloadOutcome(kind, outcome, version, now());
      if (kind === "exe" && outcome === "interrupted" && phase) {
        metricStore.recordDownloadInterruptionPhase(phase, version, now());
      }
    } catch (error) {
      console.error("FollowFrame download metric persistence failed", error);
    }
    if (kind === "exe" && outcome === "completed") {
      onCompletedDownload(fileName, version, fileSize);
    }
  }

  const server = createServer(async (request, response) => {
    const method = request.method ?? "GET";
    const requestUrl = new URL(request.url ?? "/", "http://localhost");

    const redirectLocation = canonicalRedirectLocation(request, requestUrl);
    if (redirectLocation) {
      sendPermanentRedirect(response, redirectLocation);
      return;
    }

    if (requestUrl.pathname === "/api/health" && method === "GET") {
      const day = new Date(now()).toISOString().slice(0, 10);
      try {
        sendJson(response, 200, {
          status: "ok",
          analyticsConfigured,
          metricsPersistenceConfigured,
          downloadDelivery: { day, ...metricStore.readDownloadDelivery(day) },
        });
      } catch {
        sendJson(response, 503, {
          status: "unavailable",
          error: "metrics_unavailable",
        });
      }
      return;
    }

    if (requestUrl.pathname === "/api/ops/download-delivery-alert-check" && method === "GET") {
      if (!alertCheckToken) {
        sendJson(response, 404, { error: "not_found" });
        return;
      }
      if (!hasValidBearerToken(request, alertCheckToken)) {
        response.setHeader("WWW-Authenticate", "Bearer");
        sendJson(response, 401, { error: "unauthorized" });
        return;
      }

      const day = new Date(now() - 24 * 60 * 60 * 1_000).toISOString().slice(0, 10);
      try {
        const delivery = metricStore.readDownloadDelivery(day);
        const failed = delivery.exe.failed + delivery.checksum.failed;
        const interrupted = delivery.exe.interrupted + delivery.checksum.interrupted;
        const alert = failed > 0 || interrupted > 0;
        sendJson(response, alert ? 503 : 200, {
          status: alert ? "alert" : "ok",
          day,
          failed,
          interrupted,
          delivery,
          exeInterruptionPhases: metricStore.readDownloadInterruptionPhases(day),
        });
      } catch {
        sendJson(response, 503, { status: "check_failed" });
      }
      return;
    }

    if (requestUrl.pathname === "/api/telemetry/heartbeat") {
      if (method !== "POST") {
        applySecurityHeaders(response);
        response.statusCode = 405;
        response.setHeader("Allow", "POST");
        response.end();
        return;
      }

      let payload: HeartbeatPayload | null;
      try {
        payload = parseHeartbeat(await readJsonBody(request));
      } catch {
        sendJson(response, 400, { error: "invalid_payload" });
        return;
      }
      if (!payload) {
        sendJson(response, 400, { error: "invalid_payload" });
        return;
      }

      if (now() - heartbeatWindowStartedAt >= 60_000) {
        heartbeatWindowStartedAt = now();
        heartbeatWindowCount = 0;
      }
      if (heartbeatWindowCount >= MAX_HEARTBEATS_PER_MINUTE) {
        sendJson(response, 429, { error: "rate_limited" });
        return;
      }
      heartbeatWindowCount += 1;

      if (analyticsConfigured) {
        const clientId = analyticsClientId(payload.installationId, options.telemetryHashSecret!);
        const digest = telemetryDigest(payload.installationId, options.telemetryHashSecret!);
        let firstActiveHeartbeat: boolean;
        try {
          firstActiveHeartbeat = metricStore.recordActiveInstallation(digest, payload.version, now());
        } catch (error) {
          console.error("FollowFrame active-use metric persistence failed", error);
          sendJson(response, 503, { error: "telemetry_unavailable" });
          return;
        }
        if (firstActiveHeartbeat) {
          emitAnalytics(clientId, "app_active", {
            app_version: payload.version,
            operating_system: "Windows",
            architecture: payload.architecture,
            telemetry_consent: "opt_in",
            engagement_time_msec: 1,
            session_id: Math.floor(now() / 1_000),
          });
        }
      }

      applySecurityHeaders(response);
      response.statusCode = 204;
      response.setHeader("Cache-Control", "no-store");
      response.end();
      return;
    }

    if (method !== "GET" && method !== "HEAD") {
      applySecurityHeaders(response);
      response.statusCode = 405;
      response.setHeader("Allow", "GET, HEAD");
      response.end();
      return;
    }

    await serveStaticFile({
      request,
      response,
      staticRoot: options.staticRoot,
      onDownloadStarted: (kind, version) => {
        try {
          metricStore.recordDownloadStarted(kind, version, now());
        } catch (error) {
          console.error("FollowFrame download metric persistence failed", error);
        }
      },
      onDownloadOutcome,
      statImpl: options.statImpl ?? stat,
    });
  });
  server.once("close", () => metricStore.close());
  return server;
}

function startProductionServer(): void {
  const staticRoot = resolve(process.env.STATIC_ROOT ?? "site-dist");
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  const productionServer = createProductionServer({
    staticRoot,
    measurementId: process.env.GA_MEASUREMENT_ID,
    apiSecret: process.env.GA_API_SECRET,
    telemetryHashSecret: process.env.TELEMETRY_HASH_SECRET,
    alertCheckToken: process.env.FOLLOWFRAME_ALERT_CHECK_TOKEN,
    metricsDatabasePath: process.env.METRICS_DB_PATH ?? "/app/data/followframe-metrics.sqlite",
  });
  productionServer.listen(port, "0.0.0.0", () => {
    console.log(`FollowFrame site listening on port ${port}`);
  });
}

const entryPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === entryPath) {
  startProductionServer();
}
