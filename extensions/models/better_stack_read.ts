/**
 * Bounded, read-only collection from Better Stack Uptime, Telemetry, Errors,
 * and ClickHouse-compatible SQL APIs.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Published CalVer for the Better Stack read model. */
export const BETTER_STACK_READ_MODEL_VERSION = "2026.08.18.7" as const;

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 1_000_000;
const MAX_PAGES = 5;
const MAX_WINDOW_SECONDS = 86_400;
const MAX_AGGREGATE_ROWS = 20;
const MAX_DIAGNOSTIC_ROWS = 200;
const MAX_DIAGNOSTIC_GROUPS = 25;
const Identifier = z.string().min(1).max(200);
const Timestamp = z.iso.datetime({ offset: true });
const NullableTimestamp = Timestamp.nullable();
const Count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const SafeToken = z.string().min(1).max(50).regex(/^[a-z0-9_.-]+$/);
const SafeText = z.string().min(1).max(500);
const NullableComponent = z.string().max(120).regex(/^[A-Za-z0-9_:#/.-]+$/)
  .nullable();

const sqlEndpointSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.protocol === "https:" &&
    url.hostname.endsWith(".betterstackdata.com") &&
    url.username === "" && url.password === "" && url.pathname === "/" &&
    url.search === "" && url.hash === "";
}, "SQL endpoint must be a credential-free Better Stack HTTPS origin");

/** Validated credentials and source configuration for every collection method. */
export const globalArgumentsSchema = z.strictObject({
  uptimeApiToken: z.string().min(1).max(4_096).meta({ sensitive: true }),
  telemetryApiToken: z.string().min(1).max(4_096).meta({ sensitive: true }),
  sqlEndpoint: sqlEndpointSchema,
  sqlUsername: z.string().min(1).max(200).regex(/^[\x21-\x7e]+$/).meta({
    sensitive: true,
  }),
  sqlPassword: z.string().min(1).max(1_000).regex(/^[\x20-\x7e]+$/).meta({
    sensitive: true,
  }),
  logsTable: z.string().max(200).regex(/^t\d+_[a-z0-9_]+_logs$/),
});

/** A bounded UTC interval accepted by collection methods. */
export const collectArgumentsSchema = z.object({
  windowStartedAt: Timestamp,
  windowEndedAt: Timestamp,
}).superRefine((value, context) => {
  const started = Date.parse(value.windowStartedAt);
  const ended = Date.parse(value.windowEndedAt);
  if (started >= ended) {
    context.addIssue({
      code: "custom",
      path: ["windowEndedAt"],
      message: "windowEndedAt must be after windowStartedAt",
    });
  }
  if ((ended - started) / 1_000 > MAX_WINDOW_SECONDS) {
    context.addIssue({
      code: "custom",
      path: ["windowEndedAt"],
      message: "collection window cannot exceed 24 hours",
    });
  }
});
// Swamp supplies configured global arguments to no-input workflow steps during
// method-argument validation. Accept exactly that known shape while the method
// continues to derive its rolling window internally.
const collectDailyArgumentsSchema = globalArgumentsSchema;

const Monitor = z.strictObject({
  id: Identifier,
  name: z.string().min(1).max(200),
  status: SafeToken,
  lastCheckedAt: NullableTimestamp,
  paused: z.boolean(),
});
const Heartbeat = z.strictObject({
  id: Identifier,
  name: z.string().min(1).max(200),
  status: SafeToken,
  paused: z.boolean(),
});
const Incident = z.strictObject({
  id: Identifier,
  name: z.string().min(1).max(200),
  cause: z.string().min(1).max(300),
  status: SafeToken,
  startedAt: NullableTimestamp,
  acknowledgedAt: NullableTimestamp,
  resolvedAt: NullableTimestamp,
  relatedResourceType: z.enum(["monitor", "heartbeat", "webhook", "unknown"]),
  relatedResourceId: Identifier.nullable(),
});
const InventoryItem = z.strictObject({
  id: Identifier,
  platform: SafeToken,
  ingestingPaused: z.boolean(),
  dataRegion: SafeToken,
});
const BoundedCollection = <T extends z.ZodType>(item: T, maximum: number) =>
  z.strictObject({
    items: z.array(item).max(maximum),
    truncated: z.boolean(),
  });

/** Persisted, minimized operational metadata schema. */
export const operationalSnapshotSchema = z.strictObject({
  schemaVersion: z.literal("1.0"),
  generatedAt: Timestamp,
  windowStartedAt: Timestamp,
  windowEndedAt: Timestamp,
  monitors: BoundedCollection(Monitor, 250),
  heartbeats: BoundedCollection(Heartbeat, 250),
  incidents: BoundedCollection(Incident, 500),
  telemetrySources: BoundedCollection(InventoryItem, 250),
  errorApplications: BoundedCollection(InventoryItem, 300),
  contentTrust: z.literal("untrusted-evidence"),
  minimization: z.strictObject({
    arbitraryTextRetained: z.literal(false),
    sanitizedTextRetained: z.literal(true),
    urlsRetained: z.literal(false),
    requestContentRetained: z.literal(false),
    credentialsRetained: z.literal(false),
  }),
  authority: z.strictObject({
    mode: z.literal("read-only"),
    sideEffects: z.literal("none"),
  }),
});

/** Persisted fixed-query severity aggregate schema. */
export const logAggregateSnapshotSchema = z.strictObject({
  schemaVersion: z.literal("1.0"),
  generatedAt: Timestamp,
  windowStartedAt: Timestamp,
  windowEndedAt: Timestamp,
  groups: z.array(z.strictObject({ severity: SafeToken, count: Count })).max(
    MAX_AGGREGATE_ROWS,
  ),
  returnedRows: Count.max(MAX_AGGREGATE_ROWS),
  returnedBytes: Count.max(MAX_RESPONSE_BYTES),
  queryFingerprint: z.literal("severity-count-v1"),
  rawLogsRetrieved: z.literal(false),
  truncated: z.boolean(),
  authority: z.strictObject({
    mode: z.literal("read-only"),
    sideEffects: z.literal("none"),
  }),
});

/** Persisted, grouped diagnostic evidence after deterministic redaction. */
export const diagnosticSnapshotSchema = z.strictObject({
  schemaVersion: z.literal("1.0"),
  generatedAt: Timestamp,
  windowStartedAt: Timestamp,
  windowEndedAt: Timestamp,
  groups: z.array(z.strictObject({
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    severity: SafeToken,
    errorClass: NullableComponent,
    component: NullableComponent,
    summary: SafeText,
    firstSeenAt: Timestamp,
    lastSeenAt: Timestamp,
    occurrences: Count.max(MAX_DIAGNOSTIC_ROWS),
    redactionCount: Count,
    promptInjectionDetected: z.boolean(),
  })).max(MAX_DIAGNOSTIC_GROUPS),
  returnedRows: Count.max(MAX_DIAGNOSTIC_ROWS),
  returnedBytes: Count.max(MAX_RESPONSE_BYTES),
  queryFingerprint: z.literal("bounded-error-diagnostics-v1"),
  truncated: z.boolean(),
  contentTrust: z.literal("untrusted-evidence"),
  minimization: z.strictObject({
    rawLogRecordsPersisted: z.literal(false),
    requestContentPersisted: z.literal(false),
    urlsPersisted: z.literal(false),
    credentialsPersisted: z.literal(false),
    longIdentifiersPersisted: z.literal(false),
    deterministicRedactionApplied: z.literal(true),
  }),
  authority: z.strictObject({
    mode: z.literal("read-only"),
    sideEffects: z.literal("none"),
    rawTelemetryRead: z.literal(true),
    rawTelemetryPersisted: z.literal(false),
    remediation: z.literal("prohibited"),
  }),
});

/** One atomic rolling-window resource for scheduled deterministic workflows. */
export const dailySnapshotSchema = z.strictObject({
  schemaVersion: z.literal("1.0"),
  generatedAt: Timestamp,
  windowStartedAt: Timestamp,
  windowEndedAt: Timestamp,
  operationalSnapshot: operationalSnapshotSchema,
  diagnosticSnapshot: diagnosticSnapshotSchema,
  authority: z.strictObject({
    mode: z.literal("read-only"),
    sideEffects: z.literal("none"),
    remediation: z.literal("prohibited"),
  }),
});

type GlobalArguments = z.infer<typeof globalArgumentsSchema>;
type CollectArguments = z.infer<typeof collectArgumentsSchema>;
/** Output produced by {@link collectOperationalSnapshot}. */
export type OperationalSnapshot = z.infer<typeof operationalSnapshotSchema>;
/** Output produced by {@link collectLogAggregateSnapshot}. */
export type LogAggregateSnapshot = z.infer<typeof logAggregateSnapshotSchema>;
/** Output produced by {@link collectDiagnosticSnapshot}. */
export type DiagnosticSnapshot = z.infer<typeof diagnosticSnapshotSchema>;
/** Atomic output produced by {@link collectDailySnapshot}. */
export type DailySnapshot = z.infer<typeof dailySnapshotSchema>;
type Fetcher = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;
type JsonApiItem = {
  id: string;
  type?: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<string, unknown>;
};

type WriteContext = {
  globalArgs: GlobalArguments;
  writeResource: (
    spec: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<unknown>;
};

function token(value: unknown): string {
  return typeof value === "string" &&
      /^[a-z0-9_.-]{1,50}$/.test(value.toLowerCase())
    ? value.toLowerCase()
    : "unknown";
}

function nullableTimestamp(value: unknown): string | null {
  return typeof value === "string" && Timestamp.safeParse(value).success
    ? value
    : null;
}

type SanitizedText = {
  value: string;
  redactionCount: number;
  promptInjectionDetected: boolean;
};

/** Deterministically removes common credentials, identifiers, and prompt-like instructions. */
export function sanitizeEvidenceText(
  value: unknown,
  maximum = 500,
): SanitizedText {
  let text = typeof value === "string" ? value : "";
  let redactionCount = 0;
  let promptInjectionDetected = false;
  const replace = (pattern: RegExp, replacement: string) => {
    text = text.replace(pattern, () => {
      redactionCount += 1;
      return replacement;
    });
  };
  const promptPattern =
    /\b(?:ignore|disregard|override|forget)\b.{0,40}\b(?:instruction|prompt|policy|system)\b/gi;
  if (promptPattern.test(text)) {
    promptInjectionDetected = true;
    promptPattern.lastIndex = 0;
    replace(promptPattern, "<untrusted-instruction>");
  }
  replace(/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "<credential>");
  replace(
    /\b(?:api[-_ ]?key|authorization|password|secret|token)\s*[:=]\s*[^\s,;]+/gi,
    "<credential>",
  );
  replace(
    /\b(?:parameters?|params|request[_ -]?body)\s*[:=]\s*.+$/gi,
    "<request-content>",
  );
  replace(/https?:\/\/[^\s)\]}>]+/gi, "<url>");
  replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "<email>");
  replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "<ip>");
  replace(
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
    "<uuid>",
  );
  replace(/\+?\d[\d ().-]{8,}\d/g, "<phone>");
  replace(/\b[A-Za-z0-9_-]{32,}\b/g, "<long-identifier>");
  replace(/\b\d{7,}\b/g, "<numeric-identifier>");
  text = text.replace(/\s+/g, " ").trim();
  if (!text) text = "No diagnostic message provided";
  return {
    value: text.slice(0, Math.max(1, maximum)),
    redactionCount,
    promptInjectionDetected,
  };
}

function normalizeDiagnosticFingerprintText(value: string): string {
  return value
    .replace(
      /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b/gi,
      "<timestamp>",
    )
    .replace(
      /\b(?:job[ _-]?id|jid)\s*[:=]\s*(?:<[^>]+>|[A-Za-z0-9_-]+)/gi,
      "job-id=<identifier>",
    )
    .replace(
      /\b\d+(?:\.\d+)?\s*(?:milliseconds?|ms|seconds?|secs?|s)\b/gi,
      "<duration>",
    )
    .replace(/(\.[A-Za-z0-9_]+):\d+\b/g, "$1:<line>")
    .replace(/\bline\s+\d+\b/gi, "line <line>")
    .replace(
      /<(?:uuid|long-identifier|numeric-identifier|redacted|filtered)>/gi,
      "<identifier>",
    );
}

function component(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  return /^[A-Za-z0-9_:#/.-]{1,120}$/.test(normalized) ? normalized : null;
}

async function fingerprint(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)].map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function boundedBody(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE_BYTES) {
    throw new Error("Better Stack response exceeded the byte limit");
  }
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error("Better Stack response exceeded the byte limit");
  }
  return body;
}

function validatedNext(
  value: unknown,
  expectedOrigin: string,
  expectedPath: string,
): URL | null {
  if (value === null || value === undefined) return null;
  const next = new URL(z.url().parse(value));
  if (
    next.origin !== expectedOrigin || next.pathname !== expectedPath ||
    next.username || next.password || next.hash
  ) {
    throw new Error("Better Stack returned an unsafe pagination URL");
  }
  return next;
}

async function fetchJsonApiPages(
  origin: string,
  path: string,
  tokenValue: string,
  perPage: number,
  parameters: Record<string, string>,
  fetcher: Fetcher,
): Promise<{ items: JsonApiItem[]; truncated: boolean }> {
  const first = new URL(path, origin);
  first.searchParams.set("per_page", String(perPage));
  Object.entries(parameters).forEach(([key, value]) =>
    first.searchParams.set(key, value)
  );
  let next: URL | null = first;
  const items: JsonApiItem[] = [];
  for (let page = 0; page < MAX_PAGES && next !== null; page += 1) {
    const response = await fetcher(next, {
      headers: {
        authorization: `Bearer ${tokenValue}`,
        accept: "application/json",
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`Better Stack read failed with HTTP ${response.status}`);
    }
    const parsed = JSON.parse(await boundedBody(response));
    const data = z.array(z.object({
      id: z.coerce.string().min(1).max(200),
      type: z.string().max(100).optional(),
      attributes: z.record(z.string(), z.unknown()).optional(),
      relationships: z.record(z.string(), z.unknown()).optional(),
    })).max(perPage).parse(parsed.data);
    items.push(...data);
    next = validatedNext(parsed.pagination?.next, first.origin, first.pathname);
  }
  return { items, truncated: next !== null };
}

function relationship(
  relationships: Record<string, unknown> | undefined,
): {
  type: "monitor" | "heartbeat" | "webhook" | "unknown";
  id: string | null;
} {
  if (!relationships) return { type: "unknown", id: null };
  for (
    const candidate of ["monitor", "heartbeat", "webhook_integration"] as const
  ) {
    const parsed = z.object({
      data: z.object({ id: z.coerce.string().min(1).max(200) }).nullable(),
    }).safeParse(relationships[candidate]);
    if (parsed.success && parsed.data.data) {
      return {
        type: candidate === "webhook_integration" ? "webhook" : candidate,
        id: parsed.data.data.id,
      };
    }
  }
  return { type: "unknown", id: null };
}

function uniqueById<T extends { id: string }>(items: T[]): T[] {
  return [...new Map(items.map((item) => [item.id, item])).values()];
}

/**
 * Fetches bounded operational API pages and returns only allowlisted fields.
 * Arbitrary text, URLs, request content, and credentials are discarded.
 */
export async function collectOperationalSnapshot(
  config: GlobalArguments,
  args: CollectArguments,
  fetcher: Fetcher,
  generatedAt = new Date().toISOString(),
): Promise<OperationalSnapshot> {
  const parsedConfig = globalArgumentsSchema.parse(config);
  const parsedArgs = collectArgumentsSchema.parse(args);
  if (
    Date.parse(parsedArgs.windowEndedAt) > Date.parse(generatedAt) + 300_000
  ) {
    throw new Error(
      "windowEndedAt cannot be more than five minutes in the future",
    );
  }
  const from = parsedArgs.windowStartedAt.slice(0, 10);
  const to = parsedArgs.windowEndedAt.slice(0, 10);
  const [
    monitors,
    heartbeats,
    activeIncidents,
    recentIncidents,
    sources,
    applications,
  ] = await Promise.all([
    fetchJsonApiPages(
      "https://uptime.betterstack.com",
      "/api/v2/monitors",
      parsedConfig.uptimeApiToken,
      50,
      {},
      fetcher,
    ),
    fetchJsonApiPages(
      "https://uptime.betterstack.com",
      "/api/v2/heartbeats",
      parsedConfig.uptimeApiToken,
      50,
      {},
      fetcher,
    ),
    fetchJsonApiPages(
      "https://uptime.betterstack.com",
      "/api/v3/incidents",
      parsedConfig.uptimeApiToken,
      50,
      { resolved: "false" },
      fetcher,
    ),
    fetchJsonApiPages(
      "https://uptime.betterstack.com",
      "/api/v3/incidents",
      parsedConfig.uptimeApiToken,
      50,
      { from, to },
      fetcher,
    ),
    fetchJsonApiPages(
      "https://telemetry.betterstack.com",
      "/api/v2/sources",
      parsedConfig.telemetryApiToken,
      50,
      {},
      fetcher,
    ),
    fetchJsonApiPages(
      "https://errors.betterstack.com",
      "/api/v2/applications",
      parsedConfig.telemetryApiToken,
      100,
      {},
      fetcher,
    ),
  ]);

  const incidents = uniqueById([
    ...activeIncidents.items,
    ...recentIncidents.items,
  ]);
  return operationalSnapshotSchema.parse({
    schemaVersion: "1.0",
    generatedAt,
    windowStartedAt: parsedArgs.windowStartedAt,
    windowEndedAt: parsedArgs.windowEndedAt,
    monitors: {
      items: monitors.items.map((item) => ({
        id: item.id,
        name: sanitizeEvidenceText(
          item.attributes?.pronounceable_name,
          200,
        ).value,
        status: token(item.attributes?.status),
        lastCheckedAt: nullableTimestamp(item.attributes?.last_checked_at),
        paused: item.attributes?.paused_at !== null &&
          item.attributes?.paused_at !== undefined,
      })),
      truncated: monitors.truncated,
    },
    heartbeats: {
      items: heartbeats.items.map((item) => ({
        id: item.id,
        name: sanitizeEvidenceText(item.attributes?.name, 200).value,
        status: token(item.attributes?.status),
        paused: item.attributes?.paused_at !== null &&
          item.attributes?.paused_at !== undefined,
      })),
      truncated: heartbeats.truncated,
    },
    incidents: {
      items: incidents.map((item) => {
        const related = relationship(item.relationships);
        return {
          id: item.id,
          name: sanitizeEvidenceText(item.attributes?.name, 200).value,
          cause: sanitizeEvidenceText(item.attributes?.cause, 300).value,
          status: token(item.attributes?.status),
          startedAt: nullableTimestamp(item.attributes?.started_at),
          acknowledgedAt: nullableTimestamp(item.attributes?.acknowledged_at),
          resolvedAt: nullableTimestamp(item.attributes?.resolved_at),
          relatedResourceType: related.type,
          relatedResourceId: related.id,
        };
      }),
      truncated: activeIncidents.truncated || recentIncidents.truncated,
    },
    telemetrySources: {
      items: sources.items.map((item) => ({
        id: item.id,
        platform: token(item.attributes?.platform),
        ingestingPaused: item.attributes?.ingesting_paused === true,
        dataRegion: token(item.attributes?.data_region),
      })),
      truncated: sources.truncated,
    },
    errorApplications: {
      items: applications.items.map((item) => ({
        id: item.id,
        platform: token(item.attributes?.platform),
        ingestingPaused: item.attributes?.ingesting_paused === true,
        dataRegion: token(item.attributes?.data_region),
      })),
      truncated: applications.truncated,
    },
    contentTrust: "untrusted-evidence",
    minimization: {
      arbitraryTextRetained: false,
      sanitizedTextRetained: true,
      urlsRetained: false,
      requestContentRetained: false,
      credentialsRetained: false,
    },
    authority: { mode: "read-only", sideEffects: "none" },
  });
}

function sqlQuery(config: GlobalArguments, args: CollectArguments): string {
  const historicalTable = config.logsTable.replace(/_logs$/, "_s3");
  return `SELECT
  multiIf(
    lowerUTF8(coalesce(nullIf(JSONExtractString(raw, 'level'), ''), nullIf(JSONExtractString(raw, 'severity'), ''), 'unknown')) IN ('trace','debug','info','notice','warn','warning','error','fatal','critical','alert','emergency'),
    lowerUTF8(coalesce(nullIf(JSONExtractString(raw, 'level'), ''), nullIf(JSONExtractString(raw, 'severity'), ''), 'unknown')),
    'unknown'
  ) AS severity,
  count() AS count
FROM (
  SELECT dt, raw FROM remote(${config.logsTable})
  WHERE dt >= parseDateTime64BestEffort('${args.windowStartedAt}') AND dt < parseDateTime64BestEffort('${args.windowEndedAt}')
  UNION ALL
  SELECT dt, raw FROM s3Cluster(primary, ${historicalTable})
  WHERE _row_type = 1 AND dt >= parseDateTime64BestEffort('${args.windowStartedAt}') AND dt < parseDateTime64BestEffort('${args.windowEndedAt}')
)
GROUP BY severity
ORDER BY count DESC, severity ASC
LIMIT ${MAX_AGGREGATE_ROWS}
FORMAT JSONEachRow`;
}

/**
 * Executes the extension's fixed severity-count query and returns aggregates.
 * Callers cannot supply SQL, grouping fields, or projections.
 */
export async function collectLogAggregateSnapshot(
  config: GlobalArguments,
  args: CollectArguments,
  fetcher: Fetcher,
  generatedAt = new Date().toISOString(),
): Promise<LogAggregateSnapshot> {
  const parsedConfig = globalArgumentsSchema.parse(config);
  const parsedArgs = collectArgumentsSchema.parse(args);
  if (
    Date.parse(parsedArgs.windowEndedAt) > Date.parse(generatedAt) + 300_000
  ) {
    throw new Error(
      "windowEndedAt cannot be more than five minutes in the future",
    );
  }
  const url = new URL(parsedConfig.sqlEndpoint);
  url.searchParams.set("output_format_pretty_row_numbers", "0");
  url.searchParams.set("max_result_rows", String(MAX_AGGREGATE_ROWS));
  url.searchParams.set("max_result_bytes", String(MAX_RESPONSE_BYTES));
  const response = await fetcher(url, {
    method: "POST",
    headers: {
      authorization: `Basic ${
        btoa(`${parsedConfig.sqlUsername}:${parsedConfig.sqlPassword}`)
      }`,
      "content-type": "text/plain",
    },
    body: sqlQuery(parsedConfig, parsedArgs),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `Better Stack SQL read failed with HTTP ${response.status}`,
    );
  }
  const body = await boundedBody(response);
  const groups = body.trim() === ""
    ? []
    : body.trim().split("\n").map((line) => {
      const row = JSON.parse(line);
      return {
        severity: SafeToken.parse(row.severity),
        count: z.coerce.number().int().nonnegative().parse(row.count),
      };
    });
  return logAggregateSnapshotSchema.parse({
    schemaVersion: "1.0",
    generatedAt,
    windowStartedAt: parsedArgs.windowStartedAt,
    windowEndedAt: parsedArgs.windowEndedAt,
    groups,
    returnedRows: groups.length,
    returnedBytes: new TextEncoder().encode(body).byteLength,
    queryFingerprint: "severity-count-v1",
    rawLogsRetrieved: false,
    truncated: groups.length === MAX_AGGREGATE_ROWS,
    authority: { mode: "read-only", sideEffects: "none" },
  });
}

function diagnosticSqlQuery(
  config: GlobalArguments,
  args: CollectArguments,
): string {
  const historicalTable = config.logsTable.replace(/_logs$/, "_s3");
  const severity =
    `lowerUTF8(coalesce(nullIf(JSONExtractString(raw, 'level'), ''), nullIf(JSONExtractString(raw, 'severity'), ''), 'unknown'))`;
  return `SELECT
  formatDateTime(dt, '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS dt,
  severity,
  message,
  error_class,
  controller,
  action
FROM (
  SELECT
    dt,
    ${severity} AS severity,
    coalesce(nullIf(JSONExtractString(raw, 'message'), ''), nullIf(JSONExtractString(raw, 'msg'), ''), nullIf(JSONExtractString(raw, 'error'), ''), 'No diagnostic message provided') AS message,
    coalesce(nullIf(JSONExtractString(raw, 'exception_class'), ''), nullIf(JSONExtractString(raw, 'error_class'), ''), '') AS error_class,
    coalesce(nullIf(JSONExtractString(raw, 'controller'), ''), '') AS controller,
    coalesce(nullIf(JSONExtractString(raw, 'action'), ''), '') AS action
  FROM (
    SELECT dt, raw FROM remote(${config.logsTable})
    WHERE dt >= parseDateTime64BestEffort('${args.windowStartedAt}') AND dt < parseDateTime64BestEffort('${args.windowEndedAt}')
    UNION ALL
    SELECT dt, raw FROM s3Cluster(primary, ${historicalTable})
    WHERE _row_type = 1 AND dt >= parseDateTime64BestEffort('${args.windowStartedAt}') AND dt < parseDateTime64BestEffort('${args.windowEndedAt}')
  )
)
WHERE severity IN ('error', 'fatal', 'critical', 'alert', 'emergency')
ORDER BY dt DESC
LIMIT ${MAX_DIAGNOSTIC_ROWS}
FORMAT JSONEachRow`;
}

/** Reads only selected error fields, redacts them, and persists grouped evidence. */
export async function collectDiagnosticSnapshot(
  config: GlobalArguments,
  args: CollectArguments,
  fetcher: Fetcher,
  generatedAt = new Date().toISOString(),
): Promise<DiagnosticSnapshot> {
  const parsedConfig = globalArgumentsSchema.parse(config);
  const parsedArgs = collectArgumentsSchema.parse(args);
  if (
    Date.parse(parsedArgs.windowEndedAt) > Date.parse(generatedAt) + 300_000
  ) {
    throw new Error(
      "windowEndedAt cannot be more than five minutes in the future",
    );
  }
  const url = new URL(parsedConfig.sqlEndpoint);
  url.searchParams.set("output_format_pretty_row_numbers", "0");
  url.searchParams.set("max_result_rows", String(MAX_DIAGNOSTIC_ROWS));
  url.searchParams.set("max_result_bytes", String(MAX_RESPONSE_BYTES));
  const response = await fetcher(url, {
    method: "POST",
    headers: {
      authorization: `Basic ${
        btoa(`${parsedConfig.sqlUsername}:${parsedConfig.sqlPassword}`)
      }`,
      "content-type": "text/plain",
    },
    body: diagnosticSqlQuery(parsedConfig, parsedArgs),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(
      `Better Stack diagnostic read failed with HTTP ${response.status}`,
    );
  }
  const body = await boundedBody(response);
  const rows = body.trim() === ""
    ? []
    : body.trim().split("\n").map((line) =>
      z.strictObject({
        dt: Timestamp,
        severity: SafeToken,
        message: z.string().max(100_000),
        error_class: z.string().max(1_000),
        controller: z.string().max(1_000),
        action: z.string().max(1_000),
      }).parse(JSON.parse(line))
    );
  if (rows.length > MAX_DIAGNOSTIC_ROWS) {
    throw new Error("Better Stack diagnostic result exceeded the row limit");
  }
  const grouped = new Map<string, {
    fingerprint: string;
    severity: string;
    errorClass: string | null;
    component: string | null;
    summary: string;
    firstSeenAt: string;
    lastSeenAt: string;
    occurrences: number;
    redactionCount: number;
    promptInjectionDetected: boolean;
  }>();
  for (const row of rows) {
    const sanitized = sanitizeEvidenceText(row.message, 2_000);
    const errorClass = component(row.error_class);
    const location =
      [component(row.controller), component(row.action)].filter(Boolean)
        .join("#") || null;
    const key = await fingerprint(
      JSON.stringify([
        row.severity,
        errorClass,
        location,
        normalizeDiagnosticFingerprintText(sanitized.value).slice(0, 400),
      ]),
    );
    const prior = grouped.get(key);
    if (prior) {
      prior.firstSeenAt = prior.firstSeenAt < row.dt
        ? prior.firstSeenAt
        : row.dt;
      prior.lastSeenAt = prior.lastSeenAt > row.dt ? prior.lastSeenAt : row.dt;
      prior.occurrences += 1;
      prior.redactionCount += sanitized.redactionCount;
      prior.promptInjectionDetected ||= sanitized.promptInjectionDetected;
    } else {
      grouped.set(key, {
        fingerprint: key,
        severity: row.severity,
        errorClass,
        component: location,
        summary: sanitized.value.slice(0, 500),
        firstSeenAt: row.dt,
        lastSeenAt: row.dt,
        occurrences: 1,
        redactionCount: sanitized.redactionCount,
        promptInjectionDetected: sanitized.promptInjectionDetected,
      });
    }
  }
  const groups = [...grouped.values()].sort((a, b) =>
    b.occurrences - a.occurrences || b.lastSeenAt.localeCompare(a.lastSeenAt) ||
    a.fingerprint.localeCompare(b.fingerprint)
  ).slice(0, MAX_DIAGNOSTIC_GROUPS);
  return diagnosticSnapshotSchema.parse({
    schemaVersion: "1.0",
    generatedAt,
    windowStartedAt: parsedArgs.windowStartedAt,
    windowEndedAt: parsedArgs.windowEndedAt,
    groups,
    returnedRows: rows.length,
    returnedBytes: new TextEncoder().encode(body).byteLength,
    queryFingerprint: "bounded-error-diagnostics-v1",
    truncated: rows.length === MAX_DIAGNOSTIC_ROWS ||
      grouped.size > groups.length,
    contentTrust: "untrusted-evidence",
    minimization: {
      rawLogRecordsPersisted: false,
      requestContentPersisted: false,
      urlsPersisted: false,
      credentialsPersisted: false,
      longIdentifiersPersisted: false,
      deterministicRedactionApplied: true,
    },
    authority: {
      mode: "read-only",
      sideEffects: "none",
      rawTelemetryRead: true,
      rawTelemetryPersisted: false,
      remediation: "prohibited",
    },
  });
}

/** Builds one rolling 24-hour window for scheduled deterministic collection. */
export function rollingDailyWindow(generatedAt = new Date().toISOString()) {
  const endedAt = Timestamp.parse(generatedAt);
  return collectArgumentsSchema.parse({
    windowStartedAt: new Date(
      Date.parse(endedAt) - MAX_WINDOW_SECONDS * 1_000,
    ).toISOString(),
    windowEndedAt: endedAt,
  });
}

/** Collects one shared rolling window before any persistence occurs. */
export async function collectDailySnapshot(
  config: GlobalArguments,
  fetcher: Fetcher,
  generatedAt = new Date().toISOString(),
): Promise<DailySnapshot> {
  const window = rollingDailyWindow(generatedAt);
  const [operationalSnapshot, diagnosticSnapshot] = await Promise.all([
    collectOperationalSnapshot(config, window, fetcher, generatedAt),
    collectDiagnosticSnapshot(config, window, fetcher, generatedAt),
  ]);
  return dailySnapshotSchema.parse({
    schemaVersion: "1.0",
    generatedAt,
    windowStartedAt: window.windowStartedAt,
    windowEndedAt: window.windowEndedAt,
    operationalSnapshot,
    diagnosticSnapshot,
    authority: {
      mode: "read-only",
      sideEffects: "none",
      remediation: "prohibited",
    },
  });
}

/** Read-only Better Stack model definition exposed to swamp. */
export const model = {
  type: "@mgreten/better-stack-read",
  version: BETTER_STACK_READ_MODEL_VERSION,
  globalArguments: globalArgumentsSchema,
  resources: {
    operationalSnapshot: {
      description:
        "Minimized read-only Better Stack monitor, incident, source, and application snapshot",
      schema: operationalSnapshotSchema,
      lifetime: "30d" as const,
      garbageCollection: 30,
    },
    logAggregateSnapshot: {
      description: "Aggregate-only Better Stack log severity snapshot",
      schema: logAggregateSnapshotSchema,
      lifetime: "30d" as const,
      garbageCollection: 30,
    },
    diagnosticSnapshot: {
      description:
        "Deterministically redacted and grouped error diagnostics from a bounded fixed query",
      schema: diagnosticSnapshotSchema,
      lifetime: "7d" as const,
      garbageCollection: 14,
    },
    dailySnapshot: {
      description:
        "Atomic rolling 24-hour operational and redacted diagnostic snapshot",
      schema: dailySnapshotSchema,
      lifetime: "7d" as const,
      garbageCollection: 14,
    },
  },
  methods: {
    collectDailySnapshot: {
      description:
        "Read one rolling 24-hour operational and diagnostic window for deterministic scheduled workflows.",
      arguments: collectDailyArgumentsSchema,
      execute: async (
        _args: z.infer<typeof collectDailyArgumentsSchema>,
        context: WriteContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const generatedAt = new Date().toISOString();
        const snapshot = await collectDailySnapshot(
          context.globalArgs,
          fetch,
          generatedAt,
        );
        const handle = await context.writeResource(
          "dailySnapshot",
          "daily-current",
          snapshot,
        );
        return { dataHandles: [handle] };
      },
    },
    collectOperationalSnapshot: {
      description:
        "Read bounded Better Stack operational metadata without retaining arbitrary text, URLs, request content, or credentials.",
      arguments: collectArgumentsSchema,
      execute: async (
        args: CollectArguments,
        context: WriteContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const snapshot = await collectOperationalSnapshot(
          context.globalArgs,
          args,
          fetch,
        );
        const handle = await context.writeResource(
          "operationalSnapshot",
          "operational-current",
          snapshot,
        );
        return { dataHandles: [handle] };
      },
    },
    collectLogAggregateSnapshot: {
      description:
        "Run a fixed bounded severity-count query; raw log bodies never leave Better Stack.",
      arguments: collectArgumentsSchema,
      execute: async (
        args: CollectArguments,
        context: WriteContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const snapshot = await collectLogAggregateSnapshot(
          context.globalArgs,
          args,
          fetch,
        );
        const handle = await context.writeResource(
          "logAggregateSnapshot",
          "logs-current",
          snapshot,
        );
        return { dataHandles: [handle] };
      },
    },
    collectDiagnosticSnapshot: {
      description:
        "Read selected error fields with a fixed query, redact sensitive values, and persist grouped untrusted evidence only.",
      arguments: collectArgumentsSchema,
      execute: async (
        args: CollectArguments,
        context: WriteContext,
      ): Promise<{ dataHandles: unknown[] }> => {
        const snapshot = await collectDiagnosticSnapshot(
          context.globalArgs,
          args,
          fetch,
        );
        const handle = await context.writeResource(
          "diagnosticSnapshot",
          "diagnostics-current",
          snapshot,
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
