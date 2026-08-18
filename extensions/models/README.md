# @mgreten/better-stack-read

A deliberately narrow, read-only connector for Better Stack Uptime, Telemetry,
Errors, and Logs. It stores allowlisted operational fields and severity counts,
not raw log records, arbitrary response text, URLs, request content, or
credentials. Reads are bounded by time, pagination, response size, and output
row limits. The extension exposes no mutation methods.

## Installation

```sh
swamp extension pull @mgreten/better-stack-read
```

## Setup

Store all credentials in a swamp vault. Do not put literal secrets in model
YAML. The SQL endpoint must be a credential-free HTTPS origin ending in
`.betterstackdata.com`; credentials are sent separately with HTTP Basic auth.

```sh
swamp model create @mgreten/better-stack-read better-stack-read
```

Configure the generated model's global arguments with vault expressions:

```yaml
globalArguments:
  uptimeApiToken: ${vault.get("better-stack", "uptime_api_token")}
  telemetryApiToken: ${vault.get("better-stack", "telemetry_api_token")}
  sqlEndpoint: https://REGION-connect.betterstackdata.com
  sqlUsername: ${vault.get("better-stack", "sql_username")}
  sqlPassword: ${vault.get("better-stack", "sql_password")}
  logsTable: t123_example_logs
```

The exact vault-expression syntax depends on the vault backend configured in
your swamp repository. Grant API tokens read-only scopes wherever Better Stack
supports scoped access.

## Global Arguments

| Argument | Type | Required | Meaning |
| --- | --- | --- | --- |
| `uptimeApiToken` | string | yes | Read token for Uptime monitors, heartbeats, and incidents |
| `telemetryApiToken` | string | yes | Read token for Telemetry sources and Errors applications |
| `sqlEndpoint` | HTTPS URL | yes | Better Stack SQL origin with no path, query, or credentials |
| `sqlUsername` | string | yes | Vault-backed SQL username |
| `sqlPassword` | string | yes | Vault-backed SQL password |
| `logsTable` | string | yes | Better Stack live logs table matching `t…_logs` |

There are no defaults: every value is explicit and credentials should remain
vault-backed.

## Method: `collectOperationalSnapshot`

Reads monitors, heartbeats, active/recent incidents, telemetry sources, and
error applications. Only IDs, normalized status/platform/region tokens,
selected timestamps, pause flags, and incident relationships are retained.

| Argument | Type | Required | Limit |
| --- | --- | --- | --- |
| `windowStartedAt` | offset ISO-8601 datetime | yes | Start of interval |
| `windowEndedAt` | offset ISO-8601 datetime | yes | After start; at most 24 hours later |

```sh
swamp model method run better-stack-read collectOperationalSnapshot \
  --input windowStartedAt=2026-08-17T12:00:00Z \
  --input windowEndedAt=2026-08-18T12:00:00Z
```

## Method: `collectLogAggregateSnapshot`

Runs one fixed SQL statement that groups an allowlisted normalized severity and
returns counts. Users cannot supply SQL, projections, grouping fields, or raw
log output.

| Argument | Type | Required | Limit |
| --- | --- | --- | --- |
| `windowStartedAt` | offset ISO-8601 datetime | yes | Start of interval |
| `windowEndedAt` | offset ISO-8601 datetime | yes | After start; at most 24 hours later |

```sh
swamp model method run better-stack-read collectLogAggregateSnapshot \
  --input windowStartedAt=2026-08-17T12:00:00Z \
  --input windowEndedAt=2026-08-18T12:00:00Z
```

## Storage semantics

Each method writes one stable resource name (`operational-current` or
`logs-current`). Resource versions have a 30-day lifetime and garbage collection
limit of 30. Operational responses are projected through strict schemas.
Aggregate output contains severity/count pairs, byte and row counts, a fixed
query fingerprint, truncation metadata, and explicit read-only authority flags.
Credentials and full upstream responses are never written.

## Limits and Query Boost warning

Collection windows are limited to 24 hours. API reads use at most five pages,
with bounded per-page sizes, ten-second request timeouts, and one-megabyte
response limits. SQL returns at most 20 aggregate rows and one megabyte. A
truncation flag signals pagination or row-bound exhaustion.

The log method queries both recent and historical storage using Better Stack's
`remote(...)` and `s3Cluster(...)` functions. **Better Stack Query Boost may
incur additional usage or cost when historical data is read.** Review your
plan, retention layout, and Query Boost pricing before scheduling this method.
The extension does not estimate or cap provider-side scanned bytes.

The connector is not a raw-log export, live tail, alert mutator, incident
acknowledger, or monitor manager. Better Stack API/schema changes may require a
new extension release.

## License

MIT — see LICENSE.txt for details.
