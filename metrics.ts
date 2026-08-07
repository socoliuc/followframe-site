import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const ACTIVE_DIGEST_RETENTION_MS = 45 * 24 * 60 * 60 * 1_000;
const AGGREGATE_RETENTION_MS = 730 * 24 * 60 * 60 * 1_000;

export type DownloadKind = "exe" | "checksum";
export type DownloadOutcome = "completed" | "failed" | "interrupted";
export type DownloadDeliveryCounts = Record<"started" | DownloadOutcome, number>;
export type DownloadDeliverySummary = Record<DownloadKind, DownloadDeliveryCounts>;

export type MetricName =
  | "completed_exe_responses"
  | "opt_in_active_installations"
  | "version_adoption"
  | `download_${DownloadKind}_${"started" | DownloadOutcome}`;

export type MetricStore = {
  recordCompletedDownload: (version: string, at: number) => void;
  recordDownloadStarted: (kind: DownloadKind, version: string, at: number) => void;
  recordDownloadOutcome: (kind: DownloadKind, outcome: DownloadOutcome, version: string, at: number) => void;
  recordActiveInstallation: (digest: string, version: string, at: number) => boolean;
  readDailyCount: (day: string, metric: MetricName, version?: string) => number;
  readDownloadDelivery: (day: string) => DownloadDeliverySummary;
  cleanup: (at: number) => void;
  close: () => void;
};

function utcDay(at: number): string {
  return new Date(at).toISOString().slice(0, 10);
}

export function createMetricStore(databasePath: string): MetricStore {
  if (databasePath !== ":memory:") {
    mkdirSync(dirname(databasePath), { recursive: true });
  }
  const database = new DatabaseSync(databasePath);
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    CREATE TABLE IF NOT EXISTS active_installation_seen (
      day TEXT NOT NULL,
      digest TEXT NOT NULL,
      version TEXT NOT NULL,
      last_seen_at INTEGER NOT NULL,
      PRIMARY KEY (day, digest)
    );
    CREATE TABLE IF NOT EXISTS daily_metrics (
      day TEXT NOT NULL,
      metric TEXT NOT NULL,
      version TEXT NOT NULL DEFAULT '',
      campaign TEXT NOT NULL DEFAULT '',
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (day, metric, version, campaign)
    );
  `);

  const increment = database.prepare(`
    INSERT INTO daily_metrics (day, metric, version, campaign, count)
    VALUES (?, ?, ?, '', 1)
    ON CONFLICT(day, metric, version, campaign)
    DO UPDATE SET count = count + 1
  `);
  const insertActive = database.prepare(`
    INSERT OR IGNORE INTO active_installation_seen (day, digest, version, last_seen_at)
    VALUES (?, ?, ?, ?)
  `);
  const touchActive = database.prepare(`
    UPDATE active_installation_seen SET last_seen_at = ?, version = ? WHERE day = ? AND digest = ?
  `);
  const readCount = database.prepare(`
    SELECT COALESCE(SUM(count), 0) AS count
    FROM daily_metrics
    WHERE day = ? AND metric = ? AND (? = '' OR version = ?)
  `);
  const deleteActive = database.prepare("DELETE FROM active_installation_seen WHERE last_seen_at < ?");
  const deleteAggregates = database.prepare("DELETE FROM daily_metrics WHERE day < ?");

  function cleanup(at: number): void {
    deleteActive.run(at - ACTIVE_DIGEST_RETENTION_MS);
    deleteAggregates.run(utcDay(at - AGGREGATE_RETENTION_MS));
  }

  function readDailyCount(day: string, metric: MetricName, version = ""): number {
    const row = readCount.get(day, metric, version, version) as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  }

  return {
    recordCompletedDownload(version, at) {
      increment.run(utcDay(at), "completed_exe_responses", version);
      cleanup(at);
    },
    recordDownloadStarted(kind, version, at) {
      increment.run(utcDay(at), `download_${kind}_started`, version);
      cleanup(at);
    },
    recordDownloadOutcome(kind, outcome, version, at) {
      increment.run(utcDay(at), `download_${kind}_${outcome}`, version);
      cleanup(at);
    },
    recordActiveInstallation(digest, version, at) {
      const day = utcDay(at);
      const result = insertActive.run(day, digest, version, at);
      touchActive.run(at, version, day, digest);
      const inserted = Number(result.changes) === 1;
      if (inserted) {
        increment.run(day, "opt_in_active_installations", version);
        increment.run(day, "version_adoption", version);
      }
      cleanup(at);
      return inserted;
    },
    readDailyCount(day, metric, version = "") {
      return readDailyCount(day, metric, version);
    },
    readDownloadDelivery(day) {
      const readKind = (kind: DownloadKind): DownloadDeliveryCounts => ({
        started: readDailyCount(day, `download_${kind}_started`),
        completed: readDailyCount(day, `download_${kind}_completed`),
        failed: readDailyCount(day, `download_${kind}_failed`),
        interrupted: readDailyCount(day, `download_${kind}_interrupted`),
      });
      return { exe: readKind("exe"), checksum: readKind("checksum") };
    },
    cleanup,
    close() {
      database.close();
    },
  };
}
