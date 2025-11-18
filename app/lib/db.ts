import Database from 'better-sqlite3';
import path from 'path';
import { ScanResult } from './types';

const dbPath = path.join(process.cwd(), 'scans.db');
const db = new Database(dbPath);

// Créer la table des scans
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    progress INTEGER DEFAULT 0,
    current_step TEXT,
    results TEXT,
    error TEXT
  )
`);

export function createScan(scanId: string, target: string): void {
  const stmt = db.prepare(`
    INSERT INTO scans (scan_id, target, status, started_at, progress)
    VALUES (?, ?, 'pending', ?, 0)
  `);
  stmt.run(scanId, target, Date.now());
}

export function updateScan(scanId: string, updates: Partial<ScanResult>): void {
  const fields: string[] = [];
  const values: any[] = [];

  if (updates.status) {
    fields.push('status = ?');
    values.push(updates.status);
  }
  if (updates.progress !== undefined) {
    fields.push('progress = ?');
    values.push(updates.progress);
  }
  if (updates.currentStep) {
    fields.push('current_step = ?');
    values.push(updates.currentStep);
  }
  if (updates.results) {
    fields.push('results = ?');
    values.push(JSON.stringify(updates.results));
  }
  if (updates.completedAt) {
    fields.push('completed_at = ?');
    values.push(updates.completedAt.getTime());
  }
  if (updates.error) {
    fields.push('error = ?');
    values.push(updates.error);
  }

  values.push(scanId);

  const stmt = db.prepare(`
    UPDATE scans SET ${fields.join(', ')} WHERE scan_id = ?
  `);
  stmt.run(...values);
}

export function getScan(scanId: string): ScanResult | null {
  const stmt = db.prepare('SELECT * FROM scans WHERE scan_id = ?');
  const row = stmt.get(scanId) as any;

  if (!row) return null;

  return {
    scanId: row.scan_id,
    target: row.target,
    status: row.status,
    startedAt: new Date(row.started_at),
    completedAt: row.completed_at ? new Date(row.completed_at) : undefined,
    progress: row.progress,
    currentStep: row.current_step,
    results: row.results ? JSON.parse(row.results) : {},
    error: row.error,
  };
}

export function getAllScans(): ScanResult[] {
  const stmt = db.prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT 50');
  const rows = stmt.all() as any[];

  return rows.map(row => ({
    scanId: row.scan_id,
    target: row.target,
    status: row.status,
    startedAt: new Date(row.started_at),
    completedAt: row.completed_at ? new Date(row.completed_at) : undefined,
    progress: row.progress,
    currentStep: row.current_step,
    results: row.results ? JSON.parse(row.results) : {},
    error: row.error,
  }));
}
