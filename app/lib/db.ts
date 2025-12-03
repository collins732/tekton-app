import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { ScanResult } from './types';

// Determine database location:
// - Use DB_PATH env var if set (for custom paths)
// - Use /tmp in Linux containers (dev, staging, prod on Kubernetes)
// - Use project root on Windows/Mac (local development)
const isLinuxContainer = process.platform === 'linux' && !process.env.DB_PATH;
const dataDir = process.env.DB_PATH || (isLinuxContainer ? '/tmp' : process.cwd());
const dbPath = path.join(dataDir, 'tekton.db');

console.log(`[DB] Using database at: ${dbPath} (platform: ${process.platform}, NODE_ENV: ${process.env.NODE_ENV})`);

// Ensure directory exists and is writable
try {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
} catch (e) {
  console.error('Failed to create data directory:', e);
}

const db = new Database(dbPath);

// Helper function to check if column exists
function columnExists(tableName: string, columnName: string): boolean {
  const result = db.prepare(`PRAGMA table_info(${tableName})`).all() as any[];
  return result.some(col => col.name === columnName);
}

// Initialize all tables
db.exec(`
  -- Scans table
  CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL DEFAULT 'default_user',
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    progress INTEGER DEFAULT 0,
    current_step TEXT,
    results TEXT,
    error TEXT,
    cost INTEGER DEFAULT 0
  );

  -- Users table
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar TEXT DEFAULT '🥷',
    bio TEXT,
    country TEXT DEFAULT 'France',
    github TEXT,
    twitter TEXT,
    language TEXT DEFAULT 'English',
    timezone TEXT DEFAULT 'UTC+1 (Paris)',
    two_factor_enabled INTEGER DEFAULT 0,
    level INTEGER DEFAULT 1,
    current_xp INTEGER DEFAULT 0,
    total_points INTEGER DEFAULT 0,
    tokens INTEGER DEFAULT 50,
    plan TEXT DEFAULT 'FREE',
    streak INTEGER DEFAULT 0,
    last_scan_date INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  -- Achievements table
  CREATE TABLE IF NOT EXISTS achievements (
    achievement_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    icon TEXT NOT NULL,
    rarity TEXT NOT NULL,
    points INTEGER NOT NULL,
    requirement_type TEXT NOT NULL,
    requirement_value INTEGER NOT NULL
  );

  -- User Achievements (junction table)
  CREATE TABLE IF NOT EXISTS user_achievements (
    user_id TEXT NOT NULL,
    achievement_id TEXT NOT NULL,
    unlocked_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, achievement_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (achievement_id) REFERENCES achievements(achievement_id)
  );

  -- API Keys table
  CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    status TEXT DEFAULT 'active',
    requests_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Webhooks table
  CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT,
    events TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at INTEGER NOT NULL,
    last_triggered_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Integrations table
  CREATE TABLE IF NOT EXISTS integrations (
    integration_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    service TEXT NOT NULL,
    config TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Notifications Settings table
  CREATE TABLE IF NOT EXISTS notification_settings (
    user_id TEXT PRIMARY KEY,
    scan_complete INTEGER DEFAULT 1,
    vuln_found INTEGER DEFAULT 1,
    weekly_report INTEGER DEFAULT 1,
    achievement INTEGER DEFAULT 1,
    rank_change INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Activity Feed table
  CREATE TABLE IF NOT EXISTS activity_feed (
    activity_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    metadata TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Community Posts table
  CREATE TABLE IF NOT EXISTS community_posts (
    post_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT,
    likes INTEGER DEFAULT 0,
    replies INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Scheduled Scans table
  CREATE TABLE IF NOT EXISTS scheduled_scans (
    schedule_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_types TEXT NOT NULL,
    frequency TEXT NOT NULL,
    next_run INTEGER NOT NULL,
    last_run INTEGER,
    status TEXT DEFAULT 'active',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Token Purchases table
  CREATE TABLE IF NOT EXISTS token_purchases (
    purchase_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    tokens INTEGER NOT NULL,
    price REAL NOT NULL,
    payment_method TEXT,
    status TEXT DEFAULT 'completed',
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Notifications table
  CREATE TABLE IF NOT EXISTS notifications (
    notification_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    read INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  -- Create indexes for better performance
  CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
  CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
  CREATE INDEX IF NOT EXISTS idx_users_points ON users(total_points DESC);
  CREATE INDEX IF NOT EXISTS idx_user_achievements_user ON user_achievements(user_id);
  CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_feed(user_id);
  CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_feed(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
`);

// Migrations: Add missing columns to existing tables
if (!columnExists('users', 'language')) {
  db.exec(`ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'English'`);
}
if (!columnExists('users', 'timezone')) {
  db.exec(`ALTER TABLE users ADD COLUMN timezone TEXT DEFAULT 'UTC+1 (Paris)'`);
}
if (!columnExists('users', 'two_factor_enabled')) {
  db.exec(`ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0`);
}

export function createScan(scanId: string, target: string, userId: string = 'default_user', cost: number = 0): void {
  const stmt = db.prepare(`
    INSERT INTO scans (scan_id, user_id, target, status, started_at, progress, cost)
    VALUES (?, ?, ?, 'pending', ?, 0, ?)
  `);
  stmt.run(scanId, userId, target, Date.now(), cost);
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

export function getAllScans(userId: string = 'default_user'): any[] {
  const stmt = db.prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT 50');
  const rows = stmt.all(userId) as any[];

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
    cost: row.cost || 0,
  }));
}

// ========== USER FUNCTIONS ==========

export function createUser(userData: {
  userId: string;
  username: string;
  email: string;
  passwordHash: string;
}) {
  const stmt = db.prepare(`
    INSERT INTO users (user_id, username, email, password_hash, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const now = Date.now();
  stmt.run(userData.userId, userData.username, userData.email, userData.passwordHash, now, now);

  // Create default notification settings
  const notifStmt = db.prepare(`
    INSERT INTO notification_settings (user_id) VALUES (?)
  `);
  notifStmt.run(userData.userId);
}

export function getUser(userId: string) {
  const stmt = db.prepare('SELECT * FROM users WHERE user_id = ?');
  return stmt.get(userId);
}

export function getUserByEmail(email: string) {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  return stmt.get(email);
}

export function getUserByUsername(username: string) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
  return stmt.get(username);
}

export function updateUser(userId: string, updates: any) {
  const fields: string[] = [];
  const values: any[] = [];

  Object.keys(updates).forEach(key => {
    if (updates[key] !== undefined) {
      fields.push(`${key} = ?`);
      values.push(updates[key]);
    }
  });

  fields.push('updated_at = ?');
  values.push(Date.now());
  values.push(userId);

  const stmt = db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE user_id = ?`);
  stmt.run(...values);
}

export function addXP(userId: string, xp: number) {
  // XP system removed - function kept for backwards compatibility
  return { newLevel: 1, leveledUp: false };
}

export function deductTokens(userId: string, amount: number) {
  const stmt = db.prepare('UPDATE users SET tokens = tokens - ? WHERE user_id = ? AND tokens >= ?');
  const result = stmt.run(amount, userId, amount);
  return result.changes > 0;
}

export function addTokens(userId: string, amount: number) {
  const stmt = db.prepare('UPDATE users SET tokens = tokens + ? WHERE user_id = ?');
  stmt.run(amount, userId);
}

// ========== LEADERBOARD FUNCTIONS ==========

export function getLeaderboard(limit: number = 50) {
  const stmt = db.prepare(`
    SELECT user_id, username, avatar, level, total_points, country,
           (SELECT COUNT(*) FROM scans WHERE user_id = users.user_id) as scans_count,
           (SELECT COUNT(*) FROM user_achievements WHERE user_id = users.user_id) as achievements_count
    FROM users
    ORDER BY total_points DESC, level DESC
    LIMIT ?
  `);
  return stmt.all(limit);
}

export function getUserRank(userId: string) {
  const stmt = db.prepare(`
    SELECT COUNT(*) + 1 as rank
    FROM users
    WHERE total_points > (SELECT total_points FROM users WHERE user_id = ?)
  `);
  const result = stmt.get(userId) as any;
  return result?.rank || 0;
}

// ========== ACHIEVEMENTS FUNCTIONS ==========

export function initializeAchievements() {
  const achievements = [
    { id: 'first_scan', name: 'First Blood', desc: 'Complete your first scan', icon: '🎯', rarity: 'COMMON', points: 10, type: 'scans_count', value: 1 },
    { id: 'scans_10', name: 'Getting Started', desc: 'Complete 10 scans', icon: '📊', rarity: 'COMMON', points: 50, type: 'scans_count', value: 10 },
    { id: 'scans_50', name: 'Half Century', desc: 'Complete 50 scans', icon: '💯', rarity: 'UNCOMMON', points: 200, type: 'scans_count', value: 50 },
    { id: 'scans_100', name: 'Centurion', desc: 'Complete 100 scans', icon: '🏆', rarity: 'RARE', points: 500, type: 'scans_count', value: 100 },
    { id: 'vuln_hunter', name: 'Vulnerability Hunter', desc: 'Find 50 vulnerabilities', icon: '🔍', rarity: 'UNCOMMON', points: 150, type: 'vulns_found', value: 50 },
    { id: 'streak_7', name: 'Week Warrior', desc: 'Maintain a 7-day streak', icon: '🔥', rarity: 'UNCOMMON', points: 100, type: 'streak', value: 7 },
    { id: 'streak_15', name: '15-Day Streak', desc: 'Maintain a 15-day streak', icon: '🔥', rarity: 'RARE', points: 300, type: 'streak', value: 15 },
    { id: 'streak_30', name: 'Monthly Master', desc: 'Maintain a 30-day streak', icon: '🔥', rarity: 'EPIC', points: 750, type: 'streak', value: 30 },
    { id: 'level_10', name: 'Rising Star', desc: 'Reach level 10', icon: '⭐', rarity: 'UNCOMMON', points: 100, type: 'level', value: 10 },
    { id: 'level_25', name: 'Expert', desc: 'Reach level 25', icon: '💫', rarity: 'RARE', points: 300, type: 'level', value: 25 },
    { id: 'level_50', name: 'Master', desc: 'Reach level 50', icon: '👑', rarity: 'EPIC', points: 1000, type: 'level', value: 50 },
    { id: 'api_user', name: 'API Developer', desc: 'Create your first API key', icon: '🔑', rarity: 'COMMON', points: 25, type: 'api_keys', value: 1 },
  ];

  const stmt = db.prepare(`
    INSERT OR IGNORE INTO achievements (achievement_id, name, description, icon, rarity, points, requirement_type, requirement_value)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  achievements.forEach(a => {
    stmt.run(a.id, a.name, a.desc, a.icon, a.rarity, a.points, a.type, a.value);
  });
}

export function getUserAchievements(userId: string) {
  const stmt = db.prepare(`
    SELECT a.*, ua.unlocked_at
    FROM achievements a
    LEFT JOIN user_achievements ua ON a.achievement_id = ua.achievement_id AND ua.user_id = ?
    ORDER BY ua.unlocked_at DESC NULLS LAST, a.points DESC
  `);
  return stmt.all(userId);
}

export function unlockAchievement(userId: string, achievementId: string) {
  try {
    const stmt = db.prepare(`
      INSERT INTO user_achievements (user_id, achievement_id, unlocked_at)
      VALUES (?, ?, ?)
    `);
    stmt.run(userId, achievementId, Date.now());

    // Add points for the achievement
    const achStmt = db.prepare('SELECT points FROM achievements WHERE achievement_id = ?');
    const ach = achStmt.get(achievementId) as any;
    if (ach) {
      addXP(userId, ach.points);
    }
    return true;
  } catch (e) {
    // Already unlocked
    return false;
  }
}

export function checkAndUnlockAchievements(userId: string) {
  // Achievement system removed - returning empty array
  return [];
}

// ========== API KEYS FUNCTIONS ==========

export function createAPIKey(userId: string, name: string, keyHash: string) {
  const keyId = 'key_' + Math.random().toString(36).substring(2);
  const stmt = db.prepare(`
    INSERT INTO api_keys (key_id, user_id, name, key_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(keyId, userId, name, keyHash, Date.now());
  return keyId;
}

export function getAPIKeys(userId: string) {
  const stmt = db.prepare('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC');
  return stmt.all(userId);
}

export function deleteAPIKey(keyId: string, userId: string) {
  const stmt = db.prepare('DELETE FROM api_keys WHERE key_id = ? AND user_id = ?');
  stmt.run(keyId, userId);
}

export function validateAPIKey(keyHash: string) {
  const stmt = db.prepare('SELECT * FROM api_keys WHERE key_hash = ? AND status = "active"');
  const key = stmt.get(keyHash) as any;

  if (key) {
    // Update last used
    const updateStmt = db.prepare('UPDATE api_keys SET last_used_at = ?, requests_count = requests_count + 1 WHERE key_id = ?');
    updateStmt.run(Date.now(), key.key_id);
  }

  return key;
}

// ========== WEBHOOKS FUNCTIONS ==========

export function createWebhook(userId: string, data: { name: string; url: string; events: string[]; secret?: string }) {
  const webhookId = 'webhook_' + Math.random().toString(36).substring(2);
  const stmt = db.prepare(`
    INSERT INTO webhooks (webhook_id, user_id, name, url, events, secret, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(webhookId, userId, data.name, data.url, JSON.stringify(data.events), data.secret || null, Date.now());
  return webhookId;
}

export function getWebhooks(userId: string) {
  const stmt = db.prepare('SELECT * FROM webhooks WHERE user_id = ? ORDER BY created_at DESC');
  const webhooks = stmt.all(userId) as any[];
  return webhooks.map(w => ({ ...w, events: JSON.parse(w.events) }));
}

export function deleteWebhook(webhookId: string, userId: string) {
  const stmt = db.prepare('DELETE FROM webhooks WHERE webhook_id = ? AND user_id = ?');
  stmt.run(webhookId, userId);
}

// ========== INTEGRATIONS FUNCTIONS ==========

export function createIntegration(userId: string, service: string, config: any) {
  const integrationId = 'int_' + Math.random().toString(36).substring(2);
  const stmt = db.prepare(`
    INSERT INTO integrations (integration_id, user_id, service, config, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  stmt.run(integrationId, userId, service, JSON.stringify(config), Date.now());
  return integrationId;
}

export function getIntegrations(userId: string) {
  const stmt = db.prepare('SELECT * FROM integrations WHERE user_id = ?');
  const integrations = stmt.all(userId) as any[];
  return integrations.map(i => ({ ...i, config: JSON.parse(i.config) }));
}

export function deleteIntegration(integrationId: string, userId: string) {
  const stmt = db.prepare('DELETE FROM integrations WHERE integration_id = ? AND user_id = ?');
  stmt.run(integrationId, userId);
}

// ========== NOTIFICATION SETTINGS ==========

export function getNotificationSettings(userId: string) {
  // Notification settings removed - returning null
  return null;
}

export function updateNotificationSettings(userId: string, settings: any) {
  const fields = Object.keys(settings).map(k => `${k} = ?`).join(', ');
  const values = Object.values(settings);
  values.push(userId);

  const stmt = db.prepare(`UPDATE notification_settings SET ${fields} WHERE user_id = ?`);
  stmt.run(...values);
}

// ========== ACTIVITY FEED FUNCTIONS ==========

export function addActivity(userId: string, type: string, title: string, description?: string, metadata?: any) {
  // Activity feed removed - function kept for backwards compatibility
  return 'activity_disabled';
}

export function getActivityFeed(userId: string, limit: number = 50) {
  const stmt = db.prepare(`
    SELECT * FROM activity_feed WHERE user_id = ?
    ORDER BY created_at DESC LIMIT ?
  `);
  const activities = stmt.all(userId, limit) as any[];
  return activities.map(a => ({
    ...a,
    metadata: a.metadata ? JSON.parse(a.metadata) : null
  }));
}

// ========== COMMUNITY POSTS FUNCTIONS ==========

export function createCommunityPost(userId: string, title: string, content: string, tags: string[]) {
  const postId = 'post_' + Math.random().toString(36).substring(2);
  const now = Date.now();
  const stmt = db.prepare(`
    INSERT INTO community_posts (post_id, user_id, title, content, tags, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(postId, userId, title, content, JSON.stringify(tags), now, now);
  return postId;
}

export function getCommunityPosts(limit: number = 50) {
  const stmt = db.prepare(`
    SELECT cp.*, u.username, u.avatar
    FROM community_posts cp
    JOIN users u ON cp.user_id = u.user_id
    ORDER BY cp.created_at DESC LIMIT ?
  `);
  const posts = stmt.all(limit) as any[];
  return posts.map(p => ({
    ...p,
    tags: p.tags ? JSON.parse(p.tags) : []
  }));
}

export function likePost(postId: string) {
  const stmt = db.prepare('UPDATE community_posts SET likes = likes + 1 WHERE post_id = ?');
  stmt.run(postId);
}

// ========== SCHEDULED SCANS FUNCTIONS ==========

export function createScheduledScan(userId: string, data: {
  name: string;
  target: string;
  scanTypes: string[];
  frequency: string;
}) {
  const scheduleId = 'schedule_' + Math.random().toString(36).substring(2);

  // Calculate next run based on frequency
  const now = Date.now();
  let nextRun = now;
  switch (data.frequency) {
    case 'daily':
      nextRun += 24 * 60 * 60 * 1000;
      break;
    case 'weekly':
      nextRun += 7 * 24 * 60 * 60 * 1000;
      break;
    case 'monthly':
      nextRun += 30 * 24 * 60 * 60 * 1000;
      break;
  }

  const stmt = db.prepare(`
    INSERT INTO scheduled_scans (schedule_id, user_id, name, target, scan_types, frequency, next_run, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(scheduleId, userId, data.name, data.target, JSON.stringify(data.scanTypes), data.frequency, nextRun, now);
  return scheduleId;
}

export function getScheduledScans(userId: string) {
  const stmt = db.prepare('SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY next_run ASC');
  const scans = stmt.all(userId) as any[];
  return scans.map(s => ({
    ...s,
    scan_types: JSON.parse(s.scan_types)
  }));
}

export function deleteScheduledScan(scheduleId: string, userId: string) {
  const stmt = db.prepare('DELETE FROM scheduled_scans WHERE schedule_id = ? AND user_id = ?');
  stmt.run(scheduleId, userId);
}

export function updateScheduledScanStatus(scheduleId: string, status: string) {
  const stmt = db.prepare('UPDATE scheduled_scans SET status = ? WHERE schedule_id = ?');
  stmt.run(status, scheduleId);
}

// ========== TOKEN PURCHASES FUNCTIONS ==========

export function createTokenPurchase(userId: string, amount: number, tokens: number, price: number, paymentMethod: string = 'simulated') {
  const purchaseId = 'purchase_' + Math.random().toString(36).substring(2);
  const stmt = db.prepare(`
    INSERT INTO token_purchases (purchase_id, user_id, amount, tokens, price, payment_method, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(purchaseId, userId, amount, tokens, price, paymentMethod, Date.now());

  // Add tokens to user
  addTokens(userId, tokens);

  // Add activity
  addActivity(userId, 'token_purchase', 'Tokens Purchased', `Purchased ${tokens} tokens for €${price}`);

  return purchaseId;
}

export function getTokenPurchases(userId: string) {
  const stmt = db.prepare('SELECT * FROM token_purchases WHERE user_id = ? ORDER BY created_at DESC LIMIT 20');
  return stmt.all(userId);
}

// ========== NOTIFICATIONS FUNCTIONS ==========

export function createNotification(userId: string, type: string, title: string, message: string, link?: string) {
  // Notifications removed - function kept for backwards compatibility
  return 'notif_disabled';
}

export function getNotifications(userId: string, unreadOnly: boolean = false) {
  let query = 'SELECT * FROM notifications WHERE user_id = ?';
  if (unreadOnly) {
    query += ' AND read = 0';
  }
  query += ' ORDER BY created_at DESC LIMIT 50';

  const stmt = db.prepare(query);
  return stmt.all(userId);
}

export function markNotificationAsRead(notificationId: string) {
  const stmt = db.prepare('UPDATE notifications SET read = 1 WHERE notification_id = ?');
  stmt.run(notificationId);
}

export function markAllNotificationsAsRead(userId: string) {
  const stmt = db.prepare('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0');
  stmt.run(userId);
}

export function getUnreadNotificationCount(userId: string) {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND read = 0');
  const result = stmt.get(userId) as any;
  return result.count;
}

// ========== STATS FUNCTIONS ==========

export function getDashboardStats(userId: string) {
  const scans = getAllScans(userId);
  const completedScans = scans.filter(s => s.status === 'completed');

  // Calculate total vulnerabilities
  let totalVulns = 0;
  let criticalVulns = 0;
  let highVulns = 0;
  let mediumVulns = 0;
  let lowVulns = 0;

  completedScans.forEach(scan => {
    if (scan.results?.vulnerabilities) {
      scan.results.vulnerabilities.forEach((vuln: any) => {
        totalVulns++;
        if (vuln.severity === 'critical') criticalVulns++;
        else if (vuln.severity === 'high') highVulns++;
        else if (vuln.severity === 'medium') mediumVulns++;
        else if (vuln.severity === 'low') lowVulns++;
      });
    }
  });

  // Get user data
  const user = getUser(userId) as any;

  // Recent activity
  const recentScans = scans.slice(0, 10);

  return {
    total_scans: scans.length,
    completed_scans: completedScans.length,
    running_scans: scans.filter(s => s.status === 'running').length,
    failed_scans: scans.filter(s => s.status === 'failed').length,
    vulnerabilities: {
      total: totalVulns,
      critical: criticalVulns,
      high: highVulns,
      medium: mediumVulns,
      low: lowVulns
    },
    tokens: {
      available: user?.tokens || 0,
      plan: user?.plan || 'FREE'
    },
    gamification: {
      level: user?.level || 1,
      xp: user?.current_xp || 0,
      total_points: user?.total_points || 0,
      streak: user?.streak || 0
    },
    recent_scans: recentScans
  };
}

// Initialize achievements on startup
initializeAchievements();

export default db;
