import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import { DEFAULT_CMS_CONFIG } from './src/data/gameData.ts';
import type { CmsConfig } from './src/data/gameData.ts';

interface StoredPlayer {
  username: string;
  email: string;
  passwordHash: string;
  passwordSalt: string;
  server: string;
  characterName: string;
  points: number;
  inGameGoldPoints: number;
  redeemedCodes: string[];
  createdAt: string;
}

interface PlayersDatabase {
  adminPassword: string;
  players: StoredPlayer[];
}

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(process.cwd(), 'data');
const CMS_FILE = path.join(DATA_DIR, 'cms-data.json');
const PLAYERS_FILE = path.join(DATA_DIR, 'players.json');
const SESSION_SECRET = process.env.ADMIN_SESSION_SECRET || 'ninjareborn-cms-secret-2026';
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin1234';

function ensureDataDir(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readCmsData(): CmsConfig {
  ensureDataDir();
  if (!fs.existsSync(CMS_FILE)) {
    fs.writeFileSync(CMS_FILE, JSON.stringify(DEFAULT_CMS_CONFIG, null, 2), 'utf8');
    return structuredClone(DEFAULT_CMS_CONFIG);
  }
  try {
    const raw = fs.readFileSync(CMS_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<CmsConfig>;
    return {
      ...DEFAULT_CMS_CONFIG,
      ...parsed,
      siteSettings: {
        ...DEFAULT_CMS_CONFIG.siteSettings,
        ...(parsed.siteSettings ?? {}),
      },
      worldBoss: {
        ...DEFAULT_CMS_CONFIG.worldBoss,
        ...(parsed.worldBoss ?? {}),
      },
    };
  } catch {
    return structuredClone(DEFAULT_CMS_CONFIG);
  }
}

function writeCmsData(config: CmsConfig): void {
  ensureDataDir();
  fs.writeFileSync(CMS_FILE, JSON.stringify(config, null, 2), 'utf8');
}

function readPlayersDb(): PlayersDatabase {
  ensureDataDir();
  if (!fs.existsSync(PLAYERS_FILE)) {
    const initial: PlayersDatabase = {
      adminPassword: DEFAULT_ADMIN_PASSWORD,
      players: [],
    };
    fs.writeFileSync(PLAYERS_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = fs.readFileSync(PLAYERS_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<PlayersDatabase>;
    return {
      adminPassword: parsed.adminPassword || DEFAULT_ADMIN_PASSWORD,
      players: Array.isArray(parsed.players) ? parsed.players : [],
    };
  } catch {
    return { adminPassword: DEFAULT_ADMIN_PASSWORD, players: [] };
  }
}

function writePlayersDb(db: PlayersDatabase): void {
  ensureDataDir();
  fs.writeFileSync(PLAYERS_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function hashPassword(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  const candidate = crypto.scryptSync(password, salt, 64);
  const existing = Buffer.from(storedHash, 'hex');
  if (candidate.length !== existing.length) return false;
  return crypto.timingSafeEqual(candidate, existing);
}

function createAdminToken(): string {
  const issuedAt = Date.now().toString();
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(issuedAt).digest('hex');
  return `${issuedAt}.${sig}`;
}

function verifyAdminToken(token: string | undefined): boolean {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [issuedAt, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(issuedAt).digest('hex');
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expected);
  if (sigBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, expectedBuf);
}

function sanitizePlayer(p: StoredPlayer) {
  return {
    username: p.username,
    email: p.email,
    server: p.server,
    characterName: p.characterName,
    points: p.points,
    inGameGoldPoints: p.inGameGoldPoints,
    redeemedCodes: p.redeemedCodes,
    createdAt: p.createdAt,
  };
}

function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined;
  if (!verifyAdminToken(token)) {
    res.status(401).json({ error: 'กรุณาเข้าสู่ระบบผู้ดูแลเว็บไซต์ก่อนทำรายการ' });
    return;
  }
  next();
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  // Public CMS read endpoint
  app.get('/api/cms', (_req, res) => {
    const cms = readCmsData();
    res.json(cms);
  });

  // Admin authentication & CMS editing
  app.post('/api/admin/login', (req, res) => {
    const password = String(req.body?.password ?? '');
    const db = readPlayersDb();
    if (!password || password !== db.adminPassword) {
      res.status(401).json({ error: 'รหัสผ่านหลังบ้านไม่ถูกต้อง' });
      return;
    }
    res.json({ token: createAdminToken() });
  });

  app.put('/api/admin/cms', requireAdmin, (req, res) => {
    const incoming = req.body as Partial<CmsConfig>;
    if (!incoming || typeof incoming !== 'object') {
      res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
      return;
    }
    const current = readCmsData();
    const updated: CmsConfig = {
      ...current,
      ...incoming,
      siteSettings: {
        ...current.siteSettings,
        ...(incoming.siteSettings ?? {}),
      },
      worldBoss: {
        ...current.worldBoss,
        ...(incoming.worldBoss ?? {}),
      },
      news: Array.isArray(incoming.news) ? incoming.news : current.news,
      villages: Array.isArray(incoming.villages) ? incoming.villages : current.villages,
      rankings: Array.isArray(incoming.rankings) ? incoming.rankings : current.rankings,
      downloads: Array.isArray(incoming.downloads) ? incoming.downloads : current.downloads,
      topupPackages: Array.isArray(incoming.topupPackages) ? incoming.topupPackages : current.topupPackages,
      giftCodes: Array.isArray(incoming.giftCodes) ? incoming.giftCodes : current.giftCodes,
    };
    writeCmsData(updated);
    res.json(updated);
  });

  app.post('/api/admin/password', requireAdmin, (req, res) => {
    const newPassword = String(req.body?.newPassword ?? '').trim();
    if (newPassword.length < 6) {
      res.status(400).json({ error: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร' });
      return;
    }
    const db = readPlayersDb();
    db.adminPassword = newPassword;
    writePlayersDb(db);
    res.json({ ok: true, message: 'อัปเดตรหัสผ่านหลังบ้านเรียบร้อยแล้ว' });
  });

  app.post('/api/admin/reset', requireAdmin, (_req, res) => {
    const fresh = structuredClone(DEFAULT_CMS_CONFIG);
    writeCmsData(fresh);
    res.json(fresh);
  });

  app.get('/api/admin/players', requireAdmin, (_req, res) => {
    const db = readPlayersDb();
    res.json({
      players: db.players.map(sanitizePlayer),
    });
  });

  app.post('/api/admin/players/adjust-points', requireAdmin, (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const delta = Number(req.body?.delta ?? 0);
    if (!username || !Number.isFinite(delta)) {
      res.status(400).json({ error: 'ข้อมูลปรับยอดแต้มไม่ถูกต้อง' });
      return;
    }
    const db = readPlayersDb();
    const player = db.players.find((p) => p.username.toLowerCase() === username.toLowerCase());
    if (!player) {
      res.status(404).json({ error: 'ไม่พบบัญชีผู้เล่นนี้' });
      return;
    }
    player.points = Math.max(0, player.points + Math.trunc(delta));
    writePlayersDb(db);
    res.json({ player: sanitizePlayer(player) });
  });

  // Player Auth & Portal Actions
  app.post('/api/auth/register', (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const email = String(req.body?.email ?? '').trim();
    const password = String(req.body?.password ?? '');
    const server = String(req.body?.server ?? 'S1 - โคโนฮะคลาสสิก').trim();

    if (username.length < 4) {
      res.status(400).json({ error: 'ชื่อบัญชีต้องมีความยาวอย่างน้อย 4 ตัวอักษร' });
      return;
    }
    if (!email.includes('@') || !email.includes('.')) {
      res.status(400).json({ error: 'กรุณากรอกอีเมลให้ถูกต้อง' });
      return;
    }
    if (password.length < 6) {
      res.status(400).json({ error: 'รหัสผ่านต้องมีความยาวอย่างน้อย 6 ตัวอักษร' });
      return;
    }

    const db = readPlayersDb();
    const exists = db.players.some((p) => p.username.toLowerCase() === username.toLowerCase());
    if (exists) {
      res.status(409).json({ error: 'ชื่อบัญชีนี้ถูกใช้งานแล้ว กรุณาใช้ชื่ออื่น' });
      return;
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const newPlayer: StoredPlayer = {
      username,
      email,
      passwordHash: hashPassword(password, salt),
      passwordSalt: salt,
      server,
      characterName: username,
      points: 500,
      inGameGoldPoints: 0,
      redeemedCodes: [],
      createdAt: new Date().toISOString(),
    };

    db.players.push(newPlayer);
    writePlayersDb(db);
    res.status(201).json({ player: sanitizePlayer(newPlayer) });
  });

  app.post('/api/auth/login', (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const password = String(req.body?.password ?? '');
    if (!username || !password) {
      res.status(400).json({ error: 'กรุณากรอกชื่อบัญชีและรหัสผ่าน' });
      return;
    }

    const db = readPlayersDb();
    const player = db.players.find((p) => p.username.toLowerCase() === username.toLowerCase());
    if (!player || !verifyPassword(password, player.passwordSalt, player.passwordHash)) {
      res.status(401).json({ error: 'ชื่อบัญชีหรือรหัสผ่านไม่ถูกต้อง' });
      return;
    }

    res.json({ player: sanitizePlayer(player) });
  });

  app.post('/api/player/topup', (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const packageId = String(req.body?.packageId ?? '').trim();
    const cms = readCmsData();
    const pkg = cms.topupPackages.find((p) => p.id === packageId);
    if (!pkg) {
      res.status(400).json({ error: 'ไม่พบแพ็กเกจโดเนทที่เลือก' });
      return;
    }

    const db = readPlayersDb();
    const player = db.players.find((p) => p.username.toLowerCase() === username.toLowerCase());
    if (!player) {
      res.status(404).json({ error: 'ไม่พบบัญชีผู้เล่น กรุณาเข้าสู่ระบบใหม่' });
      return;
    }

    const added = pkg.points + pkg.bonusPoints;
    player.points += added;
    writePlayersDb(db);
    res.json({ player: sanitizePlayer(player), addedPoints: added, priceThb: pkg.priceThb });
  });

  app.post('/api/player/transfer', (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const characterName = String(req.body?.characterName ?? '').trim();
    const amount = Number(req.body?.amount ?? 0);

    if (!characterName) {
      res.status(400).json({ error: 'กรุณาระบุชื่อตัวละครในเกม' });
      return;
    }
    if (!Number.isFinite(amount) || amount <= 0) {
      res.status(400).json({ error: 'กรุณาระบุจำนวนแต้มที่ต้องการโอนให้ถูกต้อง' });
      return;
    }

    const db = readPlayersDb();
    const player = db.players.find((p) => p.username.toLowerCase() === username.toLowerCase());
    if (!player) {
      res.status(404).json({ error: 'ไม่พบบัญชีผู้เล่น' });
      return;
    }
    if (amount > player.points) {
      res.status(400).json({ error: 'ยอด KagePoints คงเหลือไม่เพียงพอ' });
      return;
    }

    const transferInt = Math.trunc(amount);
    player.characterName = characterName;
    player.points -= transferInt;
    player.inGameGoldPoints += transferInt;
    writePlayersDb(db);
    res.json({ player: sanitizePlayer(player), transferred: transferInt });
  });

  app.post('/api/player/redeem', (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const code = String(req.body?.code ?? '').trim().toUpperCase();
    if (!code) {
      res.status(400).json({ error: 'กรุณากรอกโค้ดไอเทม' });
      return;
    }

    const cms = readCmsData();
    const reward = cms.giftCodes.find((g) => g.code.toUpperCase() === code);
    if (!reward) {
      res.status(404).json({ error: 'ไม่พบโค้ดนี้หรือโค้ดหมดอายุแล้ว' });
      return;
    }

    const db = readPlayersDb();
    const player = db.players.find((p) => p.username.toLowerCase() === username.toLowerCase());
    if (!player) {
      res.status(404).json({ error: 'ไม่พบบัญชีผู้เล่น' });
      return;
    }
    if (player.redeemedCodes.includes(reward.code.toUpperCase())) {
      res.status(409).json({ error: `บัญชีนี้ใช้โค้ด ${reward.code} ไปแล้ว` });
      return;
    }

    player.redeemedCodes.push(reward.code.toUpperCase());
    player.points += reward.points;
    writePlayersDb(db);
    res.json({ player: sanitizePlayer(player), reward });
  });

  // Vite dev middleware vs static production bundle
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NINJAREBORN full-stack portal listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
