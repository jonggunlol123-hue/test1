require('dotenv').config();

const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const fs = require('fs');
const path = require('path');

const required = ['DATABASE_URL', 'SESSION_SECRET'];
for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`${key} 환경변수가 필요합니다.`);
  }
}

if (
  process.env.NODE_ENV === 'production' &&
  process.env.SESSION_SECRET.length < 32
) {
  throw new Error('운영 환경의 SESSION_SECRET은 32자 이상이어야 합니다.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'disable'
    ? false
    : process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const app = express();

app.disable('x-powered-by');

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));

app.use(session({
  name: 'goldmoon.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new PgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: '로그인 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.'
  }
});

const asyncRoute = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const stateSchema = z.object({
  members: z.array(z.record(z.string(), z.any())).max(5000),
  ranks: z.array(z.string().min(1).max(30)).min(1).max(100),
  ledger: z.array(z.record(z.string(), z.any())).max(20000),
  items: z.array(z.record(z.string(), z.any())).max(10000),
  loans: z.array(z.record(z.string(), z.any())).max(10000)
}).strict();

// 로그인한 사용자의 실제 DB 계정과 역할을 확인
const isAuthenticated = asyncRoute(async (req, res, next) => {
  if (req.session.adminId) {
    const result = await pool.query(
      `SELECT id, username, display_name
       FROM admins
       WHERE id = $1`,
      [req.session.adminId]
    );

    if (!result.rowCount) {
      await new Promise(resolve =>
        req.session.destroy(() => resolve())
      );

      return res.status(401).json({
        error: '관리자 계정을 확인할 수 없습니다. 다시 로그인해 주세요.'
      });
    }

    req.user = {
      id: result.rows[0].id,
      username: result.rows[0].username,
      display_name: result.rows[0].display_name,
      role: 'admin'
    };

    // 기존 관리자 비밀번호 변경 API와의 호환
    req.admin = req.user;

    return next();
  }

  if (req.session.viewerId) {
    const result = await pool.query(
      `SELECT id, username, display_name
       FROM viewer_accounts
       WHERE id = $1`,
      [req.session.viewerId]
    );

    if (!result.rowCount) {
      await new Promise(resolve =>
        req.session.destroy(() => resolve())
      );

      return res.status(401).json({
        error: '계정을 확인할 수 없습니다. 다시 로그인해 주세요.'
      });
    }

    req.user = {
      id: result.rows[0].id,
      username: result.rows[0].username,
      display_name: result.rows[0].display_name,
      role: 'viewer'
    };

    return next();
  }

  return res.status(401).json({
    error: '로그인이 필요합니다.'
  });
});

// 수정·삭제·계정 관리 등의 작업은 관리자만 가능
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: '관리자 권한이 필요합니다.'
    });
  }

  next();
}

// DB 초기화
async function initDb() {
  const schema = fs.readFileSync(
    path.join(__dirname, 'schema.sql'),
    'utf8'
  );

  await pool.query(schema);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      sid varchar NOT NULL COLLATE "default" PRIMARY KEY,
      sess json NOT NULL,
      expire timestamp(6) NOT NULL
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS user_sessions_expire_idx
    ON user_sessions(expire)
  `);

  // 조회 전용 계정 테이블
  await pool.query(`
    CREATE TABLE IF NOT EXISTS viewer_accounts (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(100) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    INSERT INTO app_state(id, payload)
    VALUES (1, $1::jsonb)
    ON CONFLICT (id) DO NOTHING
  `, [
    JSON.stringify({
      members: [],
      ranks: ['조직 두목', '부두목', '간부', '정회원', '신입'],
      ledger: [],
      items: [],
      loans: []
    })
  ]);

  // 최초 관리자 계정 생성. 기존 계정의 비밀번호는 덮어쓰지 않음.
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (username && password) {
    if (password.length < 12) {
      throw new Error('ADMIN_PASSWORD는 12자 이상으로 설정하세요.');
    }

    const hash = await bcrypt.hash(password, 12);

    await pool.query(`
      INSERT INTO admins(username, password_hash, display_name)
      VALUES ($1, $2, $3)
      ON CONFLICT(username) DO NOTHING
    `, [
      username,
      hash,
      process.env.ADMIN_DISPLAY_NAME || '조직 두목'
    ]);

    console.log(`초기 관리자 계정 확인 완료: ${username}`);
  }
}

// 서버 상태 확인
app.get('/healthz', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok' });
}));

// 로그인: 관리자 또는 조회 전용 계정
app.post('/api/login', loginLimiter, asyncRoute(async (req, res) => {
  const parsed = z.object({
    username: z.string().trim().min(1).max(64),
    password: z.string().min(1).max(200)
  }).safeParse(req.body);

  if (!parsed.success) {
    return res.status(400).json({
      error: '아이디와 비밀번호를 입력해 주세요.'
    });
  }

  const { username, password } = parsed.data;

  const admins = await pool.query(
    `SELECT id, username, password_hash
     FROM admins
     WHERE username = $1`,
    [username]
  );

  let account;
  let role;

  if (admins.rowCount) {
    if (!(await bcrypt.compare(password, admins.rows[0].password_hash))) {
      return res.status(401).json({
        error: '아이디 또는 비밀번호를 확인해 주세요.'
      });
    }

    account = admins.rows[0];
    role = 'admin';
  } else {
    const viewers = await pool.query(
      `SELECT id, username, password_hash
       FROM viewer_accounts
       WHERE username = $1`,
      [username]
    );

    if (
      !viewers.rowCount ||
      !(await bcrypt.compare(password, viewers.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: '아이디 또는 비밀번호를 확인해 주세요.'
      });
    }

    account = viewers.rows[0];
    role = 'viewer';
  }

  // 로그인할 때 세션 ID 재발급
  await new Promise((resolve, reject) => {
    req.session.regenerate(err => err ? reject(err) : resolve());
  });

  if (role === 'admin') {
    req.session.adminId = account.id;
  } else {
    req.session.viewerId = account.id;
  }

  await new Promise((resolve, reject) => {
    req.session.save(err => err ? reject(err) : resolve());
  });

  res.json({ ok: true, role });
}));

// 현재 로그인 사용자 확인
app.get('/api/me', asyncRoute(async (req, res) => {
  let result;
  let role;

  if (req.session.adminId) {
    role = 'admin';

    result = await pool.query(
      `SELECT username, display_name
       FROM admins WHERE id = $1`,
      [req.session.adminId]
    );
  } else if (req.session.viewerId) {
    role = 'viewer';

    result = await pool.query(
      `SELECT username, display_name
       FROM viewer_accounts WHERE id = $1`,
      [req.session.viewerId]
    );
  } else {
    return res.json({ authenticated: false });
  }

  if (!result.rowCount) {
    await new Promise(resolve =>
      req.session.destroy(() => resolve())
    );

    return res.json({ authenticated: false });
  }

  res.json({
    authenticated: true,
    admin: {
      username: result.rows[0].username,
      name: result.rows[0].display_name
    },
    role
  });
}));

// 로그아웃
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('goldmoon.sid', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });

    if (err) {
      return res.status(500).json({
        error: '로그아웃에 실패했습니다.'
      });
    }

    res.json({ ok: true });
  });
});

// 데이터 조회: 관리자와 조회 전용 계정 모두 가능
app.get('/api/data', isAuthenticated, asyncRoute(async (req, res) => {
  const result = await pool.query(
    'SELECT payload FROM app_state WHERE id = 1'
  );

  res.json({
    ...result.rows[0].payload,
    admin: {
      username: req.user.username,
      name: req.user.display_name
    },
    role: req.user.role
  });
}));

// 데이터 수정: 관리자만 가능
app.put(
  '/api/data',
  isAuthenticated,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const parsed = stateSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: '데이터 형식이 올바르지 않습니다.'
      });
    }

    await pool.query(
      `UPDATE app_state
       SET payload = $1::jsonb, updated_at = NOW()
       WHERE id = 1`,
      [JSON.stringify(parsed.data)]
    );

    res.json({ ok: true });
  })
);

// 관리자 비밀번호 변경
app.post(
  '/api/password',
  isAuthenticated,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const parsed = z.object({
      currentPassword: z.string().min(1).max(200),
      newPassword: z.string().min(12).max(200)
    }).safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: '새 비밀번호는 12자 이상이어야 합니다.'
      });
    }

    const result = await pool.query(
      'SELECT password_hash FROM admins WHERE id = $1',
      [req.admin.id]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        parsed.data.currentPassword,
        result.rows[0].password_hash
      ))
    ) {
      return res.status(400).json({
        error: '현재 비밀번호가 올바르지 않습니다.'
      });
    }

    const hash = await bcrypt.hash(parsed.data.newPassword, 12);

    await pool.query(
      `UPDATE admins
       SET password_hash = $1, updated_at = NOW()
       WHERE id = $2`,
      [hash, req.admin.id]
    );

    res.json({ ok: true });
  })
);

// 조회 전용 계정 목록: 관리자만
app.get(
  '/api/viewer-accounts',
  isAuthenticated,
  requireAdmin,
  asyncRoute(async (_req, res) => {
    const result = await pool.query(`
      SELECT id, username, display_name, created_at
      FROM viewer_accounts
      ORDER BY id DESC
    `);

    res.json(result.rows);
  })
);

// 조회 전용 계정 생성: 관리자만
app.post(
  '/api/viewer-accounts',
  isAuthenticated,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const parsed = z.object({
      username: z.string()
        .trim()
        .regex(/^[a-zA-Z0-9_-]{3,50}$/),
      password: z.string().min(12).max(72),
      displayName: z.string().trim().min(1).max(100)
    }).safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: '아이디는 영문·숫자·_-로 3~50자, 비밀번호는 12자 이상이어야 합니다.'
      });
    }

    const { username, password, displayName } = parsed.data;

    // 관리자 계정과 조회 계정의 아이디 중복 방지
    const adminExists = await pool.query(
      'SELECT 1 FROM admins WHERE username = $1',
      [username]
    );

    if (adminExists.rowCount) {
      return res.status(409).json({
        error: '이미 사용 중인 아이디입니다.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    try {
      const result = await pool.query(
        `INSERT INTO viewer_accounts
          (username, password_hash, display_name)
         VALUES ($1, $2, $3)
         RETURNING id, username, display_name, created_at`,
        [username, passwordHash, displayName]
      );

      res.status(201).json(result.rows[0]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({
          error: '이미 사용 중인 아이디입니다.'
        });
      }

      throw err;
    }
  })
);

// 조회 전용 계정 삭제: 관리자만
app.delete(
  '/api/viewer-accounts/:id',
  isAuthenticated,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({
        error: '잘못된 계정 번호입니다.'
      });
    }

    const result = await pool.query(
      `DELETE FROM viewer_accounts
       WHERE id = $1
       RETURNING id`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: '계정을 찾을 수 없습니다.'
      });
    }

    res.json({ ok: true });
  })
);

app.use(express.static(
  path.join(__dirname, 'public'),
  {
    index: 'index.html',
    maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
  }
));

app.use((err, req, res, _next) => {
  console.error(err);

  if (res.headersSent) return;

  res.status(500).json({
    error: '서버 오류가 발생했습니다.'
  });
});

const port = Number(process.env.PORT || 3000);

initDb()
  .then(() => {
    app.listen(port, '0.0.0.0', () => {
      console.log(`Gold Moon portal listening on ${port}`);
    });
  })
  .catch(err => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
