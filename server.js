//server.js dvc_api
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const ActiveDirectory = require('activedirectory2');
const {
  queryPagedTracking,
  getInspectionById,
  getPool
} = require('./controllers/dboperations');
const sql = require('mssql');
const app = express();
app.use(cors());
app.use(express.json());
// ============================
// AD CONFIG
// ============================
const adConfig = {
  url: process.env.AD_URL,
  baseDN: process.env.AD_BASE_DN,
  username: process.env.AD_USERNAME,
  password: process.env.AD_PASSWORD,
  referrals: { enabled: false },
  ldapOptions: {
    connectTimeout: 3000,
    timeout: 5000,
    idleTimeout: 60000,
  },
};
const ad = new ActiveDirectory(adConfig);
// ============================
// Health check
// ============================
app.get('/ping', (req, res) => res.send('ok'));
// ============================
// Request log
// ============================
app.use((req, res, next) => {
  console.log('HIT', req.method, req.url);
  next();
});
// ============================
// Mask helper
// ============================
const mask = s =>
  (typeof s === 'string'
    ? (s.length <= 3 ? '***'
      : s[0] + '*'.repeat(Math.min(8, s.length - 2)) + s.slice(-1))
    : s);
const log = (...a) => console.log('[AUTH]', ...a);
// ============================
// LDAP error mapping
// ============================
const ldap49Message = detail => {
  const d = String(detail).toLowerCase();
  if (d.includes('data 525')) return 'User not found';
  if (d.includes('data 52e')) return 'Invalid username or password';
  if (d.includes('data 530')) return 'Not permitted to logon at this time';
  if (d.includes('data 532')) return 'Password expired';
  if (d.includes('data 533')) return 'Account disabled';
  if (d.includes('data 701')) return 'Account expired';
  if (d.includes('data 773')) return 'User must change password at next logon';
  if (d.includes('data 775')) return 'Account locked';
  return 'Invalid credentials';
};

// ============================
// Auth helper with timeout
// ============================
const authWithTimeout = (loginName, password, timeoutMs = 4000) =>
  new Promise(resolve => {
    let done = false;
    const t = setTimeout(() => {
      if (done) return;
      done = true;
      resolve({
        userTried: loginName,
        ok: false,
        err: new Error('Timeout'),
        ms: timeoutMs
      });
    }, timeoutMs);

    const t0 = Date.now();
    ad.authenticate(loginName, password, (err, ok) => {
      if (done) return;
      done = true;
      clearTimeout(t);

      const ms = Date.now() - t0;
      resolve({
        userTried: loginName,
        ok: !!ok,
        err,
        ms
      });
    });
  });
// ============================
// Cache for AD format (LRU)
// ============================
const FORMAT_CACHE_MAX = 200;
const formatCache = new Map();

const cacheGet = k => {
  if (!formatCache.has(k)) return null;
  const v = formatCache.get(k);
  formatCache.delete(k);
  formatCache.set(k, v);
  return v;
};

const cacheSet = (k, v) => {
  if (formatCache.has(k)) formatCache.delete(k);
  formatCache.set(k, { ...v, ts: Date.now() });
  if (formatCache.size > FORMAT_CACHE_MAX) {
    const firstKey = formatCache.keys().next().value;
    formatCache.delete(firstKey);
  }
};

// ============================
// AD Authentication
// ============================
// ============================
// AD Authentication
// ============================
app.post('/auth_ad', async (req, res) => {
  try {
    let { username, password } = req.body || {};
    username = (username ?? '').trim();
    password = (password ?? '');

    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    log('ENV url=', process.env.AD_URL);
    log('ENV baseDN=', process.env.AD_BASE_DN);
    log('ENV bind user=', process.env.AD_USERNAME);
    log('ENV pass=', mask(process.env.AD_PASSWORD));

    const cacheKey = username.toLowerCase();
    const cached = cacheGet(cacheKey);

    if (cached?.fmt) {
      const loginName =
        cached.fmt === 'UPN'
          ? (username.includes('@') ? username : `${username}@gfcs.co.th`)
          : `GFCS\\${username}`;

      const r = await authWithTimeout(loginName, password, 3000);
      if (r.ok) {
        log(`✓ FAST PASS [cache ${cached.fmt}]`, loginName);
        return res.json({ success: true, user: loginName, cached: true });
      }
    }

    // ----------------------------
    // 🔥 CLEAN CANDIDATES
    // ----------------------------
    let candidates = [];

    if (username.includes('@') || username.includes('\\')) {
      candidates = [username];
    } else {
      candidates = [
        `${username}@gfcs.co.th`,
        `GFCS\\${username}`,
      ];
    }

    candidates = [...new Set(candidates)];
    log('candidates =', candidates);

    const results = await Promise.all(
      candidates.map(c => authWithTimeout(c, password, 4000))
    );

    const winner = results.find(r => r.ok);
    if (winner) {
      const fmt = winner.userTried.includes('@') ? 'UPN' : 'DL_GFCS';
      cacheSet(cacheKey, { fmt });

      log(`✓ PASS ${winner.userTried}`);
      return res.json({ success: true, user: winner.userTried });
    }

    const firstErr = results.find(r => r.err)?.err;
    const message = firstErr ? ldap49Message(firstErr) : 'Authentication failed';

    log('FAIL:', message);
    return res.status(401).json({
      success: false,
      message,
      candidates,
    });

  } catch (e) {
    console.error('AUTH ERR:', e);
    res.status(500).json({ error: 'Auth error', detail: String(e) });
  }
});
// ============================
// Tracking list (paged)
// ============================
app.get('/api/tracking', async (req, res) => {
  try {
    const {
      q = '',
      page = '1',
      pageSize = '50',
      sortBy = 'Date',
      sortDir = 'DESC',
      // ✅ advanced search
      charlieNo = '',
      driverName = '',
      dateFrom = '',
      dateTo = ''
    } = req.query;

    const result = await queryPagedTracking({
      q, page, pageSize, sortBy, sortDir,// ส่งต่อให้ db layer
      charlieNo,
      driverName,
      dateFrom,
      dateTo
    });

    res.json(result);
  } catch (err) {
    console.error('GET /api/tracking error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// ============================
// Tracking detail by ID
// ============================
app.get('/api/tracking/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const row = await getInspectionById(id);
    if (!row) return res.status(404).json({ error: 'Not Found' });
    res.json(row);
  } catch (err) {
    console.error('GET /api/tracking/:id error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// ============================
// Dashboard top vehicle used
// ============================
app.get('/top_Vehicle_used', async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT TOP (5) PlateNo, TotalChecks
      FROM top_Vehicle_used
      ORDER BY TotalChecks DESC;
    `);

    const rows = result.recordset || [];
    const labels = rows.map(r => r.PlateNo);
    const counts = rows.map(r => Number(r.TotalChecks) || 0);
    const total = counts.reduce((a, b) => a + b, 0);

    res.json({ labels, counts, total });
  } catch (err) {
    console.error('[dashboard/top5-used] error:', err);
    res.status(500).json({ error: 'Failed to query dashboard data.' });
  }
});
// ============================
// Dashboard abnormal
// ============================
app.get('/top5-abnormal', async (req, res) => {
  try {
    const pool = await getPool();
    const result = await pool.request().query(`
      SELECT TOP (5) CheckItem, AbnormalCount
      FROM dbo.v_AbnormalCounts
      ORDER BY AbnormalCount DESC;
    `);

    const rows = result.recordset || [];
    const labels = rows.map(r => r.CheckItem);
    const counts = rows.map(r => Number(r.AbnormalCount) || 0);
    const total = counts.reduce((a, b) => a + b, 0);

    res.json({ labels, counts, total });
  } catch (err) {
    console.error('/dashboard/top5-abnormal] error:', err);
    res.status(500).json({ error: 'Failed to query dashboard data.' });
  }
});
// ============================
// Dashboard summary
// ============================
app.get('/dashboard/summary', async (req, res) => {
  try {
    const pool = await getPool();
    // const fixedDate = '2025-07-31';
    const fixedDate = new Date().toISOString().slice(0, 10);
    console.log('/dashboard/summary fixedDate:', fixedDate);

    const total = await pool.request().execute('sp_get_total_vehicle');

    const used = await pool.request()
      .input('workDate', sql.Date, fixedDate)
      .execute('sp_get_used_vehicle_today');

    const unused = await pool.request()
      .input('workDate', sql.Date, fixedDate)
      .execute('sp_get_unused_vehicle_today');

    res.json({
      totalVehicles: total.recordset[0].totalVehicles,
      usedVehicles: used.recordset[0].usedVehicles,
      unusedVehicles: unused.recordset[0].unusedVehicles
    });

  } catch (err) {
    console.error('/dashboard/summary error:', err);
    res.status(500).json({ error: 'Failed to load dashboard summary' });
  }
});
// ======================================================
// FILTER / SORT / PAGINATE HELPERS (GLOBAL)
// ======================================================
const VALID_FILTERS = {
  total: ['CharlieNo', 'PlateNo', 'Branch'],
  unused: ['CharlieNo', 'PlateNo', 'Branch'],
  used: ['CharlieNo', 'DriverName', 'PlateNo', 'Branch', 'Mileage', 'CreateDate'],
  // ⭐ NEW: monthly
  monthly: ['CharlieNo', 'DriverName', 'PlateNo', 'Branch', 'Mileage', 'CreateDate']
};
function applyFilters(rows, rawFilters, type) {
  const allowed = VALID_FILTERS[type] || [];
  const filters = {};

  allowed.forEach(key => {
    if (rawFilters[key] && String(rawFilters[key]).trim() !== "") {
      filters[key] = String(rawFilters[key]).toLowerCase();
    }
  });

  return rows.filter(r =>
    Object.entries(filters).every(([key, val]) => {
      const col = r[key];
      if (col == null) return false;
      return String(col).toLowerCase().includes(val);
    })
  );
}
function applySort(rows, sortBy, sortDir, type) {
  const allowed = VALID_FILTERS[type] || [];
  if (!allowed.includes(sortBy)) return rows;

  return rows.sort((a, b) => {
    const x = a[sortBy] ?? "";
    const y = b[sortBy] ?? "";
    return sortDir === "ASC" ? (x > y ? 1 : -1) : (x < y ? 1 : -1);
  });
}
function paginate(rows, page, pageSize) {
  const start = (page - 1) * pageSize;
  return rows.slice(start, start + pageSize);
}
// ============================================================
// 🔵 TOTAL VEHICLE LIST (Stored Procedure)
// ============================================================
app.get('/api/dashboard/list/total', async (req, res) => {
  try {
    const pool = await getPool();

    const result = await pool.request()
      .execute("sp_dashboard_list_total");

    let rows = result.recordset || [];

    rows = applyFilters(rows, req.query, "total");
    rows = applySort(rows, req.query.sortBy || "CharlieNo", req.query.sortDir || "ASC", "total");

    const page = Number(req.query.page || 1);
    const pageSize = Number(req.query.pageSize || 10);

    const total = rows.length;
    const pageRows = paginate(rows, page, pageSize);

    res.json({ rows: pageRows, total, page, pageSize });

  } catch (err) {
    console.error("/api/dashboard/list/total error:", err);
    res.status(500).json({ error: "Failed to load total vehicle list" });
  }
});
// ============================================================
// 🔵 USED VEHICLE LIST (Stored Procedure)
// ============================================================
app.get('/api/dashboard/list/used', async (req, res) => {
  try {
    const pool = await getPool();
    // const fixedDate = "2025-07-31";
    const fixedDate = new Date().toISOString().slice(0, 10);
    // console.log('fixedDate:', fixedDate);

    const result = await pool.request()
      .input("workDate", sql.Date, fixedDate)
      .execute("sp_dashboard_list_used");

    let rows = result.recordset || [];

    rows = applyFilters(rows, req.query, "used");
    rows = applySort(rows, req.query.sortBy || "CharlieNo", req.query.sortDir || "ASC", "used");

    const page = Number(req.query.page || 1);
    const pageSize = Number(req.query.pageSize || 10);

    const total = rows.length;
    const pageRows = paginate(rows, page, pageSize);

    res.json({ rows: pageRows, total, page, pageSize });

  } catch (err) {
    console.error("/api/dashboard/list/used error:", err);
    res.status(500).json({ error: "Failed to load used vehicle list" });
  }
});
// ============================================================
// 🔵 UNUSED VEHICLE LIST (Stored Procedure)
// ============================================================
app.get('/api/dashboard/list/unused', async (req, res) => {
  try {
    const pool = await getPool();
    // const fixedDate = "2025-07-31";
    const fixedDate = new Date().toISOString().slice(0, 10);

    const result = await pool.request()
      .input("workDate", sql.Date, fixedDate)
      .execute("sp_dashboard_list_unused");

    let rows = result.recordset || [];

    rows = applyFilters(rows, req.query, "unused");
    rows = applySort(rows, req.query.sortBy || "CharlieNo", req.query.sortDir || "ASC", "unused");

    const page = Number(req.query.page || 1);
    const pageSize = Number(req.query.pageSize || 10);

    const total = rows.length;
    const pageRows = paginate(rows, page, pageSize);

    res.json({ rows: pageRows, total, page, pageSize });

  } catch (err) {
    console.error("/api/dashboard/list/unused error:", err);
    res.status(500).json({ error: "Failed to load unused vehicle list" });
  }
});
app.get('/api/dashboard/problem', async (req, res) => {
  try {
    const pool = await getPool();

    const startDate = req.query.startDate || "2000-01-01";
    const endDate = req.query.endDate || "2100-12-31";

    // 🚀 เรียก Stored Procedure แทน SQL Query ตรงๆ
    const result = await pool.request()
      .input("startDate", sql.DateTime, startDate)
      .input("endDate", sql.DateTime, endDate)
      .execute("sp_dashboard_problem_report");

    let rows = result.recordset || [];

    // -------------------------
    // 🔍 FILTERS
    // -------------------------
    Object.entries(req.query).forEach(([k, v]) => {
      if (["page","pageSize","sortBy","sortDir","startDate","endDate"].includes(k)) return;
      if (!v) return;

      rows = rows.filter(r =>
        String(r[k] ?? "").toLowerCase().includes(String(v).toLowerCase())
      );
    });

    // -------------------------
    // 🔼 SORTING
    // -------------------------
    const sortBy = req.query.sortBy || "CreateDate";
    const sortDir = req.query.sortDir || "DESC";

    rows.sort((a, b) => {
      const x = a[sortBy], y = b[sortBy];
      return sortDir === "ASC"
        ? (x > y ? 1 : -1)
        : (x < y ? 1 : -1);
    });

    // -------------------------
    // 📄 PAGING
    // -------------------------
    const page = Number(req.query.page || 1);
    const pageSize = Number(req.query.pageSize || 10);
    const total = rows.length;
    const start = (page - 1) * pageSize;

    res.json({
      rows: rows.slice(start, start + pageSize),
      total,
      page,
      pageSize
    });

  } catch (err) {
    console.error("problem report error:", err);
    res.status(500).json({ error: "failed to load problem report" });
  }
});
// ======================================================
// FILTER / SORT / PAGINATE HELPERS (GLOBAL)
// ======================================================
function applyFilters(rows, rawFilters, type) {
  const allowed = VALID_FILTERS[type] || []
  const filters = {}

  allowed.forEach(key => {
    if (rawFilters[key] && String(rawFilters[key]).trim() !== '') {
      filters[key] = String(rawFilters[key]).toLowerCase()
    }
  })

  return rows.filter(r =>
    Object.entries(filters).every(([key, val]) => {
      const col = r[key]
      if (col == null) return false
      return String(col).toLowerCase().includes(val)
    })
  )
}
function applySort(rows, sortBy, sortDir, type) {
  const allowed = VALID_FILTERS[type] || []
  if (!allowed.includes(sortBy)) return rows

  return rows.sort((a, b) => {
    const x = a[sortBy] ?? ''
    const y = b[sortBy] ?? ''
    return sortDir === 'ASC' ? (x > y ? 1 : -1) : x < y ? 1 : -1
  })
}
function paginate(rows, page, pageSize) {
  const start = (page - 1) * pageSize
  return rows.slice(start, start + pageSize)
}

// 🔵 MONTHLY VEHICLE SUMMARY LIST (Stored Procedure ใหม่)
// ============================================================
app.get('/api/dashboard/list/monthly', async (req, res) => {
  try {
    const pool = await getPool();

    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentYear = now.getFullYear();

    let fromMonth = parseInt(req.query.fromMonth, 10);
    let toMonth = parseInt(req.query.toMonth, 10);
    let year = parseInt(req.query.year, 10);

    if (!Number.isFinite(fromMonth) || fromMonth < 1 || fromMonth > 12) {
      fromMonth = currentMonth;
    }
    if (!Number.isFinite(toMonth) || toMonth < 1 || toMonth > 12) {
      toMonth = currentMonth;
    }
    if (!Number.isFinite(year) || year < 2000 || year > 2100) {
      year = currentYear;
    }

    if (fromMonth > toMonth) {
      const tmp = fromMonth;
      fromMonth = toMonth;
      toMonth = tmp;
    }

    const result = await pool.request()
      .input('fromMonth', sql.Int, fromMonth)
      .input('toMonth', sql.Int, toMonth)
      .input('year', sql.Int, year)
      .execute('sp_dashboard_list_monthly');

    let rows = result.recordset || [];

    // ใช้ filter/sort/paging helper เดิม
    rows = applyFilters(rows, req.query, 'monthly');
    rows = applySort(
      rows,
      req.query.sortBy || 'CharlieNo',
      req.query.sortDir || 'ASC',
      'monthly'
    );

    const page = Number(req.query.page || 1);
    const pageSize = Number(req.query.pageSize || 10);
    const total = rows.length;
    const pageRows = paginate(rows, page, pageSize);

    res.json({ rows: pageRows, total, page, pageSize });
  } catch (err) {
    console.error('/api/dashboard/list/monthly error:', err);
    res.status(500).json({ error: 'Failed to load monthly vehicle summary list' });
  }
});
// ===============================================================
// START SERVER
// ===============================================================
const PORT = process.env.PORT || 4001;
const server = app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
  console.log('[Boot] file =', __filename);
});
// Shutdown
process.on('SIGINT', () => { server.close(() => process.exit(0)); });
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
