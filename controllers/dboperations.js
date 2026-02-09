// controllers/dboperations.js
const sql = require('mssql');
const dbConfig = require('../dbconfig');

// ===== SINGLETON POOL =====
let poolPromise = null;
async function getPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(dbConfig)
      .then(p => { console.log('[MSSQL] Connected'); return p; })
      .catch(err => { console.error('[MSSQL] Connection error:', err); poolPromise = null; throw err; });
  }
  return poolPromise;
}
exports.getPool = getPool;

// ===== Tracking: ค้นหา + เรียงลำดับ +แบ่งหน้า =====
const SORTABLE = {
  CharlieNo: 'CharlieNo',
  DriverName: 'DriverName',
  PlateNo: 'PlateNo',
  Branch: 'Branch',
  Mileage: 'Mileage',
  Date: 'CheckingDateTime'
};

exports.queryPagedTracking = async ({
  q = '',
  page = 1,
  pageSize = 50,
  sortBy = 'Date',
  sortDir = 'DESC',
  charlieNo = '',
  driverName = '',
  dateFrom = '',
  dateTo = ''
}) => {
  const pool = await getPool();

  page = Math.max(parseInt(page, 10) || 1, 1);
  pageSize = Math.min(Math.max(parseInt(pageSize, 10) || 50, 1), 200);
  const offset = (page - 1) * pageSize;

  const sortCol = SORTABLE[`${sortBy}`] || 'CheckingDateTime';
  const dir = (String(sortDir).toUpperCase() === 'ASC') ? 'ASC' : 'DESC';

  const whereParts = [];
  const params = {};

  if (q && q.trim()) {
    params.q = `%${q.trim()}%`;
    whereParts.push(`
      (CharlieNo LIKE @q 
       OR DriverName LIKE @q 
       OR PlateNo LIKE @q 
       OR Branch LIKE @q)
    `);
  }

  if (charlieNo && charlieNo.trim()) {
    params.charlieNo = `%${charlieNo.trim()}%`;
    whereParts.push('CharlieNo LIKE @charlieNo');
  }

  if (driverName && driverName.trim()) {
    params.driverName = `%${driverName.trim()}%`;
    whereParts.push('DriverName LIKE @driverName');
  }

  if (dateFrom) {
    params.dateFrom = dateFrom;
    whereParts.push('CheckingDateTime >= @dateFrom');
  }

  if (dateTo) {
    params.dateTo = `${dateTo} 23:59:59.999`;
    whereParts.push('CheckingDateTime <= @dateTo');
  }

  const whereSql = whereParts.length
    ? `WHERE ${whereParts.join(' AND ')}`
    : '';

  // COUNT
  const countReq = pool.request();
  Object.entries(params).forEach(([k, v]) => {
    countReq.input(
      k,
      (k === 'dateFrom' || k === 'dateTo') ? sql.DateTime : sql.NVarChar,
      v
    );
  });

  const countRs = await countReq.query(`
    SELECT COUNT(1) AS total
    FROM dbo.VehicleInspections
    ${whereSql};
  `);

  const total = countRs.recordset?.[0]?.total || 0;

  // DATA
  const dataReq = pool.request();
  Object.entries(params).forEach(([k, v]) => {
    dataReq.input(
      k,
      (k === 'dateFrom' || k === 'dateTo') ? sql.DateTime : sql.NVarChar,
      v
    );
  });

  dataReq.input('offset', sql.Int, offset);
  dataReq.input('pageSize', sql.Int, pageSize);

  const dataRs = await dataReq.query(`
    SELECT
      Id,
      CharlieNo,
      DriverName,
      PlateNo,
      Branch,
      Mileage,
      CheckingDateTime AS [Date]
    FROM dbo.VehicleInspections
    ${whereSql}
    ORDER BY ${sortCol} ${dir}
    OFFSET @offset ROWS
    FETCH NEXT @pageSize ROWS ONLY;
  `);

  return {
    page,
    pageSize,
    total,
    rows: dataRs.recordset || [],
    sortBy,
    sortDir: dir
  };
};

// ===== NEW: ดึงรายละเอียดรายการเดียวตาม Id =====
exports.getInspectionById = async (id) => {
  const pool = await getPool();
  const req = pool.request();
  req.input('id', sql.Int, parseInt(id, 10));
  const rs = await req.query(`
    SELECT *
    FROM dbo.VehicleInspections
    WHERE Id = @id
  `);
  console.log('getInspectionById rs: ', rs);
  return rs.recordset?.[0] || null;
};
