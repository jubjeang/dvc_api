require('dotenv').config();

const config = {
  user: process.env.DB_UN,               // ex: 'sa'
  password: process.env.DB_PW,           // ex: 'yourStrong(!)Password'
  server: process.env.DB_SERVER,         // ex: '192.168.100.24'
  database: process.env.DB_DATABASE,     // ex: 'DailyVehicle'
  options: {
    encrypt: false,
    trustServerCertificate: true,
    enableArithAbort: true,
    validateBulkLoadParameters: false,
    rowCollectionOnRequestCompletion: true
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

module.exports = config;
