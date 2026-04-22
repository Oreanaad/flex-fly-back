// paginareact/Backend/config/config.js
require('dotenv').config(); // Asegúrate de cargar tus variables de entorno

module.exports = {
  development: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    dialect: 'mssql', // Para SQL Server
    dialectOptions: {
      options: {
        encrypt: process.env.DB_ENCRYPT === 'true', // Use true for Azure SQL Database, false for local dev
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'true', // Change to true for local dev / self-signed certs
      }
    },
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    logging: console.log // Puedes deshabilitar esto en producción: false
  },
  production: {
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    dialect: 'mssql',
    dialectOptions: {
      options: {
        encrypt: process.env.DB_ENCRYPT === 'true', // Set to true for Azure SQL Database
        trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'true', // Set to false for production generally
      }
    },
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    },
    logging: false // Deshabilita el log SQL en producción
  }
};