const sql = require('mssql')
require("dotenv").config();

const user = process.env.USER;
const password = process.env.PASSWORD;
const server = process.env.SERVER;
const database = process.env.DATABASE;

const config ={
    user,
    password,
    server,
    database,
    options:{
        enableArithAbort: true,
        trustServerCertificate: true,
    }
}

const pool = new sql.ConnectionPool(config)//Tao 
const poolConnect = pool.connect()

pool.on('error',err => {
    console.error('SQL Pool Error',err)
})

module.exports = {
    sql,
    poolConnect,
    pool
}