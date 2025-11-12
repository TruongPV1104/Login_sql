const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cookieParser = require("cookie-parser");
const db = require('./db.js')
const bcrypt = require('bcrypt');
const { type } = require("os");

const port = 3000;
const app = express();
const SECRET = process.env.SECRET;
const RT_SECRET = process.env.RT_SECRET;
const SALT_ROUNDS = 10;

app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());

//Tuong tac voi sql
async function executeQuery(query, inputs=[]) {
  await db.poolConnect;
  const request = db.pool.request(); //Tao phien lam viec moi
  inputs.forEach(input => {
    request.input(input.name, input.type, input.value)
  })
  return request.query(query)
}

//Lay thong tin theo username
async function getUserByUsername(username)
{
  const query = `
    SELECT * FROM dbo.UserTest
    WHERE Username = @username`
  const result = await executeQuery(query,[
    { 
      name: "username",
      type: db.sql.VarChar,
      value: username
    }
  ])
  return result.recordset[0];
}

//Lay thong tin user theo FT
async function getUserByRefreshToken(refreshToken) {
  const query = `
  SELECT * FROM dbo.UserTest
  WHERE RefreshToken = @refreshToken
  `
  const result = await executeQuery(query,[
    {
      name: "refreshToken",
      type: db.sql.VarChar,
      value: refreshToken
    }
  ])
  return result.recordset[0]
}

//Update RT cho USer
async function updateRefreshToken(username, refreshToken) {
  const query = `
    UPDATE dbo.UserTest
    SET RefreshToken = @refreshToken
    WHERE Username = @username
  `
  return executeQuery(query,[
    {name: 'username', type: db.sql.VarChar, value: username},
    {name: 'refreshToken', type: db.sql.VarChar, value: refreshToken}
  ])
  
}

//Dang Ky
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, cfmPassword } = req.body;
    const testAlphaNumber = /^[a-z0-9]+$/i;
    //Dieu kien
    if (!username || !password || !cfmPassword) {
      return res.status(400).json({ message: "Vui long dien day di thong tin" });
    }
    if (password !== cfmPassword) {
      return res.status(400).json({ message: "Mat khau xac nhan khong khop" });
    }
    if (
      !testAlphaNumber.test(username) ||
      !testAlphaNumber.test(password) ||
      !testAlphaNumber.test(cfmPassword)
    ) {
      return res.json({
        message: "Ten dang nhap hoac mat khau khong duoc chua ky tu dac biet!",
      });
    }
    const existingUser = await getUserByUsername(username)
    console.log(existingUser)
    if(existingUser)
    {
      return res.status(400).json({message: "Ten tai khoan da duoc su dung"})
    }
    //Bam mat khau
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS)

    //Them vao Database
    const insertQuery = `
      INSERT INTO dbo.UserTest (Username, PasswordHash, RefreshToken)
      VALUES (@username, @passwordHash, @refreshToken)
    `
    await executeQuery(insertQuery,[
      {name: "username", type: db.sql.VarChar, value: username},
      {name: "passwordHash", type: db.sql.VarChar, value: passwordHash},
      {name: "refreshToken", type: db.sql.VarChar, value: null}
    ]) 

    res.json({message: "Dang ky thanh cong!"})
  } catch (err) {
    console.error("Loi khi dang ky: ",err)
    res.status(500).json('Loi may chu noi bo')
  }
});

//Xu ly dang nhap
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Vui long nhap day du thong tin!" });
    }
    
    const user = await getUserByUsername(username)
    if(!user || !(await bcrypt.compare(password, user.PasswordHash)))
    {
      return res.status(401).json({message: "Sai ten dang nhap hoac mat khau"})
    }

    //Cung cap AT va RT
    const token = jwt.sign({ username: user.Username }, SECRET, { expiresIn: "5m" });
    const refreshToken = jwt.sign({ username: user.Username }, RT_SECRET, { expiresIn: "1h" });

    //Luu RT trong database
    await updateRefreshToken(user.Username, refreshToken)

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60,
      sameSite: "Strict",
    });

    res.json({ message: "Dang nhap thanh cong", token });
  } catch (err) {
    console.error("Loi khi dang nhap",err)
    res.status(500).json({message: "Loi may chu noi bo"})
  }
});

//Xac thuc JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(403).json({ message: "Token het han" });
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token khong hop le hoac het han" });
    }
    req.user = user;
    next();
  });
}

//Cap lai AT
app.post("/api/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Thieu refresh token" });
    }
    
    const user = await getUserByRefreshToken(refreshToken)
    if (!user) {
      return res.status(403).json({ message: "Refresh token khong hop le" });
    }
    jwt.verify(refreshToken, RT_SECRET, (err, decode) => {
      if (err) {
        return res
          .status(401)
          .json({ message: "Refresh token het han, can dang nhap lai" });
      }
      const newAccessToken = jwt.sign({ username: decode.username }, SECRET, {
        expiresIn: "5m",
      });


      res.json({
        message: "Cap lai Access token thanh cong",
        token: newAccessToken,
      });
    });
  } catch (err) {
    console.error("Loi khi refresh token: ",err)
    res.status(500).json({message: "Loi may chu noi bo"})
  }
});

//Dang xuat, xoa cookie
app.post("/api/logout", (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ message: "Da dang xuat" });
});

app.get("/api/secret", verifyToken, (req, res) => {
  res.json({ message: "Xin chao day la khu vuc bi mat" });
  // console.log(res.token);
});

app.listen(port, (req, res) => {
  console.log(`App run on port http://localhost:${port}`);
});

// db.poolConnect
//   .then(() => {
//     app.listen(port, (req, res) => {
//       console.log(`App run on port http://localhost:${port}`);
//     });
//   })
//   .catch(err => {
//     console.error("Khong the khoi dong do loi ket noi CSDL", err)
//     process.exit(1)
//   })
