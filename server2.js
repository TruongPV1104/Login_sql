// server.js
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); // 🔑 Thêm bcrypt
const db = require("./db"); // 📦 Import module CSDL
require("dotenv").config();
const cookieParser = require("cookie-parser");

const port = 3000;
const app = express();
const SECRET = process.env.SECRET;
const RT_SECRET = process.env.RT_SECRET;
const SALT_ROUNDS = 10; // Số vòng lặp băm mật khẩu

app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());

// Hàm hỗ trợ tương tác với CSDL
async function executeQuery(query, inputs = []) {
    await db.poolConnect; // Chờ pool kết nối
    const request = db.pool.request();
    inputs.forEach(input => {
        request.input(input.name, input.type, input.value);
    });
    return request.query(query);
}

// Hàm lấy thông tin người dùng theo tên đăng nhập
async function getUserByUsername(username) {
    const query = `
        SELECT * FROM dbo.UserAuthentication 
        WHERE UserName = @username
    `;
    const result = await executeQuery(query, [
        { name: 'username', type: db.sql.NVarChar, value: username }
    ]);
    return result.recordset[0]; // Trả về người dùng đầu tiên hoặc undefined
}

// Hàm lấy thông tin người dùng theo Refresh Token
async function getUserByRefreshToken(refreshToken) {
    const query = `
        SELECT * FROM dbo.UserAuthentication 
        WHERE RefreshToken = @refreshToken
    `;
    const result = await executeQuery(query, [
        { name: 'refreshToken', type: db.sql.NVarChar(255), value: refreshToken }
    ]);
    return result.recordset[0];
}

// Cập nhật Refresh Token cho người dùng
async function updateRefreshToken(username, refreshToken) {
    const query = `
        UPDATE dbo.UserAuthentication
        SET RefreshToken = @refreshToken
        WHERE UserName = @username
    `;
    return executeQuery(query, [
        { name: 'username', type: db.sql.NVarChar, value: username },
        { name: 'refreshToken', type: db.sql.NVarChar(255), value: refreshToken }
    ]);
}


// 📝 Đăng Ký - Thay thế JSON bằng SQL Server
app.post("/api/register", async (req, res) => {
    try {
        const { username, password, cfmPassword } = req.body;
        const testAlphaNumber = /^[a-z0-9]+$/i;

        if (!username || !password || !cfmPassword) {
            return res.status(400).json({ message: "Vui long dien day du thong tin" });
        }
        if (password !== cfmPassword) {
            return res.status(400).json({ message: "Mat khau xac nhan khong khop" });
        }
        if (
            !testAlphaNumber.test(username) ||
            !testAlphaNumber.test(password)
        ) {
            return res.status(400).json({
                message: "Ten dang nhap hoac mat khau khong duoc chua ky tu dac biet!",
            });
        }

        // 1. Kiểm tra người dùng đã tồn tại
        const existingUser = await getUserByUsername(username);
        if (existingUser) {
            return res.status(400).json({ message: "Ten dang nhap da duoc su dung" });
        }

        // 2. Hash mật khẩu
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // 3. Insert vào CSDL
        const insertQuery = `
            INSERT INTO dbo.UserAuthentication (UserName, PasswordHash, IsActive, RegistrationDate, RefreshToken)
            VALUES (@username, @passwordHash, @isActive, @regDate, @refreshToken)
        `;
        
        await executeQuery(insertQuery, [
            { name: 'username', type: db.sql.NVarChar, value: username },
            { name: 'passwordHash', type: db.sql.NVarChar(255), value: passwordHash },
            { name: 'isActive', type: db.sql.Bit, value: true },
            { name: 'regDate', type: db.sql.DateTime2, value: new Date() },
            { name: 'refreshToken', type: db.sql.NVarChar(255), value: null } // Ban đầu là NULL
        ]);

        res.json({ message: "Dang ky thanh cong!" });

    } catch (err) {
        console.error('Lỗi khi đăng ký:', err);
        res.status(500).json({ message: "Lỗi máy chủ nội bộ." });
    }
});

// 🔒 Xử lý đăng nhập - Thay thế JSON bằng SQL Server
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: "Vui long nhap day du thong tin!" });
        }

        // 1. Tìm người dùng
        const user = await getUserByUsername(username);

        // 2. Xác thực mật khẩu
        if (!user || !(await bcrypt.compare(password, user.PasswordHash))) {
            return res.status(401).json({ message: "Sai ten dang nhap hoac mat khau" });
        }
        
        // 3. Cung cấp AT và RT
        const token = jwt.sign({ username: user.UserName }, SECRET, { expiresIn: "5m" });
        const refreshToken = jwt.sign({ username: user.UserName }, RT_SECRET, { expiresIn: "1h" });

        // 4. Lưu RT trong CSDL
        await updateRefreshToken(user.UserName, refreshToken);

        // 5. Trả về kết quả
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60,
            sameSite: "Strict",
        });
        res.json({ message: "Dang nhap thanh cong", token });

    } catch (err) {
        console.error('Lỗi khi đăng nhập:', err);
        res.status(500).json({ message: "Lỗi máy chủ nội bộ." });
    }
});

// Xac thuc JWT (Giữ nguyên)
function verifyToken(req, res, next) {
    // ... (Giữ nguyên code verifyToken) ...
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
        return res.status(403).json({ message: "Token het han (khong co token)" });
    }
    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: "Token khong hop le hoac het han" });
        }
        req.user = user;
        next();
    });
}

// 🔄 Cấp lại AT - Thay thế JSON bằng SQL Server
app.post("/api/refresh", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ message: "Thieu refresh token" });
        }

        // 1. Tìm người dùng bằng Refresh Token trong CSDL
        const user = await getUserByRefreshToken(refreshToken);
        if (!user) {
            return res.status(403).json({ message: "Refresh token khong hop le" });
        }
        
        // 2. Xác thực Refresh Token
        jwt.verify(refreshToken, RT_SECRET, async (err, decode) => {
            if (err) {
                // Xóa RT hết hạn trong CSDL để bảo mật
                await updateRefreshToken(user.UserName, null); 
                return res.status(401).json({ 
                    message: "Refresh token het han, can dang nhap lai" 
                });
            }
            
            // 3. Cấp Access Token mới
            const newAccessToken = jwt.sign({ username: decode.username }, SECRET, {
                expiresIn: "5m",
            });
            
            // 4. Cấp Refresh Token mới (tùy chọn: xoay vòng RT)
            const newRefreshToken = jwt.sign({ username: user.UserName }, RT_SECRET, { expiresIn: "1h" });
            await updateRefreshToken(user.UserName, newRefreshToken); // Lưu RT mới vào CSDL

            // 5. Cài đặt lại Cookie RT
            res.cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                maxAge: 1000 * 60 * 60,
                sameSite: "Strict",
            });

            res.json({
                message: "Cap lai Access token thanh cong",
                token: newAccessToken,
            });
        });

    } catch (err) {
        console.error('Lỗi khi refresh token:', err);
        res.status(500).json({ message: "Lỗi máy chủ nội bộ." });
    }
});

// 🚪 Đăng xuất - Xóa RT trong CSDL
app.post("/api/logout", async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) {
            const user = await getUserByRefreshToken(refreshToken);
            if (user) {
                await updateRefreshToken(user.UserName, null); // Xóa RT khỏi CSDL
            }
        }
        res.clearCookie("refreshToken");
        res.json({ message: "Da dang xuat" });
    } catch (err) {
        console.error('Lỗi khi logout:', err);
        res.status(500).json({ message: "Lỗi máy chủ nội bộ." });
    }
});

// ... (Các route khác giữ nguyên)
app.get("/api/secret", verifyToken, (req, res) => {
    res.json({ message: `Xin chao ${req.user.username}, day la khu vuc bi mat` });
});


// Khởi động server chỉ khi CSDL đã sẵn sàng
db.poolConnect
    .then(() => {
        app.listen(port, () => {
            console.log(`App run on port http://localhost:${port}`);
        });
    })
    .catch(err => {
        console.error('Không thể khởi động ứng dụng do lỗi kết nối CSDL:', err.message);
        process.exit(1);
    });