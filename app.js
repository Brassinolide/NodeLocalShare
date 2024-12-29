const express = require("express");
const socketIO = require("socket.io");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
window = this;
const JSEncrypt = require("jsencrypt");

const config = require("./config");
const errorEnums = require("./error");

const app = express();

//检测路径穿越
//简单有效，但存在假阳性的情况（笑
function CheckSecurity(check) {
    if (/(\/\.\.|\\\.\.|%5C\.\.|%2F\.\.|\.\.\\|\.\.\/|\.\.%5C|\.\.%2F)/i.test(check)) {
        return true;
    }
    return false;
}

app.use((req, res, next) => {
    if (CheckSecurity(req.url)) {
        res.status(403).end();
    } else {
        next();
    }
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    express.static(path.join(__dirname, "web"), {
        maxAge: 600000,
    })
);

//生成随机字符串
function GetRandomString(len = 10) {
    const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    var result = "";
    for (var i = len; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}

//获取客户端IP
//X-Forwarded-For用户可控，放到最后
//req.connection已弃用，放到req.socket后面
function GetClientIP(req) {
    return req.socket.remoteAddress || req.connection.remoteAddress || req.connection.socket.remoteAddress || req.ip || req.headers["X-Forwarded-For"] || "";
}

//计算客户端指纹
//IP + UA + 偏好语言 + Sec-Ch-Ua
//除了IP其他的都是草台班子，用户都可控（笑
function GetClientFinger(req) {
    return crypto
        .createHash("sha1")
        .update(GetClientIP(req) + (req.headers["user-agent"] || "") + (req.headers["accept-language"] || "") + (req.headers["sec-ch-ua"] || "") + config.serverConfig.salt)
        .digest("hex");
}

//解析token，成功返回用户名，失败返回null
function ParseToken(req) {
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        const cookies = cookieHeader.split(";").map((cookie) => cookie.trim().split("="));
        const token = cookies.find((cookie) => cookie[0] === "token");

        if (token) {
            try {
                const decoded = jwt.verify(token[1], config.serverConfig.salt);
                //token指纹无效，当成访客处理
                if (decoded["finger"] !== GetClientFinger(req)) {
                    return null;
                }
                return decoded.user;
            } catch (error) {
                return null;
            }
        }
    }
    return null;
}

function RequirePrivilege(priv) {
    return function (req, res, next) {
        const user = ParseToken(req);

        if (user) {
            if (config.user_db[user]["privilege"].includes(priv)) {
                next();
            } else {
                res.send(responseJson({ error: "ERR_NO_PRIVILEGE", message: `用户 ${user} 无 ${priv} 权限` }));
            }
        } else {
            if (config.user_db.allow_guest_login) {
                if (config.user_db.guest_privilege.includes(priv)) {
                    next();
                } else {
                    res.send(responseJson({ error: "ERR_NO_PRIVILEGE", message: `访客无 ${priv} 权限` }));
                }
            } else {
                res.send(responseJson({ error: "ERR_NO_PRIVILEGE", message: "禁止访客访问，请登录" }));
            }
        }
    };
}

function responseJson({ data = "", error = "ERR_SUCCESS", message = "" } = {}) {
    return {
        error,
        message,
        data,
    };
}

//获取错误枚举
app.get("/api/error", function (req, res) {
    res.send(responseJson({ data: errorEnums }));
});

//获取公钥
app.get("/api/pubkey", (req, res) => {
    res.send(responseJson({ data: config.serverConfig.public_key }));
});

//获取nonce
const nonces = new Map();
app.get("/api/nonce", (req, res) => {
    const nonce = GetRandomString();
    nonces.set(nonce, Date.now() + 15000); //nonce有效期15秒
    res.send(responseJson({ data: nonce }));
});

//获取客户端指纹
app.get("/api/finger", (req, res) => {
    res.send(responseJson({ data: GetClientFinger(req) }));
});

//获取用户信息
//返回用户名和权限，没有用户名就是访客
app.get("/api/user", (req, res) => {
    const user = ParseToken(req);
    if (user) {
        res.send(responseJson({ data: { user, privilege: config.user_db[user]["privilege"] } }));
    } else {
        res.send(responseJson({ data: { privilege: config.user_db.guest_privilege } }));
    }
});

//退出登录
//cookie是http-only，只能这样删除
app.get("/api/logout", (req, res) => {
    res.cookie("token", "", { maxAge: 0, httpOnly: true }).send(responseJson({ message: "退出登录成功" }));
});

//登录接口
app.post("/api/login", (req, res) => {
    const { data } = req.body;

    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(config.serverConfig.private_key);
    const uncrypted = decryptor.decrypt(data).split(":");

    const nonce = uncrypted[0];
    const user = uncrypted[1];
    const password = uncrypted[2];

    const nonce_expires = nonces.get(nonce);
    if (nonce_expires === undefined || nonce_expires < Date.now()) {
        res.send(responseJson({ error: "ERR_NONCE_EXPIRES", message: "nonce过期，请重新登录" }));
        nonces.delete(nonce);
        return;
    }
    nonces.delete(nonce);

    if (config.user_db[user] && bcrypt.compareSync(password, config.user_db[user]["password"])) {
        const token = jwt.sign({ user, finger: GetClientFinger(req) }, config.serverConfig.salt, { expiresIn: config.serverConfig.jwt_expires });

        res.cookie("token", token, {
            maxAge: 31557600000,
            path: "/",
            httpOnly: true,
        }).send(responseJson({ message: "登录成功" }));
    } else {
        res.send(responseJson({ error: "ERR_INVALID_USERNAME_OR_PASSWORD", message: "用户名或密码错误" }));
    }
});

//枚举目录
function EnumFile(dir) {
    let totalfile = 0;
    let totalsize = 0;
    let jsonResult = {
        totalfile: 0,
        totalsize: 0,
        files: [],
    };

    function readdirRecursive(currentDir) {
        fs.readdirSync(currentDir, { withFileTypes: true }).forEach((item) => {
            const fullPath = path.join(currentDir, item.name);
            if (item.isDirectory()) {
                readdirRecursive(fullPath);
            } else {
                ++totalfile;
                const size = fs.statSync(fullPath).size;
                totalsize += size;

                jsonResult.files.push({ path: path.relative(dir, fullPath), size: size });
            }
        });
    }
    readdirRecursive(dir);

    jsonResult.totalfile = totalfile;
    jsonResult.totalsize = totalsize;

    return jsonResult;
}

//获取文件列表
app.get("/api/list", RequirePrivilege("list"), (req, res) => {
    res.send(responseJson({ data: EnumFile(config.fileConfig.directory) }));
});

//下载文件
app.get("/download/:file", RequirePrivilege("download"), (req, res) => {
    res.download(path.join(config.fileConfig.directory, req.params.file));
});

//删除文件
app.post("/api/delete", RequirePrivilege("delete"), (req, res) => {
    const { files } = req.body;

    const failed = [];

    for (const file of files) {
        if (CheckSecurity(file)) {
            res.status(403).end();
            return;
        }

        try {
            fs.unlinkSync(path.join(config.fileConfig.directory, file));
        } catch (error) {
            failed.push({ file: error.message });
        }
    }

    if (failed.length === 0) {
        if (files.length === 1) {
            res.send(responseJson({ message: "删除成功" }));
        } else {
            res.send(responseJson({ message: "全部删除成功" }));
        }
    } else {
        if (files.length === 1) {
            res.send(responseJson({ error: "ERR_CANNOT_DELETE_FILE", message: "删除失败" }));
        } else {
            res.send(responseJson({ error: "ERR_CANNOT_DELETE_FILE", message: "有部分文件无法删除" }));
        }
    }

    io.emit("updateList");
});

//上传文件
//TODO: 大文件分块上传
app.post(
    "/api/upload",
    RequirePrivilege("upload"),
    multer({
        limits: {
            //限制最大上传大小，不然用户就可以post一个相当大的文件消耗服务器内存
            fileSize: 100 * 1024 * 1024,
        },
    }).array("file", 1),
    async (req, res) => {
        const files = req.files;
        for (const i in files) {
            const f = files[i];
            f.originalname = Buffer.from(f.originalname, "latin1").toString("utf-8");

            if (CheckSecurity(f.originalname)) {
                f.buffer = null;
                res.status(403).end();
                return;
            }

            try {
                const tempPath = path.join(config.fileConfig.tempdirectory, f.originalname);
                const finalPath = path.join(config.fileConfig.directory, f.originalname);

                if (fs.existsSync(finalPath) && !config.fileConfig.allow_override) {
                    f.buffer = null;
                    res.send(responseJson({ error: "ERR_FILE_ALREADY_EXISTS", message: "上传失败：文件已存在" }));
                    return false;
                }

                await fs.promises.writeFile(tempPath, f.buffer);
                await fs.promises.rename(tempPath, finalPath);

                //buffer显式设置为null用来优化gc
                f.buffer = null;
                res.send(responseJson({ message: `上传文件 ${f.originalname} 成功` }));
                io.emit("updateList");
            } catch (err) {
                res.send(responseJson({ error: "ERR_CANNOT_UPLOAD_FILE", message: "上传失败" }));
            }
        }
    }
);

//未处理的错误统一返回500，防止泄露后端敏感信息
app.use((err, req, res, next) => {
    console.log(err);

    res.status(500).send(responseJson({ error: "ERR_UNHANDLED_EXCEPTION" }));
});
const server = app.listen(config.serverConfig.port, () => {
    console.log(`服务器已启动，端口 ${config.serverConfig.port}`);
});

//剪贴板共享
const io = socketIO(server);
let pasteboard = "";
io.on("connection", (socket) => {
    socket.emit("updateText", pasteboard);

    socket.on("updateText", (newText) => {
        pasteboard = newText;
        socket.broadcast.emit("updateText", pasteboard);
    });
});
