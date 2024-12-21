import express, { text } from "express";
import path from "path";
import bcrypt from "bcrypt";
import fs from "fs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const app = express();

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const filePath = path.resolve("data.json");

// Utility Functions
async function register(newData) {
    try {
        const data = await fs.promises.readFile(filePath, 'utf8');
        const jsonData = data.trim() ? JSON.parse(data) : [];
        jsonData.push(newData);
        await fs.promises.writeFile(filePath, JSON.stringify(jsonData, null, 4));
        console.log('Data successfully added to the file!');
    } catch (err) {
        if (err.code === 'ENOENT') {
            console.error('File not found, creating a new one...');
            const jsonData = [newData];
            await fs.promises.writeFile(filePath, JSON.stringify(jsonData, null, 4));
            console.log('File created and data added!');
        } else if (err.name === 'SyntaxError') {
            console.error('Error parsing JSON:', err);
        } else {
            console.error('Error handling file:', err);
        }
    }
}

async function getUserByEmail(email) {
    try {
        const data = await fs.promises.readFile(filePath, 'utf8');
        const users = JSON.parse(data);
        return users.find(user => user.email === email);
    } catch (err) {
        console.error('Error reading or parsing the file:', err);
        throw err;
    }
}

async function checkUser(pwd, email) {
    try {
        const user = await getUserByEmail(email);
        if (!user) return false;
        return await bcrypt.compare(pwd, user.password);
    } catch (error) {
        console.error("Error in checkUser:", error);
        return false;
    }
}

function authenticateToken(req, res, next) {
    const token = req.cookies.authToken;
    if (!token) return res.redirect("/login");

    jwt.verify(token, "your_secret_key", (err, user) => {
        if (err) return res.redirect("/login");
        req.user = user;
        next();
    });
}

// Routes
// Authentication Routes
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    try {
        const result = await checkUser(password, email);
        if (result) {
            const token = jwt.sign({ email }, "your_secret_key", { expiresIn: "1h" });
            res.cookie("authToken", token, { httpOnly: true });
            res.status(200).json({ success: true, message: "Login successful" });
        } else {
            res.status(401).json({ success: false, message: "Invalid email or password" });
        }
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("authToken");
    res.redirect("/");
});

// User Management Routes
app.post("/register", async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$/;
    try {
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ 
                success: false, 
                message: "Գաղտնաբառը պետք է պարունակի նվազագույնը 6 նշան ունենա մեկ մեծատառ, մեկ փոքրատառ, մեկ թվանշան և մեկ սիմվոլ։"
            });
        }

        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email-ը պատկանոում է այլ հաշվի" });
        }

        const hashPwd = await bcrypt.hash(password, 10);
        await register({ firstName, lastName, email, password: hashPwd });
        res.status(200).json({ success: true, message: "Registration successful!" });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// Static Pages
app.get("/", authenticateToken, (req, res) => {
    res.sendFile(path.resolve("public/index.html"));
});

app.get("/register", (req, res) => {
    res.sendFile(path.resolve("public/register/register.html"));
});

app.get("/login", (req, res) => {
    res.sendFile(path.resolve("public/login/login.html"));
});

// Utility Routes
app.get("/check-login", (req, res) => {
    const token = req.cookies.authToken;
    if (!token) return res.json({ loggedIn: false, userName: null });

    jwt.verify(token, "your_secret_key", (err, decoded) => {
        if (err) return res.json({ loggedIn: false, userName: null });
        res.json({ loggedIn: true, userName: decoded.email });
    });
});

// Static Files
app.use(express.static("public"));

// Start Server
app.listen(3001, () => {
    console.log("Server running on port 3001");
});
