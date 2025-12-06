import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import fs from "fs";

const app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// SESSION
app.use(
  session({
    secret: "dummysecret",
    resave: false,
    saveUninitialized: true,
  })
);

// USER DATA
const USERS_FILE = "./data/users.json";
let users = JSON.parse(fs.readFileSync(USERS_FILE));

// MIDDLEWARE
function auth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function admin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.send("Yetkisiz erişim.");
  }
  next();
}

// ROUTES
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) return res.send("Kullanıcı bulunamadı.");

  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.send("Hatalı şifre.");

  req.session.user = user;
  res.redirect("/dashboard");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (users.find((u) => u.username === username)) {
    return res.send("Bu kullanıcı adı alınmış.");
  }

  const hash = await bcrypt.hash(password, 10);

  const newUser = {
    username,
    password: hash,
    role: "user",
  };

  users.push(newUser);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

  res.redirect("/login");
});

app.get("/dashboard", auth, (req, res) => {
  res.render("dashboard", { user: req.session.user });
});

app.get("/admin", admin, (req, res) => {
  res.render("admin", { users });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// SERVER
app.listen(3000, () => console.log("Server running on http://localhost:3000"));