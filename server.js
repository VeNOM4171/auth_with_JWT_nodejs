require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());

// Authentication - getting user name and password and verify if it is correct or not and then
// help the user to logged in.

// Authorization - JWT - JSON WEB TOKEN (reduce the load on server compare to old session based authorization.
// JWT already contain all the information for authorization in json format)
// => is use for Authorization - means to verify the user that makes
// request is the same user who logged in during the authentication. it's authorizing that
// user has access to this particular system.
// Normally we use sessions for that where request will contain the token and server will
// verify the session of user by token comparing with token stored in server memory.

// Production: save user information in db and this GET request will not be used it is only for testing purpose.
const users = [];
const refreshTokens = [];
const posts = [
  {
    username: "Kyle",
    title: "Post 1",
  },
  {
    username: "Jim",
    title: "Post 2",
  },
];

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15s" });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    console.log(err);
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/api/users", (req, res) => {
  res.json(users);
});

app.post("/api/users", async (req, res) => {
  console.log("RUN-" + JSON.stringify(req.body));
  try {
    const saltRounds = 10;
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
      // Store hash in your password DB.
      const hashedPassword = hash;
      console.log(`${hashedPassword}`);
      const user = { name: req.body.name, password: hashedPassword };
      // we should save user in DB
      users.push(user);
      res.status(201).send();
    });
  } catch {
    res.status(500).send();
  }
});

app.post("/api/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.post("/api/users/login", async (req, res) => {
  // Asuming that username is unique in entire db
  const user = users.find((user) => (user.name = req.body.name));
  if (user == null) {
    return res.status(400).send("Cannot find user");
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // LOGIN
      console.log("Password is correct. Login.");
      const username = req.body.username;
      const user = { name: username };

      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.send("Not Allowed");
    }
  } catch {
    res.status(500).send();
  }
});

app.delete("/api/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.get("/api/posts", authenticateToken, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
});

app.listen(3000);
