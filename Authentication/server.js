require("dotenv").config;
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();

app.listen(3000);

app.use(express.json);

const posts = [
  {
    username: "kyle",
    title: "Post1",
  },
  {
    username: "Max",
    title: "Post2",
  },
];

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.get("/posts", (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
});

app.post("/login", authenticateToken, (req, res) => {
  // Check user credentials
  const username = req.body.username;
  const user = { name: username };
  console.log(user);
  // creating a Access Token
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
  res.json(accessToken);
});
