const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(bodyParser.json());
app.use(cors());
app.use(express.static("public"));

const readData = (file) => JSON.parse(fs.readFileSync(`data/${file}`, "utf8"));
const writeData = (file, data) => fs.writeFileSync(`data/${file}`, JSON.stringify(data, null, 2));

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).send("Token missing");

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send("Invalid token");
    req.user = user;
    next();
  });
};

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const users = readData("users.json");

  const user = users.find((u) => u.username === username && u.password === password);

  if (user) {
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  } else {
    res.status(401).send("Invalid credentials");
  }
});

app.post("/register", (req, res) => {
  const { username, password, role = "user" } = req.body;
  const users = readData("users.json");

  if (users.some((u) => u.username === username)) {
    return res.status(400).send("Username already exists");
  }

  const newUser = {
    id: users.length > 0 ? users[users.length - 1].id + 1 : 1,
    username,
    password,
    role,
  };

  users.push(newUser);
  writeData("users.json", users);
  res.status(201).send("User registered successfully");
});

app.get("/items", authenticateJWT, (req, res) => {
  const items = readData("items.json");
  res.json(items);
});

app.post("/items", authenticateJWT, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access denied");

  const items = readData("items.json");
  const { item, description } = req.body;

  const newItem = {
    id: items.length > 0 ? items[items.length - 1].id + 1 : 1,
    item,
    description,
  };

  items.push(newItem);
  writeData("items.json", items);
  res.status(201).send("Item created");
});

app.put("/items/:id", authenticateJWT, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access denied");

  const items = readData("items.json");
  const { id } = req.params;
  const { item, description } = req.body;

  const index = items.findIndex((i) => i.id === parseInt(id));
  if (index === -1) return res.status(404).send("Item not found");

  items[index] = { id: parseInt(id), item, description };
  writeData("items.json", items);
  res.send("Item updated");
});

app.delete("/items/:id", authenticateJWT, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access denied");

  const items = readData("items.json");
  const { id } = req.params;

  const updatedItems = items.filter((i) => i.id !== parseInt(id));
  writeData("items.json", updatedItems);
  res.send("Item deleted");
});

app.patch("/users/:id/role", authenticateJWT, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).send("Access denied");

  const users = readData("users.json");
  const { id } = req.params;
  const { role } = req.body;

  const index = users.findIndex((u) => u.id === parseInt(id));
  if (index === -1) return res.status(404).send("User not found");

  if (!["admin", "user"].includes(role)) {
    return res.status(400).send("Invalid role");
  }

  users[index].role = role;
  writeData("users.json", users);
  res.send("User role updated");
});

app.get("/users", authenticateJWT, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("Access denied");
  }

  const users = readData("users.json");
  res.json(users);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
