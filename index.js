const express = require("express");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

const users = [];

app.get("/", (req, res) => {
  res.send("Hello from NodeJs");
});

app.get("/users", (req, res) => {
  res.send(users);
});

app.post("/users", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt();
    const newUser = req.body;
    newUser.id = users.length + 1;
    newUser.password = await bcrypt.hash(newUser.password, salt);

    users.push(newUser);

    res.status(201).send(newUser);
  } catch (e) {
    res.status(500).send("Unable to Log User!");
  }
});

app.post("/users/login", async (req, res) => {
  try {
    const userCheck = users.find((c) => c.name === req.body.name);
    if (!userCheck) return res.status(404).send("User does not exist!");

    const check = await bcrypt.compare(req.body.password, userCheck.password);
    if (!check) return res.status(401).send("Password did not Match!");

    res.send("Successfully Logged In!");
  } catch (e) {
    res.status(500).send(e.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port} ...`));
