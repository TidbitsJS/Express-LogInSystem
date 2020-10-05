const Joi = require("joi");
const express = require("express");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

const users = {};
const idCheck = 347820;

app.get("/", (req, res) => {
  res.send("Hello from NodeJs");
});

app.get("/users", (req, res) => {
  res.send(users);
});

app.post("/users", async (req, res) => {
  const { error } = validateUser(req.body);
  if (error) return res.status(401).send(error.details[0].message);

  if (/\s/g.test(req.body.username))
    return res.status(401).send("Strictly no to Whitespace!");
  const userCheck = users[req.body.username];
  if (userCheck)
    return res.status(401).send("User already exist. Try different!");

  try {
    const salt = await bcrypt.genSalt();
    const newUser = req.body;
    newUser.id = idCheck + Object.keys(users).length + 1;
    newUser.log = false;
    newUser.password = await bcrypt.hash(newUser.password, salt);

    users[newUser.username] = newUser;

    res.status(201).send(newUser);
  } catch (e) {
    res.status(500).send("Unable to Log User!");
  }
});

app.post("/users/login", async (req, res) => {
  const { error } = validateUser(req.body);
  if (error) return res.status(401).send(error.details[0].message);

  if (/\s/g.test(req.body.username))
    return res.status(401).send("Strictly no to Whitespace!");

  try {
    const userCheck = users[req.body.username];
    if (!userCheck) return res.status(404).send("User does not exist!");

    const check = await bcrypt.compare(req.body.password, userCheck.password);
    if (!check) return res.status(401).send("Password did not Match!");

    userCheck.log = true;
    res.send("Successfully Logged In!");
  } catch (e) {
    res.status(500).send(e.message);
  }
});

app.put("/users/login/:username", (req, res) => {
  const newUser = users[req.params.username];
  if (!newUser)
    return res.status(404).send(`${req.params.username} does not exist`);

  const { error } = validateUser(req.body);
  if (error) return res.status(401).send(error.details[0].message);

  if (/\s/g.test(req.body.username))
    return res.status(401).send("Strictly no to Whitespace!");

  const uniqueUsername = users[req.body.username];
  if (uniqueUsername)
    return res
      .status(500)
      .send(
        `User with username ${req.body.username} already exist. Try Unique!`
      );

  newUser.username = req.body.username;
  newUser.email = req.body.email;
  newUser.password = req.body.password;

  users[newUser.username] = newUser;
  delete users[req.params.username];

  res.send(newUser);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on port ${port} ...`));

const validateUser = (user) => {
  const schema = Joi.object({
    username: Joi.string().min(5).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
  });

  return schema.validate(user);
};
