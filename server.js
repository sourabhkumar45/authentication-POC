const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const user = require("./model/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();

const JWT_SECRET = "dshodjdfndfnadsjn3546y/3jhi?93#$"; // bang your head here to generate random key

mongoose.connect("mongodb://localhost:27017/login-app-db", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
app.use("/", express.static(path.join(__dirname, "static")));
app.use(bodyParser.json());

app.post("/api/change-password", (req, res) => {
  const { token } = req.body;
  jwt.verify(token, JWT_SECRET);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const data = await user.findOne({ username, password }).lean(); // lean returns json

  // we cannot search user based on the plain text password user has entered because we have stored the password in hashed format
  // we also cannot precompute the hash of the plain password because everytime we have different hash value for the same string
  if (!data) {
    return res.json({ status: "error", error: "Invalid username/password" });
  }
  if (await bcrypt.compare(password, data.password)) {
    // we compare hashes only when use is found
    const token = jwt.sign({ id: data._id, username: data.username }); // No sensitive infomation
    return res.json({ status: "ok", data: "" }, JWT_SECRET);
  }
  res.json({ status: "error", error: "Invalid username/password" });
});

app.post("/api/register", async (req, res) => {
  console.log(req.body);
  // store the password in encrypted form as  data may be used by
  // analyst and scripts reading databases
  // we will use hashing using bcrypt md5, sha1, sha256 sha512 algos
  // collision should be imporable
  // the algo must be slow because if database is leaked no one can brute force
  // passwords at high computational power
  const { username: username, password: plainTextPassword } = req.body;

  if (!username || typeof username != "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }
  if (!plainTextPassword || typeof plainTextPassword != "string") {
    return res.json({ status: "error", error: "Invalid username" });
  }
  if (plainTextPassword.length < 8) {
    return res.json({
      status: "error",
      error: "Password too small. Should be atleast 8 characters long",
    });
  }

  const password = await bcrypt.hash(plainTextPassword, 10);
  // 10 is salt denoting no. of iterations of encrytions, it can be string also
  // now any length of password will give the same length of hash
  try {
    let res = await user.create({
      username,
      password,
    });
    console.log("user created successfully: ", res);
  } catch (ex) {
    console.log(ex.message);
    if (ex.code === 11000)
      // code with 1100 then there is a duplicacy
      return res.json({ status: "error", error: "Duplicate Username" });

    throw error;
  }

  res.json({ status: "ok" }); // automatically sets the header
});

app.listen(9999, () => {
  console.log("Server up at 9999");
});

// Client when connect to the server somehow it has to authenticate who it is
// because we do not know the client computer so we can't authenticate the user itself
// by their ip or some sort of machine identification number
// 1. Client proves itself somehow on the request (JWT)
// 2.Client-server share a secret/ data that is non-changeable(uses cookies(resumes the session on database/redis))

// JWT - JSON web token has two dots in the token
// the part before first dot is header of the response, rest are Base64 encrpytion (do not use for secrets transfer)
// data in-between is our data, rest are for validation
// last part is the hash of the data which server generate and stores
// so we store the user data in form of hash which is the last part of the token
// and if this hash is not validated by the server we do not authenticate the user
// benefit is we have removed databases as depenceny for authentication
// this gives scalability
// cons -> do not store large data in the token
