require("./utils.js");
require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");

const saltRounds = 12;
const expireTime = 60 * 60 * 1000;
const Joi = require("joi");
const { error } = require("node:console");

const port = process.env.PORT || 3000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const app = express();

app.use("/css", express.static(__dirname + "/node_modules/bootstrap/dist/css"));
app.use("/js", express.static(__dirname + "/node_modules/bootstrap/dist/js"));

var { database } = include("db");

const userCollection = database.db(mongodb_db).collection("users");

//configure middleware
app.use('/loggedin', sessionValidation);

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  //doing this adds encryption to the stuff stored in the database
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  }),
);

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.render("loginsignup");
    return;
  }
  res.render("homepage", { username: req.session.username });
});

app.get("/membersarea", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }
  res.render("membersarea");
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    console.log(req.session.username);
    return;
  }

  res.render("login");
});

app.get("/signuperror", (req, res) => {
  let str = "";
  if (req.query.name) str += "name";
  if (req.query.email) {
    if (str) {
      str += ", ";
    }
    str += "email";
  }
  if (req.query.password) {
    if (str) {
      str += ", ";
    }
    str += "password ";
  }
  str += "can't be empty";
  res.render("error", { html: str });
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();

  const nameValidationResult = schema.validate(username);
  const emailValidationResult = schema.validate(email);
  const passwordValidationResult = schema.validate(password);

  let page = "/loginerror";
  let numErrors = 0;
  if (
    nameValidationResult.error != null ||
    emailValidationResult.error != null ||
    passwordValidationResult.error != null
  ) {
    if (nameValidationResult.error) {
      page += "?name=true";
      numErrors++;
    }
    if (emailValidationResult.error) {
      if (numErrors) {
        page += "&";
      } else page += "?";
      page += "email=true";
      numErrors++;
    }
    if (passwordValidationResult.error) {
      if (numErrors) {
        page += "&";
      } else page += "?";
      page += "password=true";
    }
    res.redirect(page);
    return;
  }

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, user_type: 1, _id: 1}).toArray();

  //user and password combination not found
  if (result.length != 1) {
    console.log("user not found");
    res.redirect(page);
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    req.session.user_type = result[0].user_type;

    res.redirect("/");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/loginerror");
    return;
  }
});

app.get("/loginerror", (req, res) => {
  let str = "";
  if (req.query.name) str += "name";
  if (req.query.email) {
    if (str) {
      str += ", ";
    }
    str += "email";
  }
  if (req.query.password) {
    if (str) {
      str += ", ";
    }
    str += "password";
  }
  let html = "";
  if (str) {
    html += `${str} can't be empty`;
  } else {
    html += `user/password combo not found.`;
  }
  res.render("error", { html: html });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

//when this page is reached it will send certain data to the server
app.post("/submitUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();

  const nameValidationResult = schema.validate(username);
  const emailValidationResult = schema.validate(email);
  const passwordValidationResult = schema.validate(password);

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  if (result.length > 0) {
    res.redirect("login");
    return;
  }

  let page = "/signuperror?";
  let numErrors = 0;
  if (
    nameValidationResult.error != null ||
    emailValidationResult.error != null ||
    passwordValidationResult.error != null
  ) {
    if (nameValidationResult.error) {
      console.log("hello");
      page += "name=true";
      numErrors++;
    }
    if (emailValidationResult.error) {
      if (numErrors) {
        page += "&";
      }
      page += "email=true";
      numErrors++;
    }
    if (passwordValidationResult.error) {
      if (numErrors) {
        page += "&";
      }
      page += "password=true";
    }
    res.redirect(page);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({username: username, password: hashedPassword, user_type: "user"});
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.render("logout");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection.find().project({ username: 1, _id: 1, user_type: 1 }).toArray();
  
  res.render("admin", { users: result });
});

app.post("/promote", sessionValidation, async (req, res) => {
  const { username } = req.body;
  await userCollection.updateOne({ username }, { $set: { user_type: "admin" } });
  console.log("updated");
  res.redirect("/admin");
});

app.post("/demote", sessionValidation, async (req, res) => {
  const { username } = req.body;
  await userCollection.updateOne({ username }, { $set: { user_type: "user" } });
  res.redirect("/admin");
});

//*splat is because of express v5
app.get("*splat", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("403", {error: "Not Authorized"});
        return;
    } 
    else {
        next();
    }
}