require("./utils.js");
require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");

const saltRounds = 12;
const expireTime = 60 * 60 * 1000;
const Joi = require("joi");

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

var { database } = include("db");

const userCollection = database.db(mongodb_db).collection("users");

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

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
    <form method="get" action="/login">
      <button type=submit>Log in</button>
    </form>
    <form method="get" action="/signup">
      <button type=submit>Sign up</button>
    </form>
    </body>`);
    return;
  }
  res.send(`
    Hello ${req.session.username}
    <form method="get" action="/membersarea">
      <button type=submit>Go to members area</button>
    </form>
    <form method="get" action="/logout">
      <button type=submit>Log out</button>
    </form>
    `);
});

app.get("/membersarea", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  let rand = Math.floor(Math.random() * 3);
  if (rand == 0) {
    res.send("<img src='/847.png' style='width:250px;'>");
  } else if (rand == 1) {
    res.send("<img src='/ungovernable.jpeg' style='width:250px;'>");
  } else {
    res.send("<img src='flowchart.png' style='width:250px;'>");
  }
});

app.get("/login", (req, res) => {
  if (req.session.authenticated) {
    res.redirect("/");
    console.log(req.session.username);
    return;
  }
  var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
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
    str += "password";
  }
  res.send(`${str} can't be empty
    <button onclick="history.back()">Go Back</button>`);
});

app.post("/loggingin", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(20).required();

  const nameValidationResult = schema.validate(username);
  const emailValidationResult = schema.validate(email);
  const passwordValidationResult = schema.validate(password);

  let page = "/loginerror?";
  let numErrors = 0;
  if (
    nameValidationResult.error != null ||
    emailValidationResult.error != null ||
    passwordValidationResult.error != null
  ) {
    if (nameValidationResult.error) {
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

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, email: 1, password: 1, _id: 1 })
    .toArray();

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

    res.redirect("/");
    return;
  } else {
    console.log("incorrect password");
    res.redirect("/loginerror");
    return;
  }
});

app.get("/loginerror", (req, res) => {
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
      str += "password";
    }
    let html = "";
    if (str) {
      html += `${str} can't be empty`;
    } else {
      html += `user/password combo not found.`;
    }
    html += `<button onclick="history.back()">Go Back</button>`;
    res.send(html);
  });
});

app.get("/signup", (req, res) => {
  var html = `
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
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

  await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
  console.log("Inserted user");
  var html = "successfully created user";
  res.send(html);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  var html = `
    You are logged out.
    <form method="get" action="/">
      <button type=submit>Home page</button>
    </form>
    `;
  res.send(html);
});

//*splat is because of express v5
app.get("*splat", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
