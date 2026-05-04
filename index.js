require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const session = require("express-session");
const { MongoStore } = require('connect-mongo');

const saltRounds = 12;
const expireTime = 24 * 60 * 60 * 1000;

const port = process.env.PORT || 3000;

/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const app = express();

const mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@bcit.bcxaqyh.mongodb.net/sessions`, 
  //doing this adds encryption to the stuff stored in the database
  crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
  secret: node_session_secret,
	store: mongoStore,  //default is memory store 
	saveUninitialized: false,
	resave: true
}
));

var users = []; 

app.use(express.urlencoded({extended: false}));

app.get('/', (req,res) => {
  res.send(`
    <form method="get" action="/login">
      <button type=submit>Log in</button>
    </form>
    <form method="get" action="/signup">
      <button type=submit>Sign up</button>
    </form>
    </body>`);
});

app.get('/login', (req,res) => {
    if(req.session.authenticated) {
      res.redirect("/loggedin");
      console.log(req.session.username);
      return;
    }
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', (req,res) => {
    var username = req.body.username;
    var password = req.body.password;


    var usershtml = "";
    for (i = 0; i < users.length; i++) {
        if (users[i].username == username) {
            //comparesync hashes the password entered and compares it to the other one
            if (bcrypt.compareSync(password, users[i].password)) {
                //tell the server that the user is authenticated
                req.session.authenticated = true;
                req.session.username = username;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/loggedIn');
                return;
            }
        }
    }

    //user and password combination not found
    res.redirect("/login");
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.get('/signup', (req,res) => {
    var html = `
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

//when this page is reached it will send certain data to the server
app.post('/submitUser', (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    //good, poggers, encrypted
    //use bcrypt.hashSync to hash a password
    var hashedPassword = bcrypt.hashSync(password, saltRounds);
    users.push({ username: username, password: hashedPassword });

    console.log(users);

    console.log("username:", username);
    console.log("password:", password);
    console.log("req.body:", req.body);

    var usershtml = "";
    for (i = 0; i < users.length; i++) {
        usershtml += "<li>" + users[i].username + ": " + users[i].password + "</li>";
    }

    var html = "<ul>" + usershtml + "</ul>";
    res.send(html);
});

app.use(express.static(__dirname + "/public"));

//*splat is because of express v5
app.get("*splat", (req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 