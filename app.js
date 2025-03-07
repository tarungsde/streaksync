// importing dependencies

import express from "express";
import bodyParser from "body-parser"
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import { v4 as uuidv4 } from "uuid";

//configurations

dotenv.config();
const app = express();
const saltRounds = 3;
const port = process.env.PORT;

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// get routes

app.get("/", (req,res) => {
  res.render("home.ejs");
});

app.get("/register", (req,res) => { 
  res.render("register.ejs", { error: req.query.error || "" });
});

app.get("/login", (req,res) => {
  res.render("login.ejs", { error: req.query.error || "" });
});

app.get("/app", (req,res) => {
  if(req.isAuthenticated())
    res.render("app.ejs");
  else 
    res.redirect("/login?error=Kindly login.");
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/streaksync", passport.authenticate("google", {
  successRedirect: "/app",
  failureRedirect: "/login?error=Invalid credentials.",
}));

app.get("/logout", (req,res) => {
  req.logOut((err) => {
    if(err) console.log(err);
    res.redirect("/");
  })
})

// post routes

app.post("/register", async (req,res) => {

  const {name, mail, password} = req.body;

  const result = await db.query(
    "select * from users where mail = ($1)",
    [mail]);

  if (result.rows.length > 0) {
    console.log("Account already exist.");
    return res.redirect("/register?error=Account already exists.");
  }

  const hash = await bcrypt.hash(password, saltRounds);
  const uuid = uuidv4();
        
  const newUser = await db.query(
    "insert into users (id, name, mail, password) values ($1, $2, $3, $4) RETURNING *",
    [uuid, name, mail, hash]);

    req.login(newUser.rows[0], (err)=>{
      if(err) console.log(err);
      res.redirect("/app");
    });
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/app",
  failureRedirect: "/login?error=Invalid credentials.",
}));

//strategies

passport.use("local",
  new Strategy({ usernameField: "mail" }, async function verify(mail, password, cb) {
  try {
    const result = await db.query(
    "select * from users where mail = ($1)",
    [mail]);
  
    if (result.rows.length == 0) {
      console.log("Account does not exist.");
      return cb(null, false, { message: "Account does not exist" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      console.log("Invalid Credentials");
      return cb(null, false, { message: "Invalid Credentials" });
    } 
    return cb(null, user);
  } catch(err) {
    console.error("Error during authentication:", err);
    return cb(err);
  }
}));

passport.use(
  "google", 
  new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/streaksync",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  }, async (accessToken, refreshToken, profile, cb) => {
    try {
      const result = await db.query(
      "select * from users where mail = ($1)",
      [profile.email]);
      
      if (result.rows.length == 0) {
        const uuid = uuidv4();
        const newUser = await db.query(
          "insert into users (id, name, mail, password) values ($1, $2, $3, $4) RETURNING *",
          [uuid, profile.displayName, profile.email, "google"]);
        cb(null, newUser.rows[0]);
      } else {
        cb(null, result.rows[0]);
      }
    } catch(err) {
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`App is running on http://localhost:${port}.`)
});
