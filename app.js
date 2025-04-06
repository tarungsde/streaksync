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

// configurations

dotenv.config();
const app = express();
const saltRounds = 3;
const port = process.env.PORT;
const d = new Date();

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
app.set('view engine', 'ejs');


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

let task = [];
let complete = [];
let percent;
let date = d.getDate() +" "+ (d.getMonth()+1) +" " + d.getFullYear();

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

app.get("/app", async (req,res) => {
  if(req.isAuthenticated()) {
    let a,b;
    try {
        const data = await db.query("select * from task where date=($1) and month=($2) and year=($3);",
          [d.getDate(),d.getMonth()+1,d.getFullYear()]);
        const data2 = await db.query("select * from complete_task where date=($1) and month=($2) and year=($3);",
          [d.getDate(),d.getMonth()+1,d.getFullYear()]);
        a=data.rowCount;
        b=data2.rowCount;
        complete=data2.rows;
        task=data.rows; 
    }
    catch(err) {
      console.error("error is executing"+err.stack);
    }
    percent = (a + b) === 0 ? 0 : (b / (a + b)) * 100;
    res.render("app.ejs", {task:task,date:date,complete:complete,percent:percent} );
  }
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
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login?error=Please log in to view your history.");
}

app.get('/app/history', ensureAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;

    const today = new Date();
    const start = new Date(today.getFullYear(), today.getMonth() - 5, 1); // Start from the 1st of 6 months ago

    const { rows } = await db.query(
      `SELECT date, month, year
       FROM complete_task
       WHERE user_id = $1
         AND (year > $2 OR (year = $2 AND month >= $3))`,
      [userId, start.getFullYear(), start.getMonth() + 1]
    );

    // Create a structure like: { 'April 2025': [1, 2, 4, 15], ... }
    const history = {};

    for (let i = 0; i < 6; i++) {
      const date = new Date(today.getFullYear(), today.getMonth() - i, 1);
      const key = date.toLocaleString('default', { month: 'long', year: 'numeric' });
      history[key] = new Set(); // avoid duplicates
    }

    rows.forEach(({ date, month, year }) => {
      const key = new Date(year, month - 1).toLocaleString('default', { month: 'long', year: 'numeric' });
      if (history[key]) {
        history[key].add(date);
      }
    });

    // Convert Sets to Arrays for EJS rendering
    for (let key in history) {
      history[key] = Array.from(history[key]).sort((a, b) => a - b);
    }

    res.render('history.ejs', { history });

  } catch (err) {
    console.error('Error in /app/history:', err);
    res.status(500).send('Something went wrong');
  }
});

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

app.post("/task",(req,res)=>{
  console.log("task: "+req.body.t_name);
  const task_id=uuidv4();
  db.query('INSERT INTO task (user_id, task, task_id, date, month, year) VALUES ($1, $2, $3, $4, $5, $6)',
      [req.user.id, req.body.t_name, task_id, d.getDate(), d.getMonth()+1, d.getFullYear()]
    );
  res.redirect("/app");  
});

app.post("/delete-task",async (req,res)=>{
  console.log("del id: "+req.body.task_id);
  try {    
      const data=await db.query("delete from task where task_id=($1)",[req.body.task_id]);
  }
  catch(err) {
      console.error(err);
  }
  res.redirect("/app");
});

app.post("/complete-task",async (req,res)=>{
  console.log(req.body);
  try {
      db.query("delete from task where task_id=($1)",[req.body.task_id]);
      const data = await db.query("select * from task where date=($1) and month=($2) and year=($3);",
        [d.getDate(),d.getMonth()+1,d.getFullYear()]); 
      db.query('INSERT INTO complete_task (user_id, task, task_id, date, month, year) VALUES ($1, $2, $3, $4, $5, $6)',
      [req.user.id ,req.body.task, req.body.task_id, d.getDate(), d.getMonth()+1, d.getFullYear()]
    );
  }
  catch(err) {
      console.error(err);
  }
  res.redirect("/app");
});


app.post("/delete-complete",(req,res)=>{
  try{
      db.query("delete from complete_task where date=($1) and month=($2) and year=($3)",
        [d.getDate(), d.getMonth()+1, d.getFullYear()]);
  }
  catch(err) {
      console.error(err);
  }
  res.redirect("/app");
})

app.post("/delete-today",(req,res)=>{
  try {
      db.query("delete from task where date=($1) and month=($2) and year=($3)",
        [d.getDate(), d.getMonth()+1, d.getFullYear()]
      );
  }
  catch(err) {
      console.error(err);
  }
  res.redirect("/app");
})

// strategies

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
