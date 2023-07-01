const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const configDotenv = require("dotenv").config();
const bcrypt = require("bcryptjs");

mongoose.connect(process.env.mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const messageSchema = new Schema({
  username: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model("Message", messageSchema);

const userSchema = new Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  username: { type: String, required: true },
  email: { type: String, required: true },
  messages: [{ type: Schema.Types.ObjectId, ref: "Message" }],
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false }
});


const User = mongoose.model("User", userSchema);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "process.env.sessionKey", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => {
  res.render("views/index", { user: req.user });
});

app.get("/signup", (req, res) => res.render("views/signup"));
app.post("/signup", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const isAdmin = req.body.isAdmin === "on"; // Convert "on" string to boolean

    const user = new User({
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
      isAdmin: isAdmin || false
    });

    const result = await user.save();
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/create", (req, res) => {
  res.render("views/create-message", { user: req.user });
});
app.post('/create', async (req, res) => {
  try {
    // Extract the data from the request body
    const { message } = req.body;

    // Create a new message document using your Mongoose model
    const newMessage = new Message({
      username: req.user.username,
      message,
      createdAt: Date.now() // Set the createdAt property to the current timestamp
    });

    // Save the new message to the database
    const savedMessage = await newMessage.save();

    // Redirect or send a response indicating the success of the operation
    res.redirect('/success'); // Redirect to a success page, or send a JSON response
  } catch (error) {
    // Handle any errors that occur during the process
    console.error(error);
    res.status(500).send('An error occurred'); // Send an appropriate error response
  }
});

app.get('/success', async (req, res) => {
  try {
    // Retrieve currently logged-in user
    const user = req.user;

    // Retrieve all messages from the database
    const messages = await Message.find();

    // Render the "success" template and pass the messages as data
    res.render('views/success', { user, messages });
  } catch (error) {
    console.error(error);
    res.status(500).send('An error occurred');
  }
});

app.post('/messages/:id/delete', async (req, res) => {
  try {
    // Check if user is logged in
    if (!req.user) {
      return res.redirect('/login');
    }

    // Check if user is an admin
    if (!req.user.isAdmin) {
      return res.status(403).send('Unauthorized');
    }

    // Delete the message logic here

    // Redirect or respond with a success message
  } catch (error) {
    // Handle any errors that occur during the process
    console.error(error);
    res.status(500).send('An error occurred');
  }
});


app.get("/login", (req, res) => res.render("views/login"));
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
  })
);

app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ email: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // Passwords match! Log in the user 
          return done(null, user);
        } else {
          // Passwords do not match!
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);


passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch(err) {
    done(err);
  };
});

app.listen(3000, () => console.log("app listening on port 3000!"));