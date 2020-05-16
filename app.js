const express = require("express");
let app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./models/user");
const sessions = require("client-sessions");
const bcrypt = require("bcryptjs");

app.set("view engine","pug");
app.use(bodyParser.urlencoded({extended:false})); 
app.use(sessions({
    cookieName : "session",
    secret: "ajkdsdfgjkm", // probably should make this an environment variable.  export VARNAME = ""
    duration: 30*60*1000,
    httpOnly : true,  //don't let js code access cookies
    secure : true, // only set cookies over https 
    ephemeral : true // destroy cookies when the browser closes. 
}));

app.use((req,res,next)=>{
    if(!(req.session && req.session.userId)){
        return next();
    }
    User.findById(req.session.userId, (err,foundUser)=>{
        if(err){
            return next(err);
        }
        if(!foundUser){
            return next();
        }
        foundUser.password = undefined;
        req.user = foundUser; 
        res.locals.user = foundUser;
        next();
    });
});
// mongoose config
mongoose.set('useUnifiedTopology', true);
mongoose.connect("mongodb://localhost/ss-auth",{useNewUrlParser: true, useCreateIndex : true}).then(()=>{
    console.log("db connected");
});

// Routes
app.get("/",(req,res)=>{
    res.render("index");
});

// NEW register
app.get("/register",(req,res)=>{
    res.render("register");
});

// CREATE register
app.post("/register",(req,res)=>{
    let hash = bcrypt.hashSync(req.body.password, 14);
    req.body.password = hash;
    User.create(req.body, (err, newUser)=>{
        if(err){
            let error = "Something bad happened, pls try again"; 

            if(err.code === 11000){
                error = "That email is already in use.";
            }
            return res.render("register",{error: error});
        }
        res.redirect("dashboard");
    });
});

app.get("/login",(req,res)=>{
    res.render("login");
});

app.post("/login",(req,res)=>{
    User.findOne({email: req.body.email}, (err,foundUser)=>{
        if(!foundUser || !bcrypt.compareSync(req.body.password, foundUser.password)){
            return res.render("login",{error :"incorrect email/password"});
        }
        req.session.userId = foundUser._id;
        res.redirect("dashboard");
    });
})

app.get("/dashboard", loginRequired,(req,res,next)=>{
   res.render("dashboard");
});

function loginRequired(req,res,next){
    if(!req.user){
        return res.redirect("/login");
    }
    next();
}

app.listen(3000,()=>{
    console.log("server has started");
});