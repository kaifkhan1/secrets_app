//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

const app = express();

app.set('view engine','ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}));
app.set('trust proxy',1);

app.use(session({
    secret:"This is my secret",
    resave: true,
    saveUninitialized:true
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/usersDB",{useNewUrlParser:true,useUnifiedTopology:true});

const userSchema = new mongoose.Schema({
    googleId:String,
    email : String,
    password : String,
    secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
    done(null,user.id);
});

passport.deserializeUser(function(user,done){
    done(null,user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get('/',function(req,res){
    res.render('home');
});

app.get('/login',function(req,res){
    res.render('login');
});

app.post('/login',function(req,res){
    const user = new User({
        email:req.body.username,
        password:req.body.password
    });

    req.login(user,function(err){
        if(!err){
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');
            });
        }
        else{
            console.log(err);
        }
    });
});

app.get('/register',function(req,res){
    res.render('register');
});

app.post('/register',function(req,res){
    User.register({username: req.body.username},req.body.password,function(err,user){
        if(!err){
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');
            });
        }
        else{
            console.log(err);
        }
    });

});


app.get('/secrets',function(req,res){

    User.find({"secret":{$ne:null}},function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                res.render('secrets',{userWithSecrets:foundUser});
            }
        }
    });

});

app.get('/submit',function(req,res){
    if(req.isAuthenticated){
        res.render('submit');
    }
    else{
        res.redirect('/login');
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
  
  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);
    console.log(req.user);
    User.findById(req.user, function(err, foundUser){
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
              res.redirect("/secrets");
            });
          }
        }
      });
});

app.get('/logout',function(req,res){
    req.logout();
    res.redirect('/');
});

app.listen(3000,function()
{
    console.log("Started Server");
});