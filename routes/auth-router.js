const express = require("express");
const authRoutes = express.Router();
const passport = require("passport");
const bcrypt = require("bcrypt");
const User = require("../models/user-model.js");


// <---------- SIGN UP ---------------->

authRoutes.get("/signup", (req, res, next) => {
    res.render("auth-views/signUp-form.hbs");
})

authRoutes.post("/process-signup", (req, res, next) => {
    //res.send(req.body)
    const userName = req.body.userName;
    const email = req.body.email;
    const profession = req.body.profession;
    let encryptedPassword;


    if(req.body.password === ""){
        // message: please enter a valid password!
        res.redirect("/signup");
        return
    } else {
        encryptedPassword = bcrypt.hashSync(req.body.password, 10);
    }

    User.create({ userName, email, profession, encryptedPassword})
    .then((users) => {
        console.log("data saved to DB!");
        // message: success! you have signup, please log in.
        res.redirect("/");
    })
    .catch((err) => {
        next(err);
    })
})


// <--------------LOG IN -------------------------->

authRoutes.get("/login", (req, res, next) => {
    res.render("auth-views/logIn-form.hbs")
})

authRoutes.post("/process-login", (req, res, next) => {
    //res.send(req.body);
    const email = req.body.email;
    const password = req.body.password;

    User.findOne({email})
    .then((user) => {
        if (!user){
            // message: please enter a valid email!
            res.redirect("/login");}
        else {
            const {encryptedPassword} = user;

            if (!bcrypt.compareSync(password, encryptedPassword)){
                // message: error, incorrect password
                res.redirect("/login");
                return;
            } else {
                req.login(user, () => {
                    // message: you have logged in successfully!
                    console.log("=================");
                    console.log("You have logged in!")
                    res.redirect("/center")
                })
                }
            }
    })
    .catch((err) => {next(err)})
})

// <-------------- LOG OUT------------------------>
authRoutes.get("/logout", (req, res, next) => {
    req.logout();
    console.log("You have logged out!");
    // message: You have logged out successfully!
    res.redirect("/");
})



// <------------------ SETTING ------------------->
authRoutes.get("/settings", (req, res, next) => {
    // check if user is logged in
    res.render("auth-views/settings.hbs")
})

authRoutes.post("/change-username", (req, res, next) =>{
    const {newName} = req.body;
    const userID = req.user._id;

    User.findById(userID, function (err, user) {
        if (err) next(err);

        user._id = newName;
        user.save(function (err, updatedUser) {
          if (err) next(err);
          // message: user name updated!
          console.log("User name update successfully!!");
          res.redirect("/center")
        });
      });
})

authRoutes.post("/change-password", (req, res, next) => {
    const {newPassword} = req.body;
    const newEncryptedPass = bcrypt.hashSync(newPassword, 10)
    const oldPassword = req.user.encryptedPassword;
    const userID = req.user._id;

    res.send(newPassword);

    // if new and old password match
  if(!bcrypt.compareSync(oldPassword, newEncryptedPass)){

    User.findById(userID, function (err, user) {
        if (err) next(err);

        user.encryptedPassword  = newEncryptedPass;
        user.save(function (err, updatedUser) {
          if (err) next(err);
          // message: user password updated!
          res.send(updatedUser);
          console.log("User password update successfully!!");
          res.redirect("/")
        });
      });
    } else {
        res.redirect("/settings")
    }
})


// <------------- Export AuthRoutes -----------------
module.exports= authRoutes;