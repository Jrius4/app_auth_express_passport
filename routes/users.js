const express = require('express');
const bcrypt = require('bcryptjs');
const passport = require('passport');

const router = express.Router();

const User = require('../models/User')


//register Page
router.get('/register',(req,res) => res.render('register'));

//login Page
router.get('/login',(req,res) => res.render('login'));


//controllers
//registration controllers
//Register Handle
router.post('/register',(req,res)=>{
    const {name,email,password,password2} = req.body;
    let errors=[];

    // check required fields
    if(!name || !email ||!password ||!password2){
        errors.push({msg:'Please fill in all fields'});
    }
    //check passwords match
    if(password !== password2){
        errors.push({
            msg:'Passwords don\'t match'
        });
    }

    //check pwd length
    if(password.length < 6){
        errors.push({msg:'Password should be at least 6 characters'})
    }

    if(errors.length > 0){
        res.render('register',{
            errors,
            name,
            email,
            password,
            password2
        });
    }else{
        // valdation passed
        User.findOne({email:email})
        .then(user => {
            if(user){
                // user exists
                errors.push({msg:'Email is already registered'});
                res.render('register',{
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else{
                const newUser = new User({
                    name,
                    email,
                    password
                });
                // hash password
                bcrypt.genSalt(10,(err,salt)=>{bcrypt.hash(newUser.password,salt,
                    (err,hash)=>{
                        if(err) throw err;
                        // set password to hashed
                        newUser.password = hash;
                        // save user
                        newUser.save()
                        .then(user =>{
                            req.flash('success_msg','You are now registered and can log in');
                            res.redirect('/users/login');
                        })
                        .catch(err => console.log(err));
                    })});
            }
        });

    }

})
//end registration controllers
//start login controllers
router.post('/login',(req,res,next)=>{
    passport.authenticate('local',{
        successRedirect:'/dashboard',
        failureRedirect:'/users/login',
        failureFlash:true
    })(req,res,next);
});
//end login controllers
//start logout controllers
router.get('/logout',(req,res)=>{
    req.logout();
    req.flash('success_msg','You are logged out');
    res.redirect('/users/login')
});
//end login controllers
//end controllers

module.exports = router;