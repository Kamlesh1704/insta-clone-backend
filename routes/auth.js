const express = require('express')
const router = express.Router()
const mongoose = require('mongoose');
const USER  = mongoose.model('USER')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {Jwt_secret} = require('../keys.js');
const requireLogin = require('../middlewares/requireLogin.js');

router.post("/signup" ,async (req,res)=>{
    const {name,email,password,username} = req.body;
    if(!name || !email || !password || !username){
        res.status(422).send({error:"Please add all the fields"})
    }
    const savedUser =await USER.findOne({$or:[{email:email},{username:username}]})
    if(savedUser){
        return res.status(422).json({error:"User already exists with this Email or Username"})
    }
     const hashedPassword =await bcrypt.hash(password,12)
     const user = new USER({
        name,
        email,
        username,
        password:hashedPassword})
    try {
        await user.save()
        res.json({message:"Registered Successfully"})
    } catch (error){
        console.log(error)
    }
})

router.post("/signin", async (req,res) => {
    const {email, password} = req.body
    if (!email || !password) {
       return  res.status(422).json({error: "Please add both Email and Password"})
    }
    const savedUser = await USER.findOne({email:email})
    if (!savedUser) {
        return res.status(422).json({error:"Invalid Email"})
    }
    try {
        const match = await bcrypt.compare(password, savedUser.password)
        if(match){
            const token = jwt.sign({_id:savedUser.id}, Jwt_secret)
            const {_id, name, username, email} = savedUser
            return res.json({token,
                message:"Signed In Successfully",
            user:{_id,name,username,email}})
        }else{
            return res.status(422).json({error: "Invalid password"})
        }
    } catch (err){
        console.log(err)
    }
})

router.post("/googleLogin", async (req,res) => {
    const {email_verified, email, name, clientId, username, Photo} = req.body
    if(email_verified){
        const savedUser = await USER.findOne({email:email})
        if (savedUser) {
            const token = jwt.sign({_id:savedUser.id}, Jwt_secret)
            const {_id, name, username, email} = savedUser
            return res.json({token,
                message:"Signed In Successfully",
            user:{_id,name,username,email}})
        }else{
            const password = email + clientId
            const user = new USER({
                name,
                email,
                username,
                password:password,
                Photo: Photo
            })
            try {
                const userDetails = await user.save()
                const userId = userDetails._id.toString()
                const token = jwt.sign({_id: userId}, Jwt_secret)
                const {_id, name, username, email} = userDetails
                return res.json({token,
                    message:"Signed In Successfully",
                user:{_id,name,username,email}})
                } catch (error){
                    console.log(error)
            }
        }
    }
})

module.exports=router