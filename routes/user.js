
const express = require('express')
const router = express.Router()
const mongoose = require('mongoose')
const POST = mongoose.model('POST')
const USER = mongoose.model('USER') 
const requireLogin = require('../middlewares/requireLogin');

router.get("/user/:id", async (req,res) => {
    try{
        const user = await USER.findOne({_id : req.params.id}).select("-password")
        const userPost = await POST.find({postedBy: req.params.id}).populate("postedBy","_id name")
        res.status(200).json({user,userPost})
    }catch(err){
        res.status(422).json(err)
    }
})

router.put("/follow",requireLogin,async (req,res) => {
    const followIdDetails = await USER.findByIdAndUpdate({_id:req.body.followId},{
         $push: {
            followers: req.user._id
         }},{
            new : true
         }
    )
    const followerDetails = await USER.findByIdAndUpdate({_id: req.user._id},{
        $push: {
            following: req.body.followId
        }
    },{
        new: true
    })
    res.status(200).json({followIdDetails, followerDetails})
})

router.put("/unfollow",requireLogin,async (req,res) => {
const response = await USER.findByIdAndUpdate({_id:req.body.followId},{
         $pull: {
            followers: req.user._id
         }},{
            new : true
         }
    )
const response2 = await USER.findByIdAndUpdate({_id: req.user._id},{
        $pull: {
            following: req.body.followId
        }
    },{
        new: true
    })
    res.status(200).json({response,response2})
})

router.put("/uploadProfilePic",requireLogin,async (req,res) =>{
    try{const response = await USER.findByIdAndUpdate(req.user._id,{
        $set: {
            Photo: req.body.pic
        }
    },{
        new: true
    })
    return res.status(200).json(response)
    }catch(err){
        return  res.status(422).json({error:err})
    }

})

router.get("/searcheduser/:name", requireLogin, async (req,res) => {
    try{
        const partialUsername = req.params.name
        const regex = new RegExp('.*' + partialUsername + '.*', 'i');
        const response = await USER.find({ name: { $regex: regex } });
        res.status(200).json(response )
    }
    catch(err)
    {
        res.status(422).json(err )
    }
})

module.exports = router