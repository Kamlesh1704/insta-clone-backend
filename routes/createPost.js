const express = require('express')
const router = express.Router()
const mongoose = require('mongoose');
const requireLogin = require('../middlewares/requireLogin');
const POST  = mongoose.model('POST')
const USER = mongoose.model("USER")

router.get("/allPosts",requireLogin, async (req,res)=> {
    const limit = req.query.limit
    const skip = req.query.skip
    try{
        const posts = await POST.find().populate("postedBy","_id name Photo").populate("comments.postedBy","_id name")
        .skip(parseInt(skip)).limit(parseInt(limit)).sort('-createdAt')
        res.status(200).send(posts)
    }catch(err){
        console.log(err)
    }
})

router.post("/createPost",requireLogin, async (req,res) => {
    const {pic, body} = req.body
    if (!pic || !body){
        return res.status(422).json({error:"Please add all the feilds"})
    }
    const post = new POST({
        photo: pic,
        body,
        postedBy: req.user
    })
    try {await post.save()
    res.status(200).json({message:"Post Created Successfully"})
    } catch (err){
        console.log(err)
    }
})

router.get("/myPosts",requireLogin, async (req,res)=> {
    try{const response = await POST.find({postedBy: req.user.id}).populate("postedBy","_id name").populate("comments.postedBy","_id name")
    .sort('-createdAt')
    res.json(response)
}catch(err){
    console.log(err)
}
})

router.put("/like", requireLogin, async (req,res) => {
    try{
        const response = await POST.findByIdAndUpdate(req.body.postId,{
        $push: {
            likes: req.user._id
        }},{
            new: true
        }).populate("postedBy","_id name Photo")
        res.status(200).json(response)
    }catch(err){
        req.status(4222).json(err)
    }
})

router.put("/unlike", requireLogin, async (req,res) => {
    try{const response = await POST.findByIdAndUpdate(req.body.postId,{
        $pull: {
            likes: req.user._id
        }},{
            new: true
        }).populate("postedBy","_id name Photo")
    res.status(200).json(response)
    }catch(err){
        res.status(422).json(err)
    }
})

router.put("/comment", requireLogin, async (req,res)=> {
    try{const response = await POST.findByIdAndUpdate(req.body.postId,{
        $push : {
            comments: {
                comment: req.body.text,
                postedBy: req.user._id
            }
        }
    },{
        new: true
    }).populate("comments.postedBy","_id name")
    .populate("postedBy" , "_id name Photo")
    res.status(200).json(response)
    }catch(err){
        res.status(422).json(err)
    }
})

router.delete("/deletePost/:postId", requireLogin, async (req,res) => {
    try{const post = await POST.findOne({_id: req.params.postId}).populate("postedBy","_id")
        if(post.postedBy._id.toString() == req.user._id.toString()){
            try{await POST.deleteOne({_id: req.params.postId})
            res.status(200).json({message: "Post deleted Successfully"})
            }catch(err){
                res.status(422).json(err)
            }
        }
    }
    catch(err){
        res.status(422).json(err)
    }
})

router.get("/myfollowingpost",requireLogin, async (req,res) => {
    try{   
        const response = await POST.find({postedBy: {$in: req.user.following}}).populate("postedBy","_id name").populate("comments.postedBy","_id name")
        res.status(200).json(response)
    }catch(err){
        res.status(422).json(err)
    }
})

module.exports = router