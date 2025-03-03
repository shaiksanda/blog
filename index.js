const express = require('express')
const mongoose = require('mongoose');
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const uuid=require('uuid')
const nodemailer=require("nodemailer")
require('dotenv').config()
const app = express()
const User = require('./models/User')
const Blog = require("./models/Blog")
const Comment=require("./models/Comment")
app.use(cors())
app.use(express.json())
const transporter=nodemailer.createTransport({
    service:"gmail",
    auth:{
        user:process.env.EMAIL,
        pass:process.env.PASSWORD
    }
})

const connectToMongodb = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI)
        console.log("MongoDb Database Connected Successfully")
    }
    catch (error) {
        console.error(error)
        process.exit(1)
    }
}

connectToMongodb()

const authenticateToken = (req, res, next) => {
    const authHeaders = req.headers['authorization']
    if (!authHeaders) {
        return res.status(401).send({ error_msg: "Authorization Header Is Missing" })
    }
    const jwtToken = authHeaders.split(" ")[1]
    if (!jwtToken) {
        return res.status(401).send({ error_msg: "Invalid JWT TOKEN" })
    }

    jwt.verify(jwtToken, process.env.JWT_SECRET, (err, payload) => {
        if (err) {
            return res.status(401).send({ error_msg: err })
        }
        if(!payload.isVerified){
            return res.status(401).send({error_msg:"Please Verify the Email"})
        }
        req.user = { userId: payload.userId, username: payload.username, role: payload.role }
        
        next()
    })
}

app.get('/', function (req, res) {
    
    res.send('Hello World')
})

const sendVerificationEmail=async(email,token)=>{
    
    const verificationLink=`${process.env.BASE_URL}/verify?token=${token}`
    const mailOptions={
        from:process.env.EMAIL,
        to:email,
        subject:"Verify Your Email",
        text:`Click the Following link to verify Your Email: ${verificationLink}`
    }

    await transporter.sendMail(mailOptions)

}

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    const isExistingUser = await User.findOne({ username: username })
    const isExistingEmail = await User.findOne({ email })
    if (isExistingUser) {
        return res.status(400).send({ error_msg: "User Already Exists" })
    }
    if (isExistingEmail) {
        return res.status(400).send({ error_msg: "Email Already Exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    

    try {
        const newUser=await User.create({
            username,
            email,
            password: hashedPassword,
           
        })
        const payload={email:newUser.email};
        const token=jwt.sign(payload,process.env.EMAIL_VERIFICATION_TOKEN,{expiresIn:"3m"})
        
        sendVerificationEmail(email,token)
        res.status(201).send({ success_msg: "User Created Successfully. Please check your email to verify your account."})
    }
    catch (error) {
        res.send({ error_msg: `Error Creating User: ${error.message}` })
    }


})

app.get("/verify",async(req,res)=>{
    const {token}=req.query
    try{
        const decoded=jwt.verify(token,process.env.EMAIL_VERIFICATION_TOKEN)
        const user=await User.findOne({email:decoded.email})
        if(!user){
            return res.status(400).send({error_msg:"Invalid Token"})
        }

        if (user.isVerified) {
            return res.status(400).send({ error_msg: "Email already verified" });
        }
        user.isVerified=true;
        await user.save(); // ✅ Saves the changes

        res.status(200).send({success_msg:"Email Verified Successfully! You can now log in."})
    }catch(error){
        res.status(500).send({error_msg:error.message})
    }
})

app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username })

        if (!existingUser) {
            return res.status(404).send({ error_msg: "User Not Found" })
        }
        if(!existingUser.isVerified){
            return res.status(401).send({error_msg:"Please verify The Email to Proceed Further"})
        }
        const isPasswordMatched =await bcrypt.compare(password, existingUser.password)
        if (!isPasswordMatched) {
            return res.status(401).send({ error_msg: "Password is not correct" })
        }
        const payload = { userId: existingUser._id, username: existingUser.username, role: existingUser.role,isVerified:existingUser.isVerified }
        const jwtToken = jwt.sign(payload, process.env.JWT_SECRET,{expiresIn:"3d"})
        return res.status(200).send({ success_msg: "User Logged In Successfully", jwtToken })
    }
    catch (error) {
        res.status(500).send({ error_msg: `Error Logging in User: ${error.message}` })
    }
})

app.post("/create", authenticateToken, async (req, res) => {
    const { role } = req.user;
    const { title, content } = req.body;
    try {
        if (role === "admin") {
            await Blog.create({ title, content })
            return res.status(201).send({ success_msg: "Blog Created Successfully" })
        } else {
            return res.status(403).send({ error_msg: "You Don't Have Access To create Blogs" })
        }
    }
    catch (error) {
        return res.status(500).send({ error_msg: error.message })
    }

})

app.put("/blog/:blogId", authenticateToken, async (req, res) => {
    const { blogId } = req.params;
    const { role } = req.user
    const { title, content } = req.body
    const blog = await Blog.findById(blogId)
    let blogEditAccess = false;
    if (blog) {
        const editorId = blog.editor
        const editor = await User.findById(editorId)

        if (editor) {
            blogEditAccess = editor.assignedBlogs.includes(blogId)
        }
    }
    else {
        return res.status(404).send({ error_msg: "Blog Not Found" })
    }

    try {
        if (role === "admin" || blogEditAccess) {
            await Blog.findByIdAndUpdate(blogId, { $set: { title, content } }, { new: true })

            res.status(200).send({ success_msg: "Blog Updated Successfully" })
        }
        else {
            return res.status(403).send({ error_msg: "You Dont Have Access to Edit the Blog" })
        }
    }
    catch (error) {
        res.status(500).send({ error_msg: error.message })
    }

})

app.put("/assign-blog/:blogId", authenticateToken, async (req, res) => {
    const { role } = req.user;
    const { blogId } = req.params
    const { editorId } = req.body;
    try {
        const blog = await Blog.findById(blogId)
        if (!blog) {
            return res.status(404).send({ error_msg: "Blog Not Found" })
        }
        if (role === "admin") {
            const editor = await User.findById(editorId)
            if (!editor) {
                return res.status(404).send({ error_msg: "Editor Not Found" })
            }
            if(blog.editor){
                return res.status(400).send({ error_msg: "This blog is already assigned"});
            }
            editor.assignedBlogs=[...new Set([...(editor.assignedBlogs||[]),blogId])]
            await editor.save()
            blog.editor = editorId
            await blog.save()
            res.status(200).send({ success_msg: "Blog assigned successfully" });
        }
        else{
            return res.status(403).send({error_msg:"You Dont Have Access to Assign an Editor"})
        }
    }
    catch (error) {
        res.status(500).send({ error_msg: error.message })
    }
})

app.delete('/delete-blog', authenticateToken, async (req, res) => {
    const { id } = req.body;
    const { role } = req.user;
    try {
        if (!id) {
            return res.status(400).send({ error_msg: "Blog ID is required" })
        }

        if (role === "admin") {
            const blog = await Blog.findById(id)
            if (!blog) {
                return res.status(404).send({ error_msg: "Blog Not Found" })
            }

            await Blog.findByIdAndDelete(id)
            res.status(200).send({ success_msg: "Blog Deleted Successfully" })
        }
        else {
            return res.status(403).send({ error_msg: "You Dont have Access to Delete The Blog" })
        }
    }
    catch (error) {
        res.status(500).send({ error_msg: error.message })
    }



})

app.get("/blogs",authenticateToken,async(req,res)=>{
    try{
        const blogs=await Blog.find()
        res.status(200).send(blogs)
        
    }
    catch(error){
        res.status(500).send({error_msg:error.message})
    }
})

app.post('/comment/:blogId',authenticateToken,async(req,res)=>{
    const {blogId}=req.params;
    const {text}=req.body;
    const {userId}=req.user

    try{
        const blog=await Blog.findById(blogId)
    if(!blog){
        return res.status(404).send({error_msg:"Blog Not Found"})
    }
    await Comment.create({blogId,userId,text})
    res.status(200).send({success_msg:"Comment Added Successfully"})

    }
    catch(error){
        res.status(500).send({error_msg:error.message})
    }
})


app.delete("/comment/:commentId",authenticateToken,async(req,res)=>{
    const {commentId}=req.params
    const {userId}=req.user
     
    try{
        const comment=await Comment.findById(commentId)
        if(!comment){
            return res.status(404).send({error_msg:"Comment Not Found"})
        }
        if (comment.userId.toString()!==userId.toString()){
            return res.status(403).send({error_msg:"Unauthorized To Delete this Comment"})
        }
        await Comment.findByIdAndDelete(commentId)
        res.status(200).send({success_msg:"Comment Deleted Successfully"})
    }
    catch(error){
        res.status(500).send({error_msg:error.message})
    }
})



app.get("/data", async (req, res) => {
    try {
        const connection = mongoose.connection.useDb("sample_weatherdata"); // Switch to the correct DB
        const collection = connection.collection("data"); // Access collection

        const data = await collection.find({}).limit(20).toArray(); // Fetch data
        res.status(200).send(data);
    } catch (error) {
        res.status(500).send({ error_msg: error.message });
    }
});

app.get("/restaurants",async(req,res)=>{
    try{
        const connection=mongoose.connection.useDb("sample_restaurants")
        const collection=connection.collection("restaurants")
        const data=await collection.find().limit(20).toArray()
        res.status(200).send(data)
    }
    catch(error){
        res.status(500).send({error_msg:error.message})
    }
})


const port = process.env.PORT || 3004
app.listen(port, () => {
    console.log(`Server Is Running at http://localhost:${port}`)
})