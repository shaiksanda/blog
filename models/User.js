const mongoose=require("mongoose")


const userSchema=new mongoose.Schema({
    username:{type:"string",required:"true",unique:"true"},
    password:{type:"string",required:"true"},
    email:{type:"string",required:"true",unique:"true"},
    role:{type:'string',enum:["admin","editor","user"],default:"user"},
    isVerified:{type:Boolean,default:false},
    
    assignedBlogs:[{type:mongoose.Schema.Types.ObjectId,ref:"Blog",default:[]}]

})

module.exports=mongoose.model("User",userSchema)