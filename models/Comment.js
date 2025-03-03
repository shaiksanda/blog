const mongoose=require("mongoose")
const commentSchema=new mongoose.Schema({
    blogId:{type:mongoose.Schema.Types.ObjectId,ref:"Blog",required:"true"},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:"true"},
    text:{type:"string",required:'true'}
})

module.exports=mongoose.model("Comment",commentSchema)