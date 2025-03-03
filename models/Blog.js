const mongoose=require("mongoose")
const blogSchema=new mongoose.Schema({
    title:{type:'string',required:"true"},
    content:{type:'string',required:"true"},
    // author:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:"true"},
    editor:{type:mongoose.Schema.Types.ObjectId,ref:"User",default:null}
})

module.exports=mongoose.model("Blog",blogSchema)