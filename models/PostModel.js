const mongoose = require('mongoose');

const postSchema = mongoose.Schema({

    title:{
        type:String,
        required:[true,"title is required"],
        trim:true
    },
    description:{
        type:String,
        required:[true,"description is required"],
        trim:true
    },
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"Users",
        required:true,
    }

},{tiemstamps:true});

module.exports = mongoose.model("Posts",postSchema);