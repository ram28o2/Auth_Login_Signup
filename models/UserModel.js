const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: [true, "Email must be unique"],
    trim: true,
    minLenght: [5, "Email must be greater than 5 characters!"],
    lowercase: true,
  },
  password: {
    type: String,
    select: false,
    required: [true, "Password is required"],
    trim: true,
  },
  verified:{
    type:Boolean,
    default:false
  },
  verificationCode:{
    type:String,
    select:false,
  },
  verificationCodeValidation:{
    type:Number,
    select:false,
  },
  forgetPasswordCode:{
    type:String,
    select:false,
  },
  forgetPasswordCodeValidation:{
    type:Number,
    select:false,
  },
},{timestamps:true}); 

module.exports = mongoose.model("Users",userSchema);
