const transport = require("../middlewares/sendMail");
const { signupSchema, signinSchema, codeSchema, changeSchema, forgetPasswordSchema } = require("../middlewares/validator");
const User = require("../models/UserModel");
const hash = require("../utils/hashing");
const jwt = require("jsonwebtoken");

exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signupSchema.validate({ email, password });

    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.details[0].message });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(401)
        .json({ success: false, msg: "User already exist" });
    }

    const hashedPassword = await hash.doHash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword,
    });

    const result = await newUser.save();

    result.password = undefined;

    res
      .status(201)
      .json({ success: true, msg: "Your account created successfully!" });
  } catch (error) {
    console.log(error);
  }
};

exports.signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signinSchema.validate({ email, password });

    if (error) {
      return res
        .status(401)
        .json({ success: false, message: error.message[0].details });
    }

    const existingUser = await User.findOne({ email }).select("+password");

    if (!existingUser) {
      return res
        .status(401)
        .json({ success: false, message: "User Does not exist!" });
    }

    const hashedPassword = hash.doHashSignin(password, existingUser.password);

    if (!hashedPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid Credentails.." });
    }

    const token = jwt.sign(
      {
        userId: existingUser._id,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.JWT_TOKEN,
      {
        expiresIn: "8h",
      }
    );

    res
      .cookie("Authorization", "Bearer " + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === "production",
        secure: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        message: "Logged-In Successful",
      });
  } catch (error) {
    console.log(error);
  }
};

exports.signout = async (req, res) => {
  res
    .clearCookie("Authentication")
    .status(200)
    .json({ success: true, message: "Logged-out Successfully" });
};

exports.sendVerificationCode = async (req, res) => {
  try {
    const { email } = req.body;

    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User does not exist" });
    }

    if (existingUser.verified) {
      return res
        .status(400)
        .json({ success: false, message: "You are already verified" });
    }

    const verifyCode = Math.floor(Math.random() * 1000000).toString();

    let info = await transport.sendMail({
      from: process.env.EMAIL_ID,
      to: existingUser.email,
      subject: "Verification Code",
      html: "<h1>" + verifyCode + "</h1>",
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedVerifycode = hash.hmacProcess(
        verifyCode,
        process.env.HMAC_VERIFY_CODE
      );

      existingUser.verificationCode = hashedVerifycode;

      existingUser.verificationCodeValidation = Date.now();

      await existingUser.save();

      return res.status(200).json({ success: true, message: "Code sent!" });
    }

    res.status(400).json({ success: false, message: "Code sent Failed!" });
  } catch (error) {
    console.log(error);
  }
};

exports.verifyVerificationCode = async(req, res) => {

    try {

        const {email, providedCode} = req.body;

        const{value, error} = codeSchema.validate({email, providedCode});

        if(error){
            return res.status(400).json({success:false,message:error.details[0].message});
        }

        const verifycode = providedCode.toString();

        const existingUser = await User.findOne({email}).select("+verificationCode").select("+verificationCodeValidation");

        if(!existingUser) {
            return res
                .status(401)
                .json({ success: false, msg: "User already exist" });
        }

        if(existingUser.verified){

            return res.status(400).json({success:false,message:"User already verified"});

        }

        console.log("Existing User : ", existingUser.verificationCode);
        console.log("Existing User Validation : ", existingUser.verificationCodeValidation);

        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation){
            return res.status(400).json({success:false,message:"Something went wrong with the code"});
        }

        if(Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000){

            return res.staus(400).json({success:false,message:"Code has been expired!"});

        }

        const hashedVerifycode = hash.hmacProcess(verifycode,process.env.HMAC_VERIFY_CODE);

        if(hashedVerifycode === existingUser.verificationCode){

            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;

            await existingUser.save();

            return res.status(200).json({succss:true,message:"Your account is verified"});

        }

        return res.status(400).json({succss:false,message:"Unexpected error occured while verifing the user"});
        
    } catch (error) {
        console.log(error);
    }

}

exports.changePassword = async (req, res) =>{

    const {userId, verified } = req.user;

    const {oldPassword, newPassword} = req.body;

    try {
        
        const {value, error} = changeSchema.validate({oldPassword, newPassword});

        if(error) return res.status(400).json({success:false,message:error.details[0].message});

        // if(!verified) return res.status(400).json({success:false,message:"You are not verified"});

        const existingUser = await User.findOne({_id:userId}).select("+password");

        if(!existingUser) return res.status(400).json({success:false,message:"User does not exist"});

        const result = await hash.doHashSignin(oldPassword,existingUser.password);

        console.log("Result : ", result);

        if(!result) return res.status(400).json({success:false,message:"Invalid Credentails"});

        const hashedPassword = await hash.doHash(newPassword,12);

        existingUser.password = hashedPassword;

        await existingUser.save();

        return res.status(200).json({success:true,message:"password changed"});


    } catch (error) {
        console.log(error);
    }

}


exports.sendForgetPasswordCode = async (req, res) => {
  try {
    const { email } = req.body;

    const existingUser = await User.findOne({ email });

    if (!existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "User does not exist" });
    }

    const verifyCode = Math.floor(Math.random() * 1000000).toString();

    let info = await transport.sendMail({
      from: process.env.EMAIL_ID,
      to: existingUser.email,
      subject: "Forget Password Code",
      html: "<h1>" + verifyCode + "</h1>",
    });

    if (info.accepted[0] === existingUser.email) {

      const hashedVerifycode = hash.hmacProcess(
        verifyCode,
        process.env.HMAC_VERIFY_CODE

      );

      existingUser.forgetPasswordCode = hashedVerifycode;

      existingUser.forgetPasswordCodeValidation = Date.now();

      await existingUser.save();

      return res.status(200).json({ success: true, message: "Code sent!" });
    }

    res.status(400).json({ success: false, message: "Code sent Failed!" });
  } catch (error) {
    console.log(error);
  }
};

exports.verifyForgetPasswordCode = async(req, res) => {

    try {

        const {email, providedCode, newPassword} = req.body;

        const{value, error} = forgetPasswordSchema.validate({email, providedCode,newPassword});

        if(error){
            return res.status(400).json({success:false,message:error.details[0].message});
        }

        const verifycode = providedCode.toString();

        const existingUser = await User.findOne({email}).select("+forgetPasswordCode").select("+forgetPasswordCodeValidation");

        if(!existingUser) {
            return res
                .status(401)
                .json({ success: false, msg: "User does not exist" });
        }

        if(!existingUser.forgetPasswordCode || !existingUser.forgetPasswordCodeValidation){
            return res.status(400).json({success:false,message:"Something went wrong with the code"});
        }

        if(Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000){

            return res.staus(400).json({success:false,message:"Code has been expired!"});

        }

        const hashedVerifycode = hash.hmacProcess(verifycode,process.env.HMAC_VERIFY_CODE);

        if(hashedVerifycode === existingUser.forgetPasswordCode){

          const hashedPassword = await hash.doHash(newPassword,12);

          console.log("Hashed Password : ", hashedPassword);

            existingUser.password = hashedPassword;
            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;

            await existingUser.save();

            return res.status(200).json({succss:true,message:"Password Updated!"});

        }

        return res.status(400).json({succss:false,message:"Unexpected error occured while verifing the user"});
        
    } catch (error) {
        console.log(error);
    }

}