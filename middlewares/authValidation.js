const jwt = require("jsonwebtoken");

exports.authValidation = (req, res,next) =>{

    let token;

    if(req.headers.client === 'not-browser'){
        token = req.headers.authorization;
    }else{
        token = req.cookies['Authorization'];
    }

    // console.log("Token : "+token);

    if(!token){

        return res.status(403).json({success:false,message:"You are Unauthorized!"});

    }

    try {
        const userToken = token.split(" ")[1];
        // console.log("User Token : "+userToken);
        if(!userToken){
            return res.status(403).json({success:false,message:"You are Unauthorized!"});
        }
        const jwtverified = jwt.verify(userToken,process.env.JWT_TOKEN);

        if(jwtverified){
            req.user = jwtverified;
            next();
        }else{
            throw new Error("Error in token");
        }

    } catch (error) {
        console.log("Error : "+error);
    }
}