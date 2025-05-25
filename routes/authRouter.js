const express = require('express');

const {signup, signin, signout, sendVerificationCode, verifyVerificationCode, changePassword, sendForgetPasswordCode, verifyForgetPasswordCode} = require('../controllers/authController');
const { authValidation } = require('../middlewares/authValidation');

const router = express();

router.post("/signup",signup);
router.post("/signin",signin);
router.post("/signout",authValidation ,signout);

router.patch('/send-code',authValidation, sendVerificationCode);
router.patch('/verify-code',authValidation, verifyVerificationCode);
router.patch('/change-password',authValidation, changePassword);

router.patch('/forget-password', sendForgetPasswordCode);
router.patch('/reset-password', verifyForgetPasswordCode);

module.exports = router;