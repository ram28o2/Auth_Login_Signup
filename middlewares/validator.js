const Joi = require("joi");

const passwordPattern = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$");

exports.signupSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({ tlds: { allow: ["com", "net", "edu"] } }),

  password: Joi.string().required().pattern(passwordPattern),
});

exports.signinSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({ tlds: { allow: ["com", "net", "edu"] } }),

  password: Joi.string().required().pattern(passwordPattern),
});

exports.codeSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({ tlds: { allow: ["com", "net", "edu"] } }),

  providedCode: Joi.number(),
});

exports.changeSchema = Joi.object({
  oldPassword: Joi.string().required().pattern(passwordPattern),
  newPassword: Joi.string().required().pattern(passwordPattern),
});

exports.forgetPasswordSchema = Joi.object({
  email: Joi.string()
    .min(6)
    .max(60)
    .required()
    .email({ tlds: { allow: ["com", "net", "edu"] } }),

  providedCode: Joi.number(),

  newPassword: Joi.string().required().pattern(passwordPattern),

});
