const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
  email: {
    type: "String",

    required: true,
  },
  hash: String,
  salt: String,
  strategy: String,
  githubId: String,
  googleId: String,
  otp: { type: "String", default: "" },
  otp_expires: { type: "String", default: "" },
});

module.exports = mongoose.model("User", userSchema);
