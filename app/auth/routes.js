const router = require("express").Router();
const { validPassword, genPassword, issueJWT } = require("./passwordUtils");
const { User } = require("../users/index");
const crypto = require("crypto");

//---email---
router.post("/register-with-email", async (req, res, next) => {
  const saltHash = genPassword(req.body.password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;
  //since the User model has the email field set --unique:false-- we must check if a user with this email and strategy already exists

  try {
    const user = await User.findOne({
      email: req.body.email,
      strategy: "email",
    });
    if (user)
      return res.status(403).json({
        success: false,
        message: "User with this email already exists",
      });
    const newUser = new User({
      email: req.body.email,
      hash: hash,
      salt: salt,
      strategy: "email",
    });
    await newUser.save();

    return res.status(201).json({ success: true });
  } catch (error) {
    return res.status(500).json(error);
  }
});

router.post("/login-with-email", async (req, res, next) => {
  try {
    let user = await User.findOne({
      email: req.body.email,
      strategy: "email",
    });
    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "Could not find the user" });
    const isValid = validPassword(req.body.password, user.hash, user.salt);
    if (!isValid)
      return res
        .status(401)
        .json({ success: false, message: "Check your email or password" });
    const { token, expires } = issueJWT(user._id);
    const loggedUser = {
      email: user.email,
      strategy: user.strategy,

      _id: user._id,
      __v: user.__v,
    };

    res.status(200).json({ success: true, user: loggedUser, token, expires });
  } catch (error) {
    res.status(500).json(error);
  }
});

//---password reset---
//---forgot password ---> send email with an otp then a reset route---
router.post("/forgot-password", async (req, res, next) => {
  //create otp ; valid 1hr
  const otp = crypto.randomBytes(6).toString("hex");
  const otp_expires = (Date.now() + 1000 * 60 * 5).toString(); //valid for 1 hour
  const user = await User.findOneAndUpdate(
    { email: req.body.email, strategy: "email" },
    {
      otp,
      otp_expires,
    },
    { new: true }
  );

  //send email
  return res.json(otp);
});
router.post("/verify-otp", async (req, res, next) => {
  //verify otp
  const { otp, email } = req.body;
  try {
    const user = await User.findOne({
      email,
      strategy: "email",
    });
    if (parseInt(user.otp_expires) <= Date.now()) {
      return res
        .status(403)
        .json({ success: false, message: "The otp has already expired" });
    }

    if (!(otp == user.otp)) {
      return res
        .status(403)
        .json({ success: false, message: "The otp is not legit" });
    }

    //redirect to password reset
    return res.status(200).json({ success: true, message: "otp valid" });
  } catch (error) {
    res.status(500).json(error);
  }
});
//---password-reset---
router.post("/password-reset", async (req, res) => {
  //get email and new password and create new hash and salt
  const { password, email } = req.body;
  const saltHash = genPassword(password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;
  //update current email record
  try {
    const user = await User.findOneAndUpdate(
      { email, strategy: "email" },
      {
        salt,
        hash,
        otp: "",
        otp_expires: "",
      },
      { new: true }
    );
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "user does not exist" });
    return res.status(200).json({ success: true, user });
  } catch (error) {
    res.status(500).json(error);
  }

  //success
});

//---test route---

const passport = require("passport");
router.get(
  "/users",
  passport.authenticate("jwt", { session: false }),
  async (req, res, next) => {
    try {
      const users = await User.find();
      return res.json(users);
    } catch (error) {
      return res.status(500).json(error);
    }
  }
);

//---github---

router.get(
  "/github",
  passport.authenticate("github", { scope: ["openid", "profile", "email"] })
);

router.get(
  "/github/callback",
  passport.authenticate("github", {
    failureRedirect: "/login",
    session: false,
  }),
  function (req, res) {
    const { token, expires } = issueJWT(req.user.id);
    res.status(200).json({ success: true, user: req.user, token, expires });
  }
);

//---google---
router.get(
  "/google",
  passport.authenticate("google", { scope: ["openid", "profile", "email"] })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    session: false,
  }),
  function (req, res) {
    const { token, expires } = issueJWT(req.user.id);
    res.status(200).json({ success: true, user: req.user, token, expires });
  }
);

//handle failure redirect for both github and google
router.get("/login", (req, res) => {
  return res
    .status(401)
    .json({ success: false, message: "Authentication failed." });
});

module.exports = router;
