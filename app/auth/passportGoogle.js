const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;
const { User } = require("../users/index");
const dotenv = require("dotenv");

dotenv.config();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const options = {
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/api/auth/google/callback",
};

const strategy = new GoogleStrategy(
  options,
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (user) return done(null, user);

      const newUser = new User({
        email: profile._json.email,
        strategy: "google",
        googleId: profile.id,
      });
      user = await newUser.save();
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
);

module.exports = (passport) => {
  passport.use(strategy);
};
