const GithubStrategy = require("passport-github2").Strategy;
const { User } = require("../users/index");
const dotenv = require("dotenv");

dotenv.config();
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;

const options = {
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/api/auth/github/callback",
  scope: ["user:email"],
};

const strategy = new GithubStrategy(
  options,
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
      if (user) return done(null, user);

      const newUser = new User({
        email: profile.emails[0].value,
        strategy: "github",
        githubId: profile.id,
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
