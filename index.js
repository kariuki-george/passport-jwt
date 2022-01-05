const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const dotenv = require("dotenv");
const passport = require("passport");
const authRoute = require("./app/auth/routes");

//basic config
const PORT = process.env.PORT || 3000;
dotenv.config();
require("./config/database");

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

// ---passport---
require("./app/auth/passportjwt")(passport);
require("./app/auth/passportGithub")(passport);
require("./app/auth/passportGoogle")(passport);
app.use(passport.initialize());

// ---Routes---
app.use("/api/auth", authRoute);

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
