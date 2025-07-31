const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;
const User = require("../models/User");
require("dotenv").config();

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL || "http://localhost:3000/api/auth/github/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });

        if (!user) {
          // Only set email if it exists and is valid
          const email = profile.emails?.[0]?.value;
          const userData = {
            githubId: profile.id,
            username: profile.username,
            avatar: profile.photos[0]?.value || "",
            accessToken: accessToken, // Store access token
          };
          
          // Only add email if it exists
          if (email && email.trim()) {
            userData.email = email;
          }
          
          user = await User.create(userData);
        } else {
          user.accessToken = accessToken; // Update access token
          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// ✅ Ensure the user ID is properly serialized
passport.serializeUser((user, done) => {
  console.log("Serializing user:", user._id);
  done(null, user._id);
});

// ✅ Ensure the user is properly deserialized
passport.deserializeUser(async (id, done) => {
  try {
    console.log("Deserializing user ID:", id);
    const user = await User.findById(id);
    console.log("Found user:", user ? user.username : 'null');
    done(null, user);
  } catch (error) {
    console.error("Deserialization error:", error);
    done(error, null);
  }
});
