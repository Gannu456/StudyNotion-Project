// Import the required modules
const express = require("express")
const router = express.Router()
const User = require("../models/User") // Import the User model

// Import the required controllers and middleware functions
const {
  login,
  signup,
  sendotp,
  changePassword,
  registerPasskey, 
  verifyPasskey,
  loginWithPasskey,
  verifyPasskeyLogin,
} = require("../controllers/Auth")
const {
  resetPasswordToken,
  resetPassword,
} = require("../controllers/resetPassword")

const { auth } = require("../middleware/auth")

// Route for logging in with a passkey
router.post("/login-with-passkey", loginWithPasskey);

// Route for verifying a passkey login
router.post("/verify-passkey-login", verifyPasskeyLogin);

// Routes for Login, Signup, and Authentication

// ********************************************************************************************************
//                                      Authentication routes
// ********************************************************************************************************

// Route for user login
router.post("/login", login)

// Route for user signup
router.post("/signup", signup)

// Route for sending OTP to the user's email
router.post("/sendotp", sendotp)

// Route for Changing the password
router.post("/changepassword", auth, changePassword)

// ********************************************************************************************************
//                                      Reset Password
// ********************************************************************************************************

// Route for generating a reset password token
router.post("/reset-password-token", resetPasswordToken)

// Route for resetting user's password after verification
router.post("/reset-password", resetPassword)

router.post("/register-passkey", auth, registerPasskey);
router.post("/register-passkey/verify", auth, verifyPasskey);
router.post("/removePasskey", auth, async (req, res) => {
  try {
    const { credentialID } = req.body;
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.passkeys = user.passkeys.filter(
      (passkey) => passkey.credentialID !== credentialID
    );

    await user.save();

    res.status(200).json({ success: true, message: "Passkey removed" });
  } catch (error) {
    console.error("Remove passkey error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

router.post("/updatePasskeyName", auth, async (req, res) => {
  try {
    const { credentialID, name } = req.body;
    const user = await User.findById(req.user.id);

    if (!user) {
      console.log("User not found for id:", req.user.id);
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Update the name in the passkeys array
    user.passkeys = user.passkeys.map((p) =>
      p.credentialID === credentialID ? { ...p, name } : p
    );

    await user.save();
    console.log("Passkey name updated successfully for user:", user.id);
    res.status(200).json({ success: true, message: "Passkey name updated" });
  } catch (error) {
    console.error("Update passkey name error:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});
// Export the router for use in the main application
module.exports = router
