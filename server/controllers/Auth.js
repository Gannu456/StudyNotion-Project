const bcrypt = require("bcrypt")
const User = require("../models/User")
const OTP = require("../models/OTP")
const jwt = require("jsonwebtoken")
const otpGenerator = require("otp-generator")
const mailSender = require("../utils/mailSender")
const { passwordUpdated } = require("../mail/templates/passwordUpdate")
const Profile = require("../models/Profile")
require("dotenv").config()
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

// Signup Controller for Registering USers
const Buffer = require('buffer').Buffer

exports.signup = async (req, res) => {
  try {
    // Destructure fields from the request body
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body
    // Check if All Details are there or not
    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp
    ) {
      return res.status(403).send({
        success: false,
        message: "All Fields are required",
      })
    }
    // Check if password and confirm password match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message:
          "Password and Confirm Password do not match. Please try again.",
      })
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email })
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists. Please sign in to continue.",
      })
    }

    // Find the most recent OTP for the email
    const response = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1)
    console.log(response)
    if (response.length === 0) {
      // OTP not found for the email
      return res.status(400).json({
        success: false,
        message: "The OTP is not valid",
      })
    } else if (otp !== response[0].otp) {
      // Invalid OTP
      return res.status(400).json({
        success: false,
        message: "The OTP is not valid",
      })
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create the user
    let approved = ""
    approved === "Instructor" ? (approved = false) : (approved = true)

    // Create the Additional Profile For User
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    })
    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType: accountType,
      approved: approved,
      additionalDetails: profileDetails._id,
      image: "",
    })

    return res.status(200).json({
      success: true,
      user,
      message: "User registered successfully",
    })
  } catch (error) {
    console.error(error)
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again.",
    })
  }
}

// Login controller for authenticating users
exports.login = async (req, res) => {
  try {
    // Get email and password from request body
    const { email, password } = req.body

    // Check if email or password is missing
    if (!email || !password) {
      // Return 400 Bad Request status code with error message
      return res.status(400).json({
        success: false,
        message: `Please Fill up All the Required Fields`,
      })
    }

    // Find user with provided email
    const user = await User.findOne({ email }).populate("additionalDetails")

    // If user not found with provided email
    if (!user) {
      // Return 401 Unauthorized status code with error message
      return res.status(401).json({
        success: false,
        message: `User is not Registered with Us Please SignUp to Continue`,
      })
    }

    // Generate JWT token and Compare Password
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        { email: user.email, id: user._id, role: user.role },
        process.env.JWT_SECRET,
        {
          expiresIn: "24h",
        }
      )

      // Save token to user document in database
      user.token = token
      user.password = undefined
      // Set cookie for token and return success response
      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      }
      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: `User Login Success`,
      })
    } else {
      return res.status(401).json({
        success: false,
        message: `Password is incorrect`,
      })
    }
  } catch (error) {
    console.error(error)
    // Return 500 Internal Server Error status code with error message
    return res.status(500).json({
      success: false,
      message: `Login Failure Please Try Again`,
    })
  }
}
// Send OTP For Email Verification
exports.sendotp = async (req, res) => {
  try {
    const { email } = req.body

    // Check if user is already present
    // Find user with provided email
    const checkUserPresent = await User.findOne({ email })
    // to be used in case of signup

    // If user found with provided email
    if (checkUserPresent) {
      // Return 401 Unauthorized status code with error message
      return res.status(401).json({
        success: false,
        message: `User is Already Registered`,
      })
    }

    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    })
    const result = await OTP.findOne({ otp: otp })
    console.log("Result is Generate OTP Func")
    console.log("OTP", otp)
    console.log("Result", result)
    while (result) {
      otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
      })
    }
    const otpPayload = { email, otp }
    const otpBody = await OTP.create(otpPayload)
    console.log("OTP Body", otpBody)
    res.status(200).json({
      success: true,
      message: `OTP Sent Successfully`,
      otp,
    })
  } catch (error) {
    console.log(error.message)
    return res.status(500).json({ success: false, error: error.message })
  }
}

// Controller for Changing Password
exports.changePassword = async (req, res) => {
  try {
    // Get user data from req.user
    const userDetails = await User.findById(req.user.id)

    // Get old password, new password, and confirm new password from req.body
    const { oldPassword, newPassword } = req.body

    // Validate old password
    const isPasswordMatch = await bcrypt.compare(
      oldPassword,
      userDetails.password
    )
    if (!isPasswordMatch) {
      // If old password does not match, return a 401 (Unauthorized) error
      return res
        .status(401)
        .json({ success: false, message: "The password is incorrect" })
    }

    // Update password
    const encryptedPassword = await bcrypt.hash(newPassword, 10)
    const updatedUserDetails = await User.findByIdAndUpdate(
      req.user.id,
      { password: encryptedPassword },
      { new: true }
    )

    // Send notification email
    try {
      const emailResponse = await mailSender(
        updatedUserDetails.email,
        "Password for your account has been updated",
        passwordUpdated(
          updatedUserDetails.email,
          `Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
        )
      )
      console.log("Email sent successfully:", emailResponse.response)
    } catch (error) {
      // If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
      console.error("Error occurred while sending email:", error)
      return res.status(500).json({
        success: false,
        message: "Error occurred while sending email",
        error: error.message,
      })
    }

    // Return success response
    return res
      .status(200)
      .json({ success: true, message: "Password updated successfully" })
  } catch (error) {
    // If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
    console.error("Error occurred while updating password:", error)
    return res.status(500).json({
      success: false,
      message: "Error occurred while updating password",
      error: error.message,
    })
  }
}

exports.registerPasskey = async (req, res) => {
  try {
    const userId = req.user.id;
    // Fetch the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }
    // Convert the user ID (string) to a Uint8Array
    const userIDBuffer = Buffer.from(userId, 'utf8'); // Convert string to Buffer
    const userIDUint8Array = new Uint8Array(userIDBuffer); // Convert Buffer to Uint8Array
    // Prepare excludeCredentials (if any passkeys exist)
    const excludeCredentials = user.passkeys.map((passkey) => ({
      id: passkey.credentialID, // Ensure this is a Base64 URL-encoded string
      type: 'public-key',
    }));
    // Generate registration options (await the result)
    const options = await generateRegistrationOptions({
      rpName: 'Your App Name',
      rpID: process.env.RP_ID || 'localhost',
      userID: userIDUint8Array, // Pass the Uint8Array user ID
      userName: user.email,
      userDisplayName: `${user.firstName} ${user.lastName}`,
      attestationType: 'none',
      excludeCredentials, // Pass existing credential IDs to prevent re-registration
    });
    console.log("Generated Registration Options:", options); // Log the options
    // Save the challenge to the user
    user.currentChallenge = options.challenge;
    await user.save();
    res.status(200).json({
      success: true,
      message: 'Registration options generated successfully',
      options, // Ensure the options object contains a challenge
    });
  } catch (error) {
    console.error('Error in registerPasskey:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate registration options',
      error: error.message, // Include the error message in the response
    });
  }
};
exports.verifyPasskey = async (req, res) => {
  try {
    const { credential } = req.body;
    const userId = req.user.id;
    // Fetch the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }
    if (!user.currentChallenge) {
      return res.status(400).json({
        success: false,
        message: 'No pending challenge found for this user.',
      });
    }
    console.log("Received credential:", credential); // Log the received credential
    // Verify the registration response
    const verificationResult = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.ORIGIN || 'http://localhost:3000',
      expectedRPID: process.env.RP_ID || 'localhost',
    });
    console.log("Verification result:", verificationResult); // Log the verification result
    const { verified, registrationInfo } = verificationResult;
    if (!verified || !registrationInfo || !registrationInfo.credential) {
      return res.status(400).json({
        success: false,
        message: 'Passkey verification failed.',
      });
    }
    const { id, publicKey, counter, transports } = registrationInfo.credential;
    // Ensure the credential ID is a valid Base64 URL-encoded string
    const credentialID = Buffer.from(id).toString('base64url');
    // Add the new passkey to the user's passkeys array
    user.passkeys.push({
      credentialID, // Store as Base64 URL-encoded string
      credentialPublicKey: Buffer.from(publicKey).toString('base64'),
      counter,
      transports: transports || [], // Ensure transports is an array
    });
    // Clear the current challenge
    user.currentChallenge = null;
    // Save the updated user
    await user.save();
    res.status(200).json({
      success: true,
      message: 'Passkey registered successfully',
    });
  } catch (error) {
    console.error('Error in verifyPasskey:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify passkey',
      error: error.message, // Include the error message in the response
    });
  }
};


exports.loginWithPasskey = async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Prepare allowCredentials array
    const allowCredentials = user.passkeys.map((passkey) => {
      // Decode the credentialID from Base64 URL format
      const credentialID = Buffer.from(passkey.credentialID, 'base64url');
      return {
        id: credentialID, // Pass the decoded Buffer
        type: "public-key",
        transports: passkey.transports || ["usb", "ble", "nfc"], // Default transports
      };
    });

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID: process.env.RP_ID || "localhost", // Use environment variable or default to 'localhost'
      allowCredentials, // Pass the allowCredentials array
      userVerification: "preferred", // Prefer user verification
      timeout: 60000, // 60 seconds timeout
    });

    // Save the current challenge to the user
    user.currentChallenge = options.challenge;
    await user.save();

    // Return the authentication options
    res.status(200).json({
      success: true,
      options,
    });
  } catch (error) {
    console.error("Error generating passkey login options:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate passkey login options",
      error: error.message, // Include the error message for debugging
    });
  }
};

exports.verifyPasskeyLogin = async (req, res) => {
  try {
    const { email, credential } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if there's a pending challenge for the user
    if (!user.currentChallenge) {
      return res.status(400).json({
        success: false,
        message: "No pending challenge found for this user.",
      });
    }

    // Find the matching passkey for the credential ID
    const passkey = user.passkeys.find((p) => {
      const credentialID = Buffer.from(p.credentialID, 'base64url').toString('base64url');
      return credentialID === Buffer.from(credential.id, 'base64url').toString('base64url');
    });

    if (!passkey) {
      return res.status(400).json({
        success: false,
        message: "Passkey not found for this user.",
      });
    }

    // Decode the credentialID and public key
    const credentialIDBuffer = Buffer.from(passkey.credentialID, 'base64url');
    const credentialPublicKeyBuffer = Buffer.from(passkey.credentialPublicKey, 'base64');

    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: process.env.ORIGIN || "http://localhost:3000",
      expectedRPID: process.env.RP_ID || "localhost",
      authenticator: {
        credentialPublicKey: credentialPublicKeyBuffer,
        credentialID: credentialIDBuffer,
        counter: passkey.counter,
      },
      requireUserVerification: false,
    });

    // Check if verification was successful
    if (!verification.verified) {
      return res.status(400).json({
        success: false,
        message: "Passkey verification failed.",
      });
    }

    // Generate a JWT token for the user
    const token = jwt.sign(
      { email: user.email, id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Save the token and clear the current challenge
    user.token = token;
    user.currentChallenge = null;
    await user.save();

    // Return the token and user data
    res.status(200).json({
      success: true,
      token,
      user,
      message: "Passkey login successful",
    });
  } catch (error) {
    console.error("Error verifying passkey login:", error);
    res.status(500).json({
      success: false,
      message: "Failed to verify passkey login",
      error: error.message, // Include the error message for debugging
    });
  }
};