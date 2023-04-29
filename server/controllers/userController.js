const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail"); 
const shortid = require("shortid");
const Url = require("../models/url");
const validUrl = require('valid-url') 
// Generate Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};


const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all required fields");
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 characters");
  }

  // Check if user email already exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email has already been registered");
  }

  // Create new user
  const user = await User.create({
    name,
    email,
    password,
  });

  // Generate Token for email verification
  const token = await Token.create({
    userId: user._id,
    token: crypto.randomBytes(32).toString("hex"),
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
  });

  // Send Email Verification Link
  const verificationLink = `${req.protocol}://${req.get(
    "host"
  )}/api/auth/verify-email/${token.token}`;
  const message = `Please click the following link to verify your email address: ${verificationLink}`;
  await sendEmail({
    to: user.email,
    subject: "Email Verification",
    text: message,
  });

  // Send HTTP-only cookie
  const authCookieOptions = {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true,
  };
  res.cookie("token", generateToken(user._id), authCookieOptions);

  res.status(201).json({
    message:
      "User created successfully. Please check your email to verify your account.",
  });
});


// Login User
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validate Request
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  // Check if user exists
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }

  // User exists, check if password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  //   Generate Token
  const token = generateToken(user._id);
  
  if(passwordIsCorrect){
   // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "none",
    secure: true,
  });
}
  if (user && passwordIsCorrect) {
    const { _id, name, email } = user;
    res.status(200).json({
      _id,
      name,
      email,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid email or password");
  }
});

// Logout User
const logout = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Successfully Logged Out" });
});

// Get User Data
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email} = user;
    res.status(200).json({
      _id,
      name,
      email,
    });
  } else {
    res.status(400);
    throw new Error("User Not Found");
  }
});

// Get Login Status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  // Verify Token
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});


const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  // Delete token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create Reste Token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  // Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // Save Token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
  }).save();

  // Construct Reset Url
   const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;
  
  // Reset Email
  const message = `

    <h2>Dear ${user.name}</h2>


    <p>We recently received a request to reset your password for your account.To reset your password, please click on the link below</p>
 
      <p>This reset link is valid for only 30minutes.</p>

      <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

      <p>Regards...</p>
      <p>Support Team</p>
    `;
  const subject = "Password Reset Request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({ success: true, message: "Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;

  // Hash token, then compare to Token in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // fIND tOKEN in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or Expired Token");
  }

  // Find user
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: "Password Reset Successful, Please Login",
  });
});

 

// Route to shorten the long URL
const shorten = asyncHandler(async (req, res) => {
  const { longUrl } = req.body;

  // Check if the long URL is valid
  if (!validUrl.isUri(longUrl)) {
    return res.status(401).json('Invalid long URL');
  }

  try {
    // Check if the long URL already exists in the database
    let url = await Url.findOne({ longUrl });

    // If the long URL exists, return it
    if (url) {
      res.json(url);
    } else {
      // Generate a unique URL code
      const urlCode = shortid.generate();

      // Create the short URL
      const shortUrl = req.protocol + '://' + req.get('host') + '/' + urlCode;

      // Create a new URL object and save it to the database
      url = new Url({
        longUrl,
        shortUrl,
        urlCode,
        date: new Date(),
      });
      await url.save();

      res.json(url);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json('Server Error');
  }
});

const urlredirect = asyncHandler(async (req, res) => {
  try {
      // find a document match to the code in req.params.code
      const url = await Url.findOne({
          urlCode: req.params.code
      })
      if (url) {
          // when valid we perform a redirect
          return res.redirect(url.longUrl)
      } else {
          // else return a not found 404 status
          return res.status(404).json('No URL Found')
      }

  }
  // exception handler
  catch (err) {
      console.error(err)
      res.status(500).json('Server Error')
  }
})

const getAllUrls = asyncHandler(async (req, res) => {
  const urls = await Url.find({});

  if (!urls) {
    res.status(404);
    throw new Error("No URLs found");
  }

  res.status(200).json({ urls });
});






module.exports = {
  registerUser,
  loginUser,
  logout,
  loginStatus,
  forgotPassword,
  resetPassword,
  shorten,
  urlredirect,
  getAllUrls
};








