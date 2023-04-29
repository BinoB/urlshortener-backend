const express = require("express");
const router = express.Router();
const {
 registerUser,
  loginUser,
  logout,
  loginStatus,
  forgotPassword,
  resetPassword,
  shorten,
  urlredirect,
  getAllUrls,
} = require("../controllers/userController");
const protect = require("../middleWare/authMiddleware");

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/logout", logout);
router.get("/loggedin", loginStatus);
router.post("/forgotpassword", forgotPassword);
router.put("/resetpassword/:resetToken", resetPassword);
router.post('/shorten', shorten);
router.get('/:code',urlredirect);
router.get('/urls',getAllUrls);

module.exports = router;