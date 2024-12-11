import passport from "passport";
import express from "express";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import User from "../models/User.js";
import { validationResult, body } from 'express-validator';
import bodyParser from "body-parser"; // Nếu sử dụng body-parser


const router = express.Router();

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Serialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Register new user
router.post("/register", async (req, res) => {

  const { email, password, confirmPassword, name } = req.body;
  // Kiểm tra các trường bắt buộc
  if (!email || !password || !confirmPassword || !name) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  // Kiểm tra confirmPassword
  if (password !== confirmPassword) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    // Kiểm tra email đã tồn tại chưa
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Mã hóa mật khẩu
    const hashedPassword = await bcrypt.hash(password, 10);

    // Tạo user mới
    const newUser = new User({
      email,
      password: hashedPassword,
      name,
    });

    await newUser.save();

    // Phản hồi thành công
    res.redirect("/auth/register-form");
  } catch (error) {
    console.error("Error registering user:", error);
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

router.post(
  '/register-form',
  [
    body('email').isEmail().withMessage('Email không hợp lệ.'),
    body('role').notEmpty().withMessage('Vai trò không được để trống.'),
    body('name').notEmpty().withMessage('Họ và tên không được để trống.'),
    body('dob').notEmpty().withMessage('Ngày sinh không được để trống.'),
    body('phone').notEmpty().withMessage('Số điện thoại không được để trống.'),
    body('gender').notEmpty().withMessage('Giới tính không được để trống.'),
    body('country').notEmpty().withMessage('Quốc tịch không được để trống.'),
  ],
  async (req, res) => {
    // Lấy các lỗi nếu có
    const errors = validationResult(req);

    // In ra body nhận được để debug
    console.log('Dữ liệu nhận được: ', req.body);

    // Kiểm tra nếu có lỗi từ validation
    if (!errors.isEmpty()) {
      console.log('Lỗi validation: ', errors.array());
      return res.status(400).json({
        message: 'Dữ liệu đầu vào không hợp lệ.',
        errors: errors.array(), // Trả về lỗi chi tiết
      });
    }

    const { email, role, name, dob, phone, gender, country } = req.body;

    try {
      // Kiểm tra nếu người dùng đã tồn tại trong hệ thống
      const existingUser = await User.findOne({ email });

      if (existingUser) {
        return res.status(400).json({
          message: 'Email đã được sử dụng. Vui lòng chọn email khác.',
        });
      }

      const user = await User.findOneAndUpdate(
        { email }, // Điều kiện tìm kiếm
        { $set: updateData }, // Dữ liệu cập nhật
        { new: true, upsert: false } // Trả về user đã cập nhật, không tự động tạo nếu không tồn tại
      );

      if (!user) {
        return res.status(404).json({
          message: 'Không tìm thấy người dùng với email đã cung cấp.',
        });
      }

      return res.status(200).json({
        message: 'Cập nhật thông tin người dùng thành công.',
        user,
      });
    } catch (err) {
      return res.status(500).json({
        message: 'Đã xảy ra lỗi trong quá trình cập nhật.',
        error: err.message,
      });
    }
  }
);

// Log in existing user
router.post("/login", passport.authenticate("local"), (req, res) => {
  res.json({ message: "Logged in successfully" });
});

// Change password
router.post("/change-password", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Not authenticated" });
  }
  const { currentPassword, newPassword } = req.body;
  const user = req.user;
  const isMatch = await bcrypt.compare(currentPassword, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Current password is incorrect" });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
    res.json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error changing password" });
  }
});

// Log out user
router.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ message: "Error logging out" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

// Render login page
router.get("/login", (req, res) => {
  res.render("pages/login");
});

// Render register page
router.get("/register", (req, res) => {
  res.render("pages/register");
});

router.get("/logout", (req, res) => {
  res.send("Logging out");
});

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

// Callback route for google redirect
router.get("/google/redirect", passport.authenticate("google"), (req, res) => {
  res.send("You reach the callback URL");
});

export default router;
