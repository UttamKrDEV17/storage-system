import bcrypt from "bcrypt";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
import User from "../models/user.model.js";
import Folder from "../models/folder.model.js";
import Session from "../models/session.model.js";
import crypto from "crypto";
import { sendEmail } from "../services/emailService.js";

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // --- 3. Account Status Checks ---
    if (user.accountStatus === "pending_email_verification") {
      return res
        .status(403)
        .json({
          message: "Please verify your email address to activate your account.",
        });
    }
    if (user.accountStatus === "suspended") {
      return res
        .status(403)
        .json({
          message:
            "Your account has been suspended. Please contact support." +
            (user.suspensionReason ? ` Reason: ${user.suspensionReason}` : ""),
        });
    }
    if (user.accountStatus === "locked") {
      return res
        .status(403)
        .json({
          message:
            "Your account is locked. Please try again later or reset your password.",
        });
    }
    if (user.accountStatus === "deactivated") {
      return res
        .status(403)
        .json({
          message:
            "Your account is deactivated. Please contact support to reactivate.",
        });
    }
    // If accountStatus is 'active', proceed. Other statuses like 'is_active: false' are covered by accountStatus.

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    user.lastLogin = new Date();
    user.lastLoginIp = req.ip;
    user.lastLoginUserAgent = req.headers["user-agent"];

    await user.save();

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const expiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || "30d";
    const expiresAt = new Date(
      Date.now() +
        (expiresIn.endsWith("d")
          ? parseInt(expiresIn) * 24 * 60 * 60 * 1000
          : 30 * 24 * 60 * 60 * 1000) // fallback 30d
    );

    const hashedToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    await Session.create({
      user: user._id,
      token: hashedToken,
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.status(200).json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        profile: user.profile,
        addresses: user.addresses,
        role: user.role,
        accountStatus: user.accountStatus, // New: Include detailed account status
        isEmailVerified: user.isEmailVerified, // New: Include email verification status
        lastLogin: user.lastLogin,
        lastLoginIp: user.lastLoginIp, // New: Include last login IP
        lastLoginUserAgent: user.lastLoginUserAgent, // New: Include last login User Agent
        storageUsed: user.storageUsed, // New: Include storage info
        storageQuota: user.storageQuota, // New: Include storage info
        rootFolder: user.rootFolder, // New: Include root folder ID
        // Do NOT send sensitive info like password, reset tokens, 2FA secrets
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const register = async (req, res) => {
  try {
    const {
      email,
      password,
      username,
      profile = {},
      addresses = [],
      role = "user",
    } = req.body;

    // Required fields check
    if (!email || !password || !username) {
      return res
        .status(400)
        .json({ message: "Email, password, and username are required." });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "Password must be at least 8 character long." });
    }

    // Check for existing user (by email or username)
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(409).json({ message: "Email already registered." });
      }
      if (existingUser.username === username) {
        return res.status(409).json({ message: "Username already taken." });
      }

      return res
        .status(409)
        .json({ message: "Username or Email already exists." });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const passwordChangedAt = new Date();

    // Capture IP address and User Agent
    const registeredIp = req.ip;
    const userAgent = req.headers["user-agent"] || "Unknown";

    // Create user with all fields
    const newUser = await User.create({
      email,
      password: hashedPassword,
      username,
      profile: {
        firstname: profile.firstname,
        lastname: profile.lastname,
        birthdate: profile.birthdate,
        gender: profile.gender,
        phone: profile.phone,
        avatar: profile.avatar,
        bio: profile.bio,
      },
      addresses,
      role,
      accountStatus: "pending_email_verification",
      lastLogin: new Date(),
      lastLoginIp: registeredIp,
      lastLoginUserAgent: userAgent,
      passwordChangedAt: new Date(),
      storageUsed: 0,
      storageQuota: undefined,
    });

    const rootFolder = await Folder.create({
      name: `${username}'s Drive`,
      owner: newUser._id,
      parentFolder: null,
      isRoot: true,
      visibility: "private",
      sharedWith: [{user: newUser._id,
        permission: 'manage',
      }]
    });

    newUser.rootFolder = rootFolder._id;

    await newUser.save();

    // Generate tokens
    const accessToken = generateAccessToken(newUser);
    const refreshToken = generateRefreshToken(newUser);

    // Calculate refresh token expiry date
    const expiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || "30d";
    const expiresAt = new Date(
      Date.now() +
        (expiresIn.endsWith("d")
          ? parseInt(expiresIn) * 24 * 60 * 60 * 1000
          : 30 * 24 * 60 * 60 * 1000) // fallback 30d
    );

    const hashedToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    // Create session
    await Session.create({
      user: newUser._id,
      token: hashedToken,
      expiresAt,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    res.status(201).json({
      accessToken,
      refreshToken,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        profile: newUser.profile,
        addresses: newUser.addresses,
        role: newUser.role,
        accountStatus: newUser.accountStatus, // Use the new status field
        lastLogin: newUser.lastLogin,
        rootFolder: newUser.rootFolder, // Include root folder ID
        storageUsed: newUser.storageUsed, // Include storage info
        storageQuota: newUser.storageQuota,
      },
    });
  } catch (error) {
    console.error("Register error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required." });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");
    const session = await Session.findOne({ token: hashedToken });

    if (!session || session.expiresAt < new Date()) {
      return res
        .status(401)
        .json({ message: "Invalid or expired refresh token." });
    }

    const user = await User.findById(session.user);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const accessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    // Update session with new refresh token
    session.token = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");
    const expiresIn = process.env.REFRESH_TOKEN_EXPIRES_IN || "30d";
    const expiresAt = new Date(
      Date.now() +
        (expiresIn.endsWith("d")
          ? parseInt(expiresIn) * 24 * 60 * 60 * 1000
          : 30 * 24 * 60 * 60 * 1000) // fallback 30d
    );
    session.expiresAt = expiresAt;
    session.ipAddress = req.ip;
    await session.save();

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error("Refresh token error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required." });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const session = await Session.findOneAndUpdate(
      { token: hashedToken, isRevoked: false },
      { $set: { isRevoked: true } },
      { new: true }
    );

    if (!session) {
      return res
        .status(404)
        .json({ message: "Session not found or already invalidated." });
    }

    await User.findByIdAndUpdate(session.user, {
      $set: { lastLogout: new Date() },
    });

    res.status(200).json({ message: "Logged out successfully." });
  } catch (error) {
    console.error("Logout error:", error.message);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const logoutAll = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required." });
    }

    const result = await Session.updateMany({ user: userId, isRevoked: false });
  } catch (error) {
    console.error("Logout all error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(200)
        .json({
          message: "If this email is registered, a reset link will be sent.",
        });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    const expires = new Date(Date.now() + 3600000); // 1 hour

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = expires;
    await user.save();

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}&email=${user.email}`;
    try {
      await sendEmail({
        to: user.email,
        subject: "password reset Request",
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password. The link will expire in 1 hour.</p>`,
      });
      res
        .status(200)
        .json({
          message: "If this email is registered, a reset link has been sent.",
        });
    } catch (emailError) {
      console.error("Email sending error:", emailError);
      return res
        .status(500)
        .json({
          message: "Failed to send reset email. Please try again later.",
        });
    }
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res
        .status(400)
        .json({ message: "Token and new password are required." });
    }

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    res.status(200).json({ message: "Password has been reset successfully." });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const sendVerificationEmail = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required." });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(200)
        .json({
          message:
            "if the email is registered, a verification email has been sent.",
        });
    }

    if (user.isEmailVerified) {
      return res
        .status(200)
        .json({ message: "This email is already verified." });
    }

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationExpires = Date.now() + 3600000; // 1 hour from now (in milliseconds)

    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = verificationExpires;
    await user.save();

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

    const emailSubject = "Verify Your Email Address";
    const emailHtml = `
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <title>Email Verification</title>
            <style>
                body {
                font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                background-color: #f4f4f7;
                margin: 0;
                padding: 0;
                }
                .container {
                max-width: 600px;
                margin: 40px auto;
                background-color: #ffffff;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
                }
                .header {
                background-color: #4f46e5;
                color: #ffffff;
                text-align: center;
                padding: 20px;
                }
                .header h1 {
                margin: 0;
                font-size: 22px;
                }
                .content {
                padding: 30px;
                color: #333333;
                line-height: 1.6;
                }
                .content a.verify-link {
                display: inline-block;
                margin-top: 20px;
                padding: 12px 24px;
                background-color: #4f46e5;
                color: #ffffff;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                }
                .footer {
                background-color: #f4f4f7;
                text-align: center;
                font-size: 12px;
                color: #888888;
                padding: 20px;
                }
            </style>
            </head>
            <body>
            <div class="container">
                <div class="header">
                <h1>Welcome to Our Service</h1>
                </div>
                <div class="content">
                <p>Hello <strong>${user.username || user.email}</strong>,</p>
                <p>Thank you for registering with us!</p>
                <p>Please click the button below to verify your email address:</p>
                <p>
                    <a href="${verificationUrl}" class="verify-link">Verify Email</a>
                </p>
                <p>This link will expire in <strong>1 hour</strong>.</p>
                <p>If you did not register for an account, please ignore this email.</p>
                <p>Regards,<br>Your Application Team</p>
                </div>
                <div class="footer">
                &copy; ${new Date().getFullYear()} Your Application. All rights reserved.
                </div>
            </div>
            </body>
            </html>
        `;

    await sendEmail({
      to: user.email,
      subject: emailSubject,
      html: emailHtml,
    });

    res.status(200).json({ message: "Verification email sent successfully." });
  } catch (error) {
    console.error("Error sending verification email", error.message);
    res
      .status(500)
      .json({
        message: "Failed to send verification email.",
        error: error.message,
      });
  }
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: "Token is required." });
  }

  try {
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "User not found." });
    }

    if (user.isEmailVerified) {
      return res.status(200).json({ message: "Email is already verified." });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;

    await user.save();

    res.status(200).json({ message: "Email successfully verified." });
  } catch (error) {
    console.error("Verify Email: An unexpected error occurred:", error);
    res
      .status(500)
      .json({ message: "Failed to verify email.", error: error.message });
  }
};

export {
  login,
  register,
  refresh,
  logout,
  logoutAll,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyEmail,
};
