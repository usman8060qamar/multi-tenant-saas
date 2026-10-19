
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  logoutUser,
} from "../services/auth.service.js";

import { REFRESH_TOKEN_EXPIRES_IN_DAYS } from "../config/auth.js";

const refreshCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  path: "/api/auth",
});

export const logout = async (req, res) => {
  try {
    await logoutUser(req.cookies?.refreshToken);
    res.clearCookie("refreshToken", refreshCookieOptions());
    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch {
    return res.status(500).json({
      success: false,
      message: "Unable to log out. Please try again.",
    });
  }
};

export const register = async (req, res) => {
  try {
    const { tenantId, name, email, password } = req.body;

    if (!tenantId || !name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "tenantId, name, email and password are required",
      });
    }

    const user = await registerUser({
      tenantId,
      name,
      email,
      password,
    });

    return res.status(201).json({
      success: true,
      message: "User registered successfully",
      user,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};

export const login = async (req, res) => {
  try {
    const { tenantId, email, password } = req.body;

    if (!tenantId || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "tenantId, email and password are required",
      });
    }

    const { user, accessToken, refreshToken } = await loginUser({
      tenantId,
      email,
      password,
    });

    // Store refresh token in an HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      ...refreshCookieOptions(),
      maxAge: REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000,
    });

    // Return access token only in JSON
    return res.status(200).json({
      success: true,
      message: "Login successful",
      user,
      accessToken,
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message,
    });
  }
};

export const refresh = async (req, res) => {
  try {
    // Step 1: Read refresh token from cookie
    const oldRefreshToken = req.cookies?.refreshToken;

    if (!oldRefreshToken) {
      return res.status(401).json({
        success: false,
        message: "Refresh token is missing",
      });
    }

    // Step 2: Validate token and rotate it
    const { accessToken, refreshToken } =
      await refreshAccessToken(oldRefreshToken);

    // Step 3: Send new refresh token as a cookie
    res.cookie("refreshToken", refreshToken, {
      ...refreshCookieOptions(),
      maxAge:
        REFRESH_TOKEN_EXPIRES_IN_DAYS *
        24 *
        60 *
        60 *
        1000,
    });

    // Step 4: Return new access token
    return res.status(200).json({
      success: true,
      message: "Token refreshed successfully",
      accessToken,
    });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired refresh token",
    });
  }
};

