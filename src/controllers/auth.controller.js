import {
  registerUser,
  loginUser,
} from "../services/auth.service.js";

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

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      user,
    });
  } catch (error) {
    res.status(400).json({
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

    const result = await loginUser({
      tenantId,
      email,
      password,
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      ...result,
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: error.message,
    });
  }
};