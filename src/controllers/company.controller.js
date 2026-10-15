
import { registerCompany } from "../services/company.service.js";

export const createCompany = async (req, res) => {
  try {
    const { companyName, name, email, password } = req.body;

    if (!companyName || !name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const result = await registerCompany({
      companyName,
      name,
      email,
      password,
    });

    return res.status(201).json({
      success: true,
      message: "Company registered successfully",
      ...result,
    });
  } catch (error) {
    console.error("Company registration failed:", error);

    return res.status(500).json({
      success: false,
      message: "Company registration failed",
    });
  }
};
