import express from "express";
import { register } from "../controllers/auth.controller.js";
import { login } from "../controllers/auth.controller.js";
import { createCompany } from "../controllers/company.controller.js";
import { authenticate } from "../middleware/auth.middleware.js";
import{ authorize } from "../middleware/role.middleware.js";

const router = express.Router();

//router.post("/register", register);
router.post("/login", login);
router.post("/register-company", createCompany);
router.get("/me", authenticate, (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Authenticated user",
    user: req.user,
  });
});
router.get(
  "/admin",
  authenticate,
  authorize("admin"),
  (req, res) => {
    return res.status(200).json({
      success: true,
      message: "Welcome to Admin Dashboard",
      user: req.user,
    });
  }
);

export default router;
