
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config/auth.js";
import pool from "../config/db.js";

export const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Access token required",
    });
  }

  const token = authHeader.split(" ")[1];

  let decoded;

  // Step 1: Verify JWT
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
    });
  }

  let client;

  try {
    // Step 2: Get database connection
    client = await pool.connect();

    // Step 3: Start transaction
    await client.query("BEGIN");

    // Step 4: Set tenant context for RLS
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [decoded.tenantId]
    );

    // Step 5: Fetch user with RLS applied
    const result = await client.query(
      `SELECT id, tenant_id, role
       FROM users
       WHERE id = $1 AND tenant_id = $2`,
      [decoded.userId, decoded.tenantId]
    );

    if (result.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(401).json({
        success: false,
        message: "User no longer exists or has no tenant access",
      });
    }

    const user = result.rows[0];

    // Step 6: Finish transaction
    await client.query("COMMIT");

    req.user = {
      userId: user.id,
      tenantId: user.tenant_id,
      role: user.role,
    };

    next();
  } catch (error) {
    if (client) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        console.error("Rollback failed:", rollbackError);
      }
    }

    console.error("Authentication database error:", error);

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  } finally {
    if (client) {
      client.release();
    }
  }
};
