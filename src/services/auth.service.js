
import bcrypt from "bcrypt";
import pool from "../config/db.js";
import jwt from "jsonwebtoken";

import {
  JWT_SECRET,
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN_DAYS,
} from "../config/auth.js";

import {
  generateRefreshToken,
  hashRefreshToken,
  getTenantIdFromRefreshToken
} from "../utils/refreshToken.js";

export const loginUser = async ({ tenantId, email, password }) => {
  const client = await pool.connect();

  let user;
  let refreshToken;

  try {
    // Step 1: Start transaction
    await client.query("BEGIN");

    // Step 2: Set tenant context for RLS
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [tenantId]
    );

    // Step 3: Find user
    const result = await client.query(
      `SELECT id, tenant_id, name, email, password_hash, role
       FROM users
       WHERE tenant_id = $1 AND email = $2`,
      [tenantId, email]
    );

    if (result.rows.length === 0) {
      throw new Error("Invalid email or password");
    }

    user = result.rows[0];

    // Step 4: Verify password
    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      throw new Error("Invalid email or password");
    }

    // Step 5: Generate refresh token
    refreshToken = generateRefreshToken(user.tenant_id);

    // Step 6: Hash refresh token
    const tokenHash = hashRefreshToken(refreshToken);

    // Step 7: Calculate expiration date
    const expiresAt = new Date(
      Date.now() +
        REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000
    );

    // Step 8: Save token hash in PostgreSQL
    await client.query(
      `INSERT INTO refresh_tokens
       (user_id, tenant_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [user.id, user.tenant_id, tokenHash, expiresAt]
    );

    // Step 9: Commit transaction
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Rollback failed:", rollbackError);
    }

    throw error;
  } finally {
    client.release();
  }

  // Step 10: Generate access token
  const accessToken = jwt.sign(
    {
      userId: user.id,
      tenantId: user.tenant_id,
      role: user.role,
    },
    JWT_SECRET,
    {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    }
  );

  return {
    user: {
      id: user.id,
      tenantId: user.tenant_id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    accessToken,
    refreshToken,
  };
};

export const registerUser = async ({
  tenantId,
  name,
  email,
  password,
}) => {
  const role = "viewer";

  const existingUser = await pool.query(
    "SELECT id FROM users WHERE tenant_id = $1 AND email = $2",
    [tenantId, email]
  );


  if (existingUser.rows.length > 0) {
    throw new Error("User with this email already exists");
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const result = await pool.query(
    `INSERT INTO users
     (tenant_id, name, email, password_hash, role)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, tenant_id, name, email, role, created_at`,
    [tenantId, name, email, passwordHash, role]
  );

  return result.rows[0];
};

export const logoutUser = async (refreshToken) => {
  let tenantId;
  try {
    tenantId = getTenantIdFromRefreshToken(refreshToken);
  } catch {
    // Missing or malformed cookies are already logged out.
    return;
  }

  const tokenHash = hashRefreshToken(refreshToken);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [tenantId]
    );
    await client.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE token_hash = $1 AND tenant_id = $2
         AND revoked_at IS NULL`,
      [tokenHash, tenantId]
    );
    await client.query("COMMIT");
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Rollback failed:", rollbackError);
    }
    throw error;
  } finally {
    client.release();
  }
};

export const refreshAccessToken = async (oldRefreshToken) => {
  // Extract tenant ID from refresh token
  const tenantId = getTenantIdFromRefreshToken(oldRefreshToken);

  // Hash old refresh token
  const oldTokenHash = hashRefreshToken(oldRefreshToken);

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Set tenant context for RLS
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [tenantId]
    );

    // Find and lock existing refresh token
    const tokenResult = await client.query(
      `SELECT id, user_id, tenant_id
       FROM refresh_tokens
       WHERE token_hash = $1
         AND tenant_id = $2
         AND revoked_at IS NULL
         AND expires_at > NOW()
       FOR UPDATE`,
      [oldTokenHash, tenantId]
    );

    if (tokenResult.rows.length === 0) {
      throw new Error("Invalid or expired refresh token");
    }

    const storedToken = tokenResult.rows[0];

    // Find the associated user
    const userResult = await client.query(
      `SELECT id, tenant_id, name, email, role
       FROM users
       WHERE id = $1 AND tenant_id = $2`,
      [storedToken.user_id, tenantId]
    );

    if (userResult.rows.length === 0) {
      throw new Error("User not found");
    }

    const user = userResult.rows[0];

    // Generate new access token
    const accessToken = jwt.sign(
      {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
    );

    // Generate new refresh token
    const newRefreshToken = generateRefreshToken(user.tenant_id);
    const newTokenHash = hashRefreshToken(newRefreshToken);

    // Revoke old refresh token
    await client.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW()
       WHERE id = $1`,
      [storedToken.id]
    );

    // Store new refresh token hash
    await client.query(
      `INSERT INTO refresh_tokens
       (user_id, tenant_id, token_hash, expires_at)
       VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 day'))`,
      [
        user.id,
        user.tenant_id,
        newTokenHash,
        REFRESH_TOKEN_EXPIRES_IN_DAYS,
      ]
    );

    await client.query("COMMIT");

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Rollback failed:", rollbackError);
    }

    throw error;
  } finally {
    client.release();
  }
};

