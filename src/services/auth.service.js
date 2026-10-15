import bcrypt from "bcrypt";
import pool from "../config/db.js";
import jwt from "jsonwebtoken";
import {
  JWT_SECRET,
  ACCESS_TOKEN_EXPIRES_IN,
} from "../config/auth.js";

// export const loginUser = async ({ tenantId, email, password }) => {
//   const result = await pool.query(
//     `SELECT id, tenant_id, name, email, password_hash, role
//      FROM users
//      WHERE tenant_id = $1 AND email = $2`,
//     [tenantId, email]
//   );

//   if (result.rows.length === 0) {
//     throw new Error("Invalid email or password");
//   }

//   const user = result.rows[0];

//   const passwordMatches = await bcrypt.compare(
//     password,
//     user.password_hash
//   );

//   if (!passwordMatches) {
//     throw new Error("Invalid email or password");
//   }

//   const accessToken = jwt.sign(
//     {
//       userId: user.id,
//       tenantId: user.tenant_id,
//       role: user.role,
//     },
//     JWT_SECRET,
//     {
//       expiresIn: ACCESS_TOKEN_EXPIRES_IN,
//     }
//   );

//   return {
//     user: {
//       id: user.id,
//       tenantId: user.tenant_id,
//       name: user.name,
//       email: user.email,
//       role: user.role,
//     },
//     accessToken,
//   };
// };

export const loginUser = async ({ tenantId, email, password }) => {
  const client = await pool.connect();

  let user;

  try {
    // Step 1: Start transaction
    await client.query("BEGIN");

    // Step 2: Tell PostgreSQL which tenant is logging in
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [tenantId]
    );

    // Step 3: Find user (RLS automatically applies)
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

    // Step 5: Finish transaction
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    // Always return connection to the pool
    client.release();
  }

  // Step 6: Generate JWT after successful authentication
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
  };
};

export const registerUser = async ({
  tenantId,
  name,
  email,
  password,
}) => {
  const role="viewer";
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