
import bcrypt from "bcrypt";
import pool from "../config/db.js";

export const registerCompany = async ({
  companyName,
  name,
  email,
  password,
}) => {
  const client = await pool.connect();

  try {
    // Step 1: Start transaction
    await client.query("BEGIN");

    // Step 2: Create the company
    const tenantResult = await client.query(
      `INSERT INTO tenants (name)
       VALUES ($1)
       RETURNING id, name`,
      [companyName]
    );

    const tenant = tenantResult.rows[0];

    // Step 3: Set tenant context for RLS
    await client.query(
      "SELECT set_config('app.current_tenant', $1, true)",
      [tenant.id]
    );

    // Step 4: Hash admin password
    const passwordHash = await bcrypt.hash(password, 10);

    // Step 5: Create the first admin
    const userResult = await client.query(
      `INSERT INTO users
       (tenant_id, name, email, password_hash, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, tenant_id, name, email, role`,
      [tenant.id, name, email, passwordHash, "admin"]
    );

    const user = userResult.rows[0];

    // Step 6: Save both operations
    await client.query("COMMIT");

    return { tenant, user };
  } catch (error) {
    // Undo changes if anything fails
    try {
      await client.query("ROLLBACK");
    } catch (rollbackError) {
      console.error("Rollback failed:", rollbackError);
    }

    throw error;
  } finally {
    // Return connection to pool
    client.release();
  }
};
