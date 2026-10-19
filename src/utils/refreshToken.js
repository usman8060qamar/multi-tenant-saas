
import crypto from "node:crypto";

// Generate refresh token with tenant identifier
export const generateRefreshToken = (tenantId) => {
  const randomToken = crypto.randomBytes(64).toString("hex");

  return `${tenantId}.${randomToken}`;
};

// Hash the complete refresh token
export const hashRefreshToken = (token) => {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
};

// Extract tenant ID from refresh token
export const getTenantIdFromRefreshToken = (token) => {
  if (typeof token !== "string") {
    throw new Error("Invalid refresh token");
  }

  const parts = token.split(".");

  if (
    parts.length !== 2 ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parts[0]) ||
    !/^[0-9a-f]{128}$/i.test(parts[1])
  ) {
    throw new Error("Invalid refresh token");
  }

  return parts[0];
};
