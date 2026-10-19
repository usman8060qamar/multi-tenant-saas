// Set AUTH_ALLOWED_ORIGINS to comma-separated, exact frontend origins.
// Without it, only the API's own origin is trusted. Never trust forwarded
// headers here; deployments behind proxies should configure the allowlist.
export const requireTrustedOrigin = (req, res, next) => {
  const origin = req.get("Origin");
  const allowedOrigins = process.env.AUTH_ALLOWED_ORIGINS
    ? process.env.AUTH_ALLOWED_ORIGINS.split(",").map((value) => value.trim())
    : [`${req.protocol}://${req.get("host")}`];

  try {
    const parsed = new URL(origin);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.origin !== origin ||
      !allowedOrigins.includes(origin)
    ) {
      throw new Error("Untrusted origin");
    }
  } catch {
    return res.status(403).json({
      success: false,
      message: "A trusted Origin header is required",
    });
  }
  next();
};
