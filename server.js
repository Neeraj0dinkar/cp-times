const express = require("express");
const path = require("path");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// Render runs the app behind a trusted reverse proxy. Trust the first proxy
// so express-rate-limit can safely determine the client IP from X-Forwarded-For.
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_ANON_KEY;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const SITE = process.env.SITE_URL || "https://cptimes.in";


// ============================================================
// SUPABASE CLIENTS
// ============================================================

// Normal client
// Used for normal authentication operations.
const sb =
  URL && KEY
    ? createClient(URL, KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;


// Admin client
// IMPORTANT:
// This client uses the Supabase SERVICE ROLE KEY.
// NEVER expose this key to frontend/browser code.
const adminSb =
  URL && SERVICE_ROLE_KEY
    ? createClient(URL, SERVICE_ROLE_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false
        }
      })
    : null;


// ============================================================
// SECURITY / MIDDLEWARE
// ============================================================

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(compression());

app.use(
  express.json({
    limit: "2mb"
  })
);


// General API rate limit
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);


// Additional protection specifically for contributor OTP APIs
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many OTP requests. Please try again later."
  }
});


// ============================================================
// STATIC WEBSITE
// ============================================================

const PUB = path.join(__dirname, "public");

app.use(
  express.static(PUB, {
    etag: false,
    maxAge: 0,
    setHeaders: (res, filePath) => {
      if (filePath.endsWith("admin.html") || filePath.endsWith("contributor-register.html")) {
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
      }
    }
  })
);


// ============================================================
// HELPER FUNCTIONS
// ============================================================

const esc = (x) =>
  String(x ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
      })[c]
  );


const categorySlug = (x) =>
  String(x || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

// Build a safe URL slug for older articles whose database slug is blank/invalid.
const articleUrlKey = (article) => {
  const stored = String(article?.slug || "").trim();
  if (stored && stored !== "%20") return encodeURIComponent(stored);
  const generated = categorySlug(article?.title);
  return generated || `id-${article?.id || "unknown"}`;
};


const bodyHtml = (x) =>
  String(x || "")
    .split(/\n{2,}/)
    .map(
      (p) =>
        `<p>${esc(p).replace(/\n/g, "<br>")}</p>`
    )
    .join("");


async function published(articleKey) {
  if (!sb) return null;

  const requested = decodeURIComponent(
    String(articleKey || "")
  ).trim();

  if (!requested || requested === "%20") {
    return null;
  }

  console.log("ARTICLE LOOKUP REQUEST:", requested);

  // ------------------------------------------------
  // Build possible variations of the article key
  // ------------------------------------------------

  const possibleKeys = [
    requested
  ];

  // If URL starts with "-", also try without "-"
  if (requested.startsWith("-")) {
    possibleKeys.push(requested.substring(1));
  }

  // If numeric without "-", also try with "-"
  if (/^\d+$/.test(requested)) {
    possibleKeys.push(`-${requested}`);
  }

  console.log("TRYING ARTICLE KEYS:", possibleKeys);

  // ------------------------------------------------
  // 1. Try finding article by slug
  // ------------------------------------------------

  for (const key of possibleKeys) {

    const { data: bySlug, error: slugError } = await sb
      .from("articles")
      .select("*")
      .eq("slug", key)
      .maybeSingle();

    if (slugError) {
      console.error(
        "SLUG LOOKUP ERROR:",
        slugError.message
      );
    }

    if (bySlug) {

      console.log(
        "ARTICLE FOUND BY SLUG:",
        {
          id: bySlug.id,
          slug: bySlug.slug,
          status: bySlug.status
        }
      );

      if (
        String(bySlug.status || "")
          .trim()
          .toLowerCase() === "published"
      ) {
        return bySlug;
      }

      console.log(
        "ARTICLE FOUND BUT NOT PUBLISHED:",
        bySlug.status
      );
    }
  }

  // ------------------------------------------------
  // 2. Support ID URLs
  // ------------------------------------------------

  let articleId = null;

  const cleanRequested = requested.replace(/^-/, "");

  if (cleanRequested.startsWith("id-")) {
    articleId = cleanRequested.slice(3);
  } else if (/^\d+$/.test(cleanRequested)) {
    articleId = cleanRequested;
  }

  if (articleId) {

    const { data: byId, error: idError } = await sb
      .from("articles")
      .select("*")
      .eq("id", articleId)
      .maybeSingle();

    if (idError) {
      console.error(
        "ID LOOKUP ERROR:",
        idError.message
      );
    }

    if (byId) {

      console.log(
        "ARTICLE FOUND BY ID:",
        {
          id: byId.id,
          slug: byId.slug,
          status: byId.status
        }
      );

      if (
        String(byId.status || "")
          .trim()
          .toLowerCase() === "published"
      ) {
        return byId;
      }
    }
  }

  // ------------------------------------------------
  // 3. Fallback search through published articles
  // ------------------------------------------------

  const { data: candidates, error: candidatesError } =
    await sb
      .from("articles")
      .select("*")
      .eq("status", "published")
      .limit(1000);

  if (candidatesError) {
    console.error(
      "CANDIDATE LOOKUP ERROR:",
      candidatesError.message
    );

    return null;
  }

  const match = (candidates || []).find((article) => {

    const storedSlug = String(
      article.slug || ""
    ).trim();

    const generatedTitleSlug =
      categorySlug(article.title);

    return (
      possibleKeys.includes(storedSlug) ||
      possibleKeys.includes(
        categorySlug(storedSlug)
      ) ||
      possibleKeys.includes(
        generatedTitleSlug
      )
    );
  });

  if (match) {
    console.log(
      "ARTICLE FOUND BY FALLBACK:",
      {
        id: match.id,
        slug: match.slug
      }
    );

    return match;
  }

  console.log(
    "ARTICLE NOT FOUND AFTER ALL LOOKUPS:",
    requested
  );

  return null;
}

// ============================================================
// CONTRIBUTOR / REPORTER HELPERS
// ============================================================

async function getRegistration(email) {
  if (!adminSb) return null;

  const normalizedEmail = String(email || "")
    .trim()
    .toLowerCase();

  if (!normalizedEmail) return null;

  const { data, error } = await adminSb
    .from("contributor_registrations")
    .select("*")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (error) {
    console.error("Contributor registration lookup error:", error);
    return null;
  }

  return data || null;
}

async function requireAdmin(req, res) {
  if (!adminSb) {
    res.status(503).json({ success: false, error: "Authentication service is not configured." });
    return null;
  }

  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

  if (!token) {
    res.status(401).json({ success: false, error: "Authentication required." });
    return null;
  }

  const { data: userData, error: userError } = await adminSb.auth.getUser(token);
  if (userError || !userData?.user) {
    res.status(401).json({ success: false, error: "Your session is invalid or expired." });
    return null;
  }

  const { data: profile, error: profileError } = await adminSb
    .from("profiles")
    .select("id, full_name, role")
    .eq("id", userData.user.id)
    .maybeSingle();

  if (profileError || !profile || profile.role !== "admin") {
    res.status(403).json({ success: false, error: "Administrator access is required." });
    return null;
  }

  return { user: userData.user, profile };
}

// ============================================================
// REGISTRATION TOKEN
// ============================================================
//
// After successful OTP verification we create a short-lived
// registration token.
//
// This prevents somebody from directly calling the
// /set-password API without first verifying the OTP.
//
// Token validity = 10 minutes.
//
// ============================================================

const REGISTRATION_TOKEN_TTL = 10 * 60 * 1000;


function createRegistrationToken(email, userId) {
  if (!SERVICE_ROLE_KEY) {
    throw new Error(
      "SUPABASE_SERVICE_ROLE_KEY is not configured."
    );
  }

  const payload = {
    email,
    userId,
    purpose: "contributor-registration",
    exp: Date.now() + REGISTRATION_TOKEN_TTL
  };

  const payloadString = Buffer.from(
    JSON.stringify(payload)
  ).toString("base64url");

  const signature = crypto
    .createHmac(
      "sha256",
      SERVICE_ROLE_KEY
    )
    .update(payloadString)
    .digest("base64url");

  return `${payloadString}.${signature}`;
}


function verifyRegistrationToken(token) {
  try {
    if (!token || !SERVICE_ROLE_KEY) {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const payloadString = parts[0];
    const suppliedSignature = parts[1];

    const expectedSignature = crypto
      .createHmac(
        "sha256",
        SERVICE_ROLE_KEY
      )
      .update(payloadString)
      .digest("base64url");

    const suppliedBuffer = Buffer.from(
      suppliedSignature
    );

    const expectedBuffer = Buffer.from(
      expectedSignature
    );

    if (
      suppliedBuffer.length !==
      expectedBuffer.length
    ) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        suppliedBuffer,
        expectedBuffer
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(
        payloadString,
        "base64url"
      ).toString("utf8")
    );

    if (
      !payload.exp ||
      Date.now() > payload.exp
    ) {
      return null;
    }

    if (
      payload.purpose !==
      "contributor-registration"
    ) {
      return null;
    }

    return payload;
  } catch (error) {
    console.error(
      "Registration token verification error:",
      error
    );

    return null;
  }
}


// ============================================================
// API CONFIG
// ============================================================

app.get("/api/config", (req, res) => {
  res.json({
    supabaseUrl: URL || "",
    supabaseAnonKey: KEY || "",
    siteUrl: SITE
  });
});


// ============================================================
// HEALTH CHECK
// ============================================================

app.get("/api/health", async (req, res) => {
  if (!adminSb) {
    return res.status(503).json({
      ok: false,
      serviceRole: false
    });
  }

  try {
    const { error } = await adminSb
      .from("contributor_registrations")
      .select("email")
      .limit(1);

    if (error) {
      return res.status(500).json({
        ok: false,
        serviceRole: false,
        error: error.message
      });
    }

    return res.json({
      ok: true,
      serviceRole: true
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      serviceRole: false,
      error: error.message
    });
  }
});


// ============================================================
// CONTRIBUTOR REGISTRATION
// SELF-REGISTRATION + OTP + ADMIN APPROVAL
// ============================================================

app.post(
  "/api/contributor/request-otp",
  otpLimiter,
  async (req, res) => {
    try {
      if (!adminSb || !sb) {
        return res.status(503).json({ success: false, error: "Authentication service is not configured." });
      }

      const email = String(req.body.email || "").trim().toLowerCase();
      const fullName = String(req.body.fullName || "").trim();
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!fullName || fullName.length < 2 || fullName.length > 100) {
        return res.status(400).json({ success: false, error: "Please enter your full name." });
      }

      if (!emailPattern.test(email)) {
        return res.status(400).json({ success: false, error: "Please enter a valid email address." });
      }

      let registration = await getRegistration(email);

      if (registration?.status === "approved") {
        return res.status(409).json({ success: false, error: "This email is already approved as a CP Times reporter. Please use Newsroom Login." });
      }

      if (registration?.status === "suspended") {
        return res.status(403).json({ success: false, error: "This reporter account is suspended. Please contact the CP Times administrator." });
      }

      if (registration?.status === "rejected") {
        return res.status(403).json({ success: false, error: "This registration was rejected. Please contact the CP Times administrator." });
      }

      // Create the registration automatically. No Supabase table entry is required from the admin.
      if (!registration) {
        const { data, error } = await adminSb
          .from("contributor_registrations")
          .insert({
            email,
            full_name: fullName,
            status: "pending"
          })
          .select("*")
          .single();

        if (error) {
          console.error("Contributor registration create error:", error);
          return res.status(500).json({ success: false, error: "Unable to create your registration. Please try again." });
        }
        registration = data;
      } else if (registration.full_name !== fullName) {
        const { data, error } = await adminSb
          .from("contributor_registrations")
          .update({ full_name: fullName, updated_at: new Date().toISOString() })
          .eq("id", registration.id)
          .select("*")
          .single();
        if (!error && data) registration = data;
      }

      const { data: control, error: controlError } = await adminSb
        .from("otp_control")
        .select("email, attempts, locked_until, last_sent_at")
        .eq("email", email)
        .maybeSingle();

      if (controlError) {
        console.error("OTP control lookup error:", controlError);
        return res.status(500).json({ success: false, error: "Unable to check OTP status." });
      }

      let attempts = Number(control?.attempts || 0);
      if (control?.locked_until && new Date(control.locked_until) <= new Date()) {
        attempts = 0;
        await adminSb.from("otp_control").upsert({ email, attempts: 0, locked_until: null, updated_at: new Date().toISOString() }, { onConflict: "email" });
      }

      if (control?.locked_until && new Date(control.locked_until) > new Date()) {
        return res.status(429).json({
          success: false,
          locked: true,
          error: "Too many incorrect OTP attempts. OTP generation is locked for 24 hours.",
          lockedUntil: new Date(control.locked_until).toISOString()
        });
      }

      if (control?.last_sent_at) {
        const seconds = (Date.now() - new Date(control.last_sent_at).getTime()) / 1000;
        if (seconds < 60) {
          const remaining = Math.ceil(60 - seconds);
          return res.status(429).json({ success: false, error: `Please wait ${remaining} seconds before requesting another OTP.`, retryAfter: remaining });
        }
      }

      const { error: otpError } = await sb.auth.signInWithOtp({
        email,
        options: { shouldCreateUser: true }
      });

      if (otpError) {
        console.error("Supabase OTP error:", otpError);
        return res.status(500).json({ success: false, error: "Unable to send OTP. Please try again later." });
      }

      const now = new Date().toISOString();
      await adminSb.from("otp_control").upsert({ email, attempts, locked_until: null, last_sent_at: now, updated_at: now }, { onConflict: "email" });
      await adminSb.from("audit_log").insert({ action: "contributor_otp_requested", target_email: email, target_id: registration.id, details: { name: registration.full_name } });

      return res.json({ success: true, message: "OTP sent successfully. Please check your email." });
    } catch (error) {
      console.error("Request OTP unexpected error:", error);
      return res.status(500).json({ success: false, error: "Something went wrong while generating the OTP." });
    }
  }
);

app.post(
  "/api/contributor/verify-otp",
  otpLimiter,
  async (req, res) => {
    try {
      if (!adminSb || !sb) return res.status(503).json({ success: false, error: "Authentication service is not configured." });

      const email = String(req.body.email || "").trim().toLowerCase();
      const token = String(req.body.token || "").trim();
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailPattern.test(email)) return res.status(400).json({ success: false, error: "Please enter a valid email address." });
      if (!/^\d{6}$/.test(token)) return res.status(400).json({ success: false, error: "Please enter the 6-digit OTP." });

      const registration = await getRegistration(email);
      if (!registration) return res.status(404).json({ success: false, error: "Registration record not found. Please request a new OTP." });
      if (registration.status === "approved") return res.status(409).json({ success: false, error: "This email is already approved. Please use Newsroom Login." });
      if (registration.status === "suspended") return res.status(403).json({ success: false, error: "This reporter account is suspended." });
      if (registration.status === "rejected") return res.status(403).json({ success: false, error: "This registration was rejected. Please contact the administrator." });

      const { data: otpControl, error: otpReadError } = await adminSb.from("otp_control").select("*").eq("email", email).maybeSingle();
      if (otpReadError) return res.status(500).json({ success: false, error: "Unable to check OTP status." });

      if (otpControl?.locked_until && new Date(otpControl.locked_until) > new Date()) {
        return res.status(429).json({ success: false, locked: true, error: "Too many incorrect OTP attempts. Please try again after 24 hours.", lockedUntil: new Date(otpControl.locked_until).toISOString() });
      }

      const { data: verifyData, error: verifyError } = await sb.auth.verifyOtp({ email, token, type: "email" });
      if (verifyError || !verifyData?.user) {
        const newAttempts = Number(otpControl?.attempts || 0) + 1;
        if (newAttempts >= 3) {
          const lockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
          await adminSb.from("otp_control").upsert({ email, attempts: newAttempts, locked_until: lockedUntil, updated_at: new Date().toISOString() }, { onConflict: "email" });
          await adminSb.from("audit_log").insert({ action: "contributor_otp_locked", target_email: email, target_id: registration.id, details: { attempts: newAttempts, reason: "Three invalid OTP attempts" } });
          return res.status(429).json({ success: false, locked: true, error: "Three invalid OTP attempts. OTP generation is locked for 24 hours.", lockedUntil });
        }
        await adminSb.from("otp_control").upsert({ email, attempts: newAttempts, locked_until: null, updated_at: new Date().toISOString() }, { onConflict: "email" });
        await adminSb.from("audit_log").insert({ action: "contributor_invalid_otp", target_email: email, target_id: registration.id, details: { attempt: newAttempts } });
        return res.status(401).json({ success: false, error: "Invalid OTP.", attemptsRemaining: 3 - newAttempts });
      }

      const userId = verifyData.user.id;
      const now = new Date().toISOString();
      await adminSb.from("otp_control").upsert({ email, attempts: 0, locked_until: null, last_sent_at: null, updated_at: now }, { onConflict: "email" });

      const { error: registrationUpdateError } = await adminSb
        .from("contributor_registrations")
        .update({ auth_user_id: userId, email_verified_at: now, updated_at: now })
        .eq("id", registration.id);

      if (registrationUpdateError) {
        console.error("Registration verification update error:", registrationUpdateError);
        return res.status(500).json({ success: false, error: "Email verified, but the registration could not be updated." });
      }

      await adminSb.from("audit_log").insert({ action: "contributor_otp_verified", target_email: email, target_id: registration.id, details: { verified: true, authUserId: userId } });

      return res.json({
        success: true,
        verified: true,
        userId,
        registrationToken: createRegistrationToken(email, userId),
        message: "Email verified successfully. You can now set your password."
      });
    } catch (error) {
      console.error("Verify OTP error:", error);
      return res.status(500).json({ success: false, error: "Something went wrong while verifying the OTP." });
    }
  }
);

app.post(
  "/api/contributor/set-password",
  async (req, res) => {
    try {
      if (!adminSb) return res.status(503).json({ success: false, error: "Authentication service is not configured." });

      const registrationToken = String(req.body.registrationToken || "").trim();
      const password = String(req.body.password || "");
      const tokenData = verifyRegistrationToken(registrationToken);
      if (!tokenData) return res.status(401).json({ success: false, error: "Your email verification has expired. Please verify your email again." });

      if (password.length < 10) return res.status(400).json({ success: false, error: "Password must be at least 10 characters long." });
      if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
        return res.status(400).json({ success: false, error: "Password must contain at least one uppercase letter, lowercase letter, number and special character." });
      }

      const registration = await getRegistration(tokenData.email);
      if (!registration || registration.auth_user_id !== tokenData.userId) return res.status(403).json({ success: false, error: "Registration record could not be verified." });
      if (registration.status === "approved") return res.status(409).json({ success: false, error: "This registration is already approved. Please use Newsroom Login." });
      if (registration.status !== "pending") return res.status(403).json({ success: false, error: "This registration is not currently eligible for account creation." });
      if (!registration.email_verified_at) return res.status(403).json({ success: false, error: "Please verify your email before creating your password." });

      const { error: passwordError } = await adminSb.auth.admin.updateUserById(tokenData.userId, { password });
      if (passwordError) {
        console.error("Password update error:", passwordError);
        return res.status(500).json({ success: false, error: "Unable to set password. Please try again." });
      }

      const now = new Date().toISOString();
      await adminSb.from("contributor_registrations").update({ password_created_at: now, registered_at: registration.registered_at || now, updated_at: now }).eq("id", registration.id);
      await adminSb.from("audit_log").insert({ actor_id: tokenData.userId, action: "contributor_password_created", target_email: tokenData.email, target_id: registration.id, details: { passwordCreated: true } });

      return res.json({ success: true, message: "Registration completed successfully. Your account is now awaiting CP Times administrator approval." });
    } catch (error) {
      console.error("Set password error:", error);
      return res.status(500).json({ success: false, error: "Something went wrong while setting your password." });
    }
  }
);

// ============================================================
// ADMIN — ARTICLE MANAGEMENT
// ============================================================
// Article writes are performed server-side after requireAdmin() validation.
// This avoids relying on a browser Supabase session for RLS INSERT/UPDATE.

app.post("/api/admin/articles", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;

  try {
    const title = String(req.body.title || "").trim();
    const category = String(req.body.category || "").trim();
    const excerpt = String(req.body.excerpt || "").trim();
    const body = String(req.body.body || "").trim();
    const authorName = String(req.body.author_name || "CP Times Desk").trim() || "CP Times Desk";
    const status = String(req.body.status || "draft").trim();
    const featured = Boolean(req.body.featured);
    const requestedId = String(req.body.id || "").trim();
    const imageUrl = req.body.image_url ? String(req.body.image_url).trim() : null;

    if (!title || !body) {
      return res.status(400).json({ success: false, error: "Headline and Article Body are required." });
    }

    const allowedStatuses = ["draft", "review", "published", "archived"];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid article status." });
    }

    let slug = title
      .normalize("NFC")
      .trim()
      .replace(/[^\\p{L}\\p{N}\\s-]+/gu, " ")
      .replace(/\\s+/gu, "-")
      .replace(/^-+|-+$/gu, "")
      .slice(0, 120);

    if (!slug) slug = `story-${Date.now()}`;

    let existingBySlug = await adminSb.from("articles").select("id").eq("slug", slug).maybeSingle();
    if (existingBySlug.error) throw existingBySlug.error;
    if (existingBySlug.data && existingBySlug.data.id !== requestedId) {
      slug = `${slug}-${Date.now()}`;
    }

    const row = {
      title,
      slug,
      category,
      excerpt,
      body,
      author_name: authorName,
      status,
      featured,
      updated_by: auth.user.id
    };

    if (imageUrl) row.image_url = imageUrl;
    if (status === "published") row.published_at = new Date().toISOString();

    let result;
    if (requestedId) {
      result = await adminSb.from("articles").update(row).eq("id", requestedId).select().single();
    } else {
      result = await adminSb.from("articles").insert({ ...row, created_by: auth.user.id }).select().single();
    }

    if (result.error) throw result.error;

    return res.json({ success: true, article: result.data });
  } catch (error) {
    console.error("Admin article save error:", error);
    return res.status(500).json({ success: false, error: error.message || "Unable to save article." });
  }
});

// ============================================================
// ADMIN — REPORTER APPROVAL WORKFLOW
// ============================================================

app.get("/api/admin/contributors", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  try {
    const status = String(req.query.status || "").trim();
    let query = adminSb.from("contributor_registrations").select("*").order("created_at", { ascending: false });
    if (status) query = query.eq("status", status);
    const { data, error } = await query;
    if (error) throw error;
    return res.json({ success: true, contributors: data || [] });
  } catch (error) {
    console.error("Admin contributor list error:", error);
    return res.status(500).json({ success: false, error: "Unable to load reporter registrations." });
  }
});

app.post("/api/admin/contributors/:id/approve", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  try {
    const id = String(req.params.id || "");
    const { data: registration, error: readError } = await adminSb.from("contributor_registrations").select("*").eq("id", id).maybeSingle();
    if (readError) throw readError;
    if (!registration) return res.status(404).json({ success: false, error: "Reporter registration not found." });
    if (registration.status === "approved") return res.json({ success: true, message: "Reporter is already approved." });
    if (!registration.auth_user_id || !registration.email_verified_at || !registration.password_created_at) {
      return res.status(400).json({ success: false, error: "The reporter must complete OTP verification and create a password before approval." });
    }
    if (!["pending"].includes(registration.status)) return res.status(400).json({ success: false, error: `Registration is currently ${registration.status}.` });

    const { data: existingProfile, error: profileReadError } = await adminSb.from("profiles").select("id, role").eq("id", registration.auth_user_id).maybeSingle();
    if (profileReadError) throw profileReadError;
    if (!existingProfile) {
      const { error: profileInsertError } = await adminSb.from("profiles").insert({ id: registration.auth_user_id, full_name: registration.full_name, role: "journalist" });
      if (profileInsertError) throw profileInsertError;
    } else {
      const { error: profileUpdateError } = await adminSb.from("profiles").update({ full_name: registration.full_name }).eq("id", registration.auth_user_id);
      if (profileUpdateError) throw profileUpdateError;
    }

    const now = new Date().toISOString();
    const { error: updateError } = await adminSb.from("contributor_registrations").update({ status: "approved", approved_at: now, approved_by: auth.user.id, updated_at: now }).eq("id", id);
    if (updateError) throw updateError;
    await adminSb.from("audit_log").insert({ actor_id: auth.user.id, action: "contributor_approved", target_email: registration.email, target_id: id, details: { authUserId: registration.auth_user_id } });
    return res.json({ success: true, message: "Reporter approved successfully." });
  } catch (error) {
    console.error("Admin contributor approval error:", error);
    return res.status(500).json({ success: false, error: "Unable to approve reporter." });
  }
});

app.post("/api/admin/contributors/:id/reject", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  try {
    const id = String(req.params.id || "");
    const reason = String(req.body.reason || "").trim().slice(0, 500);
    const { data: registration, error: readError } = await adminSb.from("contributor_registrations").select("email,status").eq("id", id).maybeSingle();
    if (readError) throw readError;
    if (!registration) return res.status(404).json({ success: false, error: "Reporter registration not found." });
    if (registration.status === "approved") return res.status(400).json({ success: false, error: "An approved reporter cannot be rejected from this screen." });
    const now = new Date().toISOString();
    const { error } = await adminSb.from("contributor_registrations").update({ status: "rejected", rejection_reason: reason || null, updated_at: now }).eq("id", id);
    if (error) throw error;
    await adminSb.from("audit_log").insert({ actor_id: auth.user.id, action: "contributor_rejected", target_email: registration.email, target_id: id, details: { reason: reason || null } });
    return res.json({ success: true, message: "Reporter registration rejected." });
  } catch (error) {
    console.error("Admin contributor rejection error:", error);
    return res.status(500).json({ success: false, error: "Unable to reject reporter." });
  }
});

app.post("/api/admin/contributors/:id/restore", async (req, res) => {
  const auth = await requireAdmin(req, res);
  if (!auth) return;
  try {
    const id = String(req.params.id || "");
    const { data: registration, error: readError } = await adminSb.from("contributor_registrations").select("*").eq("id", id).maybeSingle();
    if (readError) throw readError;
    if (!registration) return res.status(404).json({ success: false, error: "Reporter registration not found." });
    const now = new Date().toISOString();
    const { error } = await adminSb.from("contributor_registrations").update({ status: "pending", rejection_reason: null, updated_at: now }).eq("id", id);
    if (error) throw error;
    await adminSb.from("audit_log").insert({ actor_id: auth.user.id, action: "contributor_restored_to_pending", target_email: registration.email, target_id: id });
    return res.json({ success: true, message: "Reporter registration moved back to pending." });
  } catch (error) {
    console.error("Admin contributor restore error:", error);
    return res.status(500).json({ success: false, error: "Unable to restore reporter registration." });
  }
});

// ============================================================
// EXISTING CP TIMES APIs
// ============================================================


// ------------------------------------------------------------
// ARTICLES
// ------------------------------------------------------------

app.get(
  "/api/articles",
  async (req, res) => {

    if (!sb) {
      return res.status(503).json({
        error:
          "Supabase not configured"
      });
    }

    let query = sb
      .from("articles")
      .select(
        "id,title,slug,category,excerpt,image_url,author_name,published_at,featured"
      )
      .eq("status", "published")
      .order(
        "published_at",
        {
          ascending: false
        }
      )
      .limit(
        Math.min(
          Number(req.query.limit) || 12,
          50
        )
      );


    if (req.query.category) {
      query = query.eq(
        "category",
        req.query.category
      );
    }


    const {
      data,
      error
    } = await query;


    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }


    const result = (data || []).map(article => ({
      ...article,
      slug: String(article.slug || "").trim() || null,
      url_key: articleUrlKey(article)
    }));

    res.json(result);
  }
);


// ------------------------------------------------------------
// SINGLE ARTICLE
// ------------------------------------------------------------

app.get(
  "/api/articles/:slug",
  async (req, res) => {

    const article =
      await published(
        req.params.slug
      );


    if (!article) {
      return res.status(404).json({
        error: "Not found"
      });
    }


    res.json(article);
  }
);


// ------------------------------------------------------------
// BREAKING NEWS
// ------------------------------------------------------------

app.get(
  "/api/breaking",
  async (req, res) => {

    if (!sb) {
      return res.status(503).json({
        error:
          "Supabase not configured"
      });
    }


    const {
      data,
      error
    } = await sb
      .from("breaking_news")
      .select("*")
      .eq("active", true)
      .order(
        "priority",
        {
          ascending: false
        }
      )
      .order(
        "created_at",
        {
          ascending: false
        }
      )
      .limit(10);


    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }


    res.json(data || []);
  }
);


// ------------------------------------------------------------
// SITE SETTINGS
// ------------------------------------------------------------

app.get(
  "/api/settings",
  async (req, res) => {

    if (!sb) {
      return res.status(503).json({
        error:
          "Supabase not configured"
      });
    }


    const {
      data,
      error
    } = await sb
      .from("site_settings")
      .select("key,value");


    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }


    const settings = {};


    (data || []).forEach(
      (item) => {
        settings[item.key] =
          item.value;
      }
    );


    res.json(settings);
  }
);


// ------------------------------------------------------------
// FUN FACTS
// ------------------------------------------------------------

app.get(
  "/api/fun-facts",
  async (req, res) => {

    if (!sb) {
      return res.status(503).json({
        error:
          "Supabase not configured"
      });
    }


    let query = sb
      .from("fun_facts")
      .select(
        "id,title,category,fact,source,language"
      )
      .eq("status", "published")
      .order(
        "display_order",
        {
          ascending: true
        }
      )
      .order(
        "created_at",
        {
          ascending: false
        }
      )
      .limit(
        Math.min(
          Number(req.query.limit) || 8,
          20
        )
      );


    if (req.query.language) {
      query = query.eq(
        "language",
        req.query.language
      );
    }


    const {
      data,
      error
    } = await query;


    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }


    res.set(
      "Cache-Control",
      "public, max-age=300"
    );


    res.json(data || []);
  }
);


// ------------------------------------------------------------
// HOROSCOPE
// ------------------------------------------------------------

app.get(
  "/api/horoscope",
  async (req, res) => {

    if (!sb) {
      return res.status(503).json({
        error:
          "Supabase not configured"
      });
    }


    const month =
      /^\d{4}-\d{2}$/.test(
        req.query.month || ""
      )
        ? `${req.query.month}-01`
        : new Date()
            .toISOString()
            .slice(0, 7) +
          "-01";


    const {
      data,
      error
    } = await sb
      .from("monthly_horoscopes")
      .select(
        "id,month_key,sign,content,language"
      )
      .eq(
        "month_key",
        month
      )
      .eq(
        "status",
        "published"
      )
      .order(
        "sign",
        {
          ascending: true
        }
      );


    if (error) {
      return res.status(500).json({
        error: error.message
      });
    }


    res.set(
      "Cache-Control",
      "public, max-age=3600"
    );


    res.json(data || []);
  }
);


// ============================================================
// SITEMAP
// ============================================================

app.get(
  "/sitemap.xml",
  async (req, res) => {

    let urls = [
      SITE,
      "india",
      "uttar-pradesh",
      "world",
      "business",
      "technology",
      "sports",
      "entertainment",
      "politics"
    ].map(
      (item) =>
        item === SITE
          ? SITE
          : `${SITE}/category/${item}`
    );


    if (sb) {

      const {
        data
      } = await sb
        .from("articles")
        .select(
          "id,slug,category"
        )
        .eq(
          "status",
          "published"
        )
        .limit(5000);


      (data || []).forEach(
        (article) => {

          urls.push(
            `${SITE}/${categorySlug(
              article.category
            )}/${articleUrlKey(article)}`
          );

        }
      );
    }


    const xml = `
<?xml version="1.0" encoding="UTF-8"?>
<urlset
  xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
>
${urls
  .map(
    (url) =>
      `<url><loc>${esc(
        url
      )}</loc></url>`
  )
  .join("")}
</urlset>
`;


    res
      .type("application/xml")
      .send(xml);
  }
);


// ============================================================
// SEO ARTICLE PAGE
// ============================================================

app.get(
  /^\/(india|uttar-pradesh|world|business|technology|sports|entertainment|politics)\/([^/]+)$/,
  async (req, res) => {

    // The regex has two unnamed capture groups: category (params[0]) and article key (params[1]).
    // Using params[2] makes every SEO article lookup receive undefined and return 404.
    const category = String(req.params[0] || "").trim();
    const articleKey = String(req.params[1] || "").trim();

    console.log("=================================");
    console.log("ARTICLE PAGE REQUEST");
    console.log("Category:", category);
    console.log("Article Key:", articleKey);

    const article = await published(articleKey);

    console.log(
      "ARTICLE RESULT:",
      article
        ? {
            id: article.id,
            slug: article.slug,
            status: article.status,
            title: article.title
          }
        : null
    );

    console.log("=================================");


    if (!article) {
      return res
        .status(404)
        .send(
          "<h1>Article not found</h1>"
        );
    }


    const canonical =
      `${SITE}/${categorySlug(
        article.category
      )}/${articleUrlKey(article)}`;


    const ld = {
      "@context":
        "https://schema.org",

      "@type":
        "NewsArticle",

      headline:
        article.title,

      description:
        article.excerpt ||
        article.title,

      datePublished:
        article.published_at,

      dateModified:
        article.updated_at ||
        article.published_at,

      author: {
        "@type": "Person",
        name:
          article.author_name ||
          "CP Times Desk"
      },

      publisher: {
        "@type":
          "Organization",

        name:
          "CP Times",

        url: SITE
      }
    };


    res.send(`
<!doctype html>

<html lang="hi-IN">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1"
/>

<title>
${esc(article.title)} | CP Times
</title>

<meta
  name="description"
  content="${esc(
    article.excerpt ||
      article.title
  )}"
/>

<link
  rel="canonical"
  href="${esc(canonical)}"
/>

<meta
  property="og:title"
  content="${esc(
    article.title
  )}"
/>

<meta
  property="og:description"
  content="${esc(
    article.excerpt ||
      article.title
  )}"
/>

${
  article.image_url
    ? `
<meta
  property="og:image"
  content="${esc(
    article.image_url
  )}"
/>
`
    : ""
}

<link
  rel="stylesheet"
  href="/styles.css"
/>

<script type="application/ld+json">
${JSON.stringify(ld).replace(
  /</g,
  "\\u003c"
)}
</script>

</head>

<body>

<header class="mast">

<a href="/">
<img
  src="/cv-news-logo.jpeg"
  alt="CP Times"
/>
</a>

<a href="/">
Home
</a>

</header>


<main class="article">

<span class="tag">
${esc(article.category)}
</span>

<h1>
${esc(article.title)}
</h1>

<p class="lead">
${esc(
  article.excerpt || ""
)}
</p>

<div class="meta">

By
${esc(
  article.author_name ||
    "CP Times Desk"
)}

•

${new Date(
  article.published_at
).toLocaleString(
  "en-IN"
)}

</div>


${
  article.image_url
    ? `
<img
  class="article-image"
  src="${esc(
    article.image_url
  )}"
  alt="${esc(
    article.title
  )}"
/>
`
    : ""
}


<div class="article-body">

${bodyHtml(
  article.body
)}

</div>

</main>

</body>

</html>
`);
  }
);


// ============================================================
// WEBSITE ROUTES
// ============================================================

app.get(
  "/category/:category",
  (req, res) => {
    res.sendFile(
      path.join(
        PUB,
        "category.html"
      )
    );
  }
);


app.get(
  "/admin",
  (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    res.sendFile(path.join(PUB, "admin.html"), { cacheControl: false });
  }
);


app.get(
  "/login",
  (req, res) => {
    res.sendFile(
      path.join(
        PUB,
        "login.html"
      )
    );
  }
);



app.get(
  "/reporter-register",
  (req, res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");
    res.sendFile(path.join(PUB, "contributor-register.html"), { cacheControl: false });
  }
);

// ============================================================
// DEFAULT WEBSITE ROUTE
// ============================================================

app.use(
  (req, res) => {
    res.sendFile(
      path.join(
        PUB,
        "index.html"
      )
    );
  }
);


// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `CP Times production server running on port ${PORT}`
    );
  }
);
