const express = require("express");
const path = require("path");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

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
    maxAge: "1h"
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
    .replace(/\s+/g, "-");


const bodyHtml = (x) =>
  String(x || "")
    .split(/\n{2,}/)
    .map(
      (p) =>
        `<p>${esc(p).replace(/\n/g, "<br>")}</p>`
    )
    .join("");


async function published(slug) {
  if (!sb) return null;

  const { data } = await sb
    .from("articles")
    .select("*")
    .eq("slug", slug)
    .eq("status", "published")
    .maybeSingle();

  return data || null;
}


// ============================================================
// CONTRIBUTOR HELPERS
// ============================================================

async function getContributor(email) {
  if (!adminSb) return null;

  const normalizedEmail = String(email || "")
    .trim()
    .toLowerCase();

  if (!normalizedEmail) return null;

  const { data, error } = await adminSb
    .from("contributor_allowlist")
    .select("*")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (error) {
    console.error(
      "Contributor allowlist error:",
      error
    );

    return null;
  }

  return data || null;
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
      .from("contributor_allowlist")
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
// STEP 1 — REQUEST OTP
// ============================================================

app.post(
  "/api/contributor/request-otp",
  otpLimiter,
  async (req, res) => {

    try {

      if (!adminSb || !sb) {
        return res.status(503).json({
          success: false,
          error:
            "Authentication service is not configured."
        });
      }


      // --------------------------------------------------------
      // Read email
      // --------------------------------------------------------

      const email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();


      // --------------------------------------------------------
      // Validate email format
      // --------------------------------------------------------

      const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailPattern.test(email)) {
        return res.status(400).json({
          success: false,
          error:
            "Please enter a valid email address."
        });
      }


      // --------------------------------------------------------
      // Check contributor allowlist
      // --------------------------------------------------------

      const contributor =
        await getContributor(email);

      if (!contributor) {
        return res.status(403).json({
          success: false,
          error:
            "This email address is not authorized to register as a CP Times contributor."
        });
      }


      // --------------------------------------------------------
      // Check whether contributor is active
      // --------------------------------------------------------

      if (contributor.active !== true) {
        return res.status(403).json({
          success: false,
          error:
            "This contributor account is currently inactive. Please contact the CP Times administrator."
        });
      }


      // --------------------------------------------------------
      // Check OTP control
      // --------------------------------------------------------

      const {
        data: control,
        error: controlError
      } = await adminSb
        .from("otp_control")
        .select(
          "email, attempts, locked_until, last_sent_at"
        )
        .eq("email", email)
        .maybeSingle();


      if (controlError) {
        console.error(
          "OTP control lookup error:",
          controlError
        );

        return res.status(500).json({
          success: false,
          error:
            "Unable to check OTP status."
        });
      }


      // --------------------------------------------------------
      // If previous 24-hour lock has expired,
      // reset the attempt counter.
      // --------------------------------------------------------

      let attempts = Number(
        control?.attempts || 0
      );

      if (
        control?.locked_until &&
        new Date(control.locked_until) <=
          new Date()
      ) {

        attempts = 0;

        await adminSb
          .from("otp_control")
          .upsert(
            {
              email,
              attempts: 0,
              locked_until: null,
              updated_at:
                new Date().toISOString()
            },
            {
              onConflict: "email"
            }
          );
      }


      // --------------------------------------------------------
      // Check 24-hour lock
      // --------------------------------------------------------

      if (
        control?.locked_until &&
        new Date(control.locked_until) >
          new Date()
      ) {

        const lockedUntil = new Date(
          control.locked_until
        );

        return res.status(429).json({
          success: false,
          locked: true,
          error:
            "Too many incorrect OTP attempts. OTP generation is locked for 24 hours.",
          lockedUntil:
            lockedUntil.toISOString()
        });
      }


      // --------------------------------------------------------
      // Prevent rapid resend
      // --------------------------------------------------------

      if (control?.last_sent_at) {

        const lastSent = new Date(
          control.last_sent_at
        );

        const secondsSinceLastOTP =
          (Date.now() -
            lastSent.getTime()) /
          1000;

        if (
          secondsSinceLastOTP < 60
        ) {

          const remaining = Math.ceil(
            60 - secondsSinceLastOTP
          );

          return res.status(429).json({
            success: false,
            error:
              `Please wait ${remaining} seconds before requesting another OTP.`,
            retryAfter: remaining
          });
        }
      }


      // --------------------------------------------------------
      // Send OTP through Supabase
      // --------------------------------------------------------

      const {
        error: otpError
      } = await sb.auth.signInWithOtp({
        email,
        options: {
          shouldCreateUser: true
        }
      });


      if (otpError) {

        console.error(
          "Supabase OTP error:",
          otpError
        );

        return res.status(500).json({
          success: false,
          error:
            "Unable to send OTP. Please try again later."
        });
      }


      // --------------------------------------------------------
      // Update OTP control
      //
      // IMPORTANT:
      // Sending an OTP does NOT count as an invalid attempt.
      //
      // The attempt counter is increased only when the user
      // enters an incorrect OTP.
      // --------------------------------------------------------

      const now =
        new Date().toISOString();

      const {
        error: upsertError
      } = await adminSb
        .from("otp_control")
        .upsert(
          {
            email,
            attempts,
            locked_until: null,
            last_sent_at: now,
            updated_at: now
          },
          {
            onConflict: "email"
          }
        );


      if (upsertError) {
        console.error(
          "OTP control update error:",
          upsertError
        );
      }


      // --------------------------------------------------------
      // Audit log
      // --------------------------------------------------------

      const {
        error: auditError
      } = await adminSb
        .from("audit_log")
        .insert({
          action:
            "contributor_otp_requested",
          target_email: email,
          details: {
            name:
              contributor.full_name ||
              null
          }
        });


      if (auditError) {
        console.error(
          "Audit log error:",
          auditError
        );
      }


      // --------------------------------------------------------
      // Success
      // --------------------------------------------------------

      return res.json({
        success: true,
        message:
          "OTP sent successfully to your registered email address."
      });


    } catch (error) {

      console.error(
        "Request OTP unexpected error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Something went wrong while generating the OTP."
      });
    }
  }
);


// ============================================================
// CONTRIBUTOR REGISTRATION
// STEP 2 — VERIFY OTP
// ============================================================

app.post(
  "/api/contributor/verify-otp",
  otpLimiter,
  async (req, res) => {

    try {

      if (!adminSb || !sb) {
        return res.status(503).json({
          success: false,
          error:
            "Authentication service is not configured."
        });
      }


      // --------------------------------------------------------
      // Read values
      // --------------------------------------------------------

      const email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();

      const token = String(
        req.body.token || ""
      ).trim();


      // --------------------------------------------------------
      // Validate email
      // --------------------------------------------------------

      const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      if (!emailPattern.test(email)) {
        return res.status(400).json({
          success: false,
          error:
            "Please enter a valid email address."
        });
      }


      // --------------------------------------------------------
      // Validate OTP
      // --------------------------------------------------------

      if (!/^\d{6}$/.test(token)) {
        return res.status(400).json({
          success: false,
          error:
            "Please enter the 6-digit OTP."
        });
      }


      // --------------------------------------------------------
      // Check contributor
      // --------------------------------------------------------

      const contributor =
        await getContributor(email);

      if (!contributor) {
        return res.status(403).json({
          success: false,
          error:
            "This email address is not registered as a CP Times contributor."
        });
      }


      if (contributor.active !== true) {
        return res.status(403).json({
          success: false,
          error:
            "This contributor account is inactive."
        });
      }


      // --------------------------------------------------------
      // Get OTP control record
      // --------------------------------------------------------

      const {
        data: otpControl,
        error: otpReadError
      } = await adminSb
        .from("otp_control")
        .select("*")
        .eq("email", email)
        .maybeSingle();


      if (otpReadError) {

        console.error(
          "OTP control read error:",
          otpReadError
        );

        return res.status(500).json({
          success: false,
          error:
            "Unable to check OTP status."
        });
      }


      // --------------------------------------------------------
      // Check 24-hour lock
      // --------------------------------------------------------

      if (
        otpControl?.locked_until &&
        new Date(
          otpControl.locked_until
        ) > new Date()
      ) {

        const lockedUntil =
          new Date(
            otpControl.locked_until
          );

        return res.status(429).json({
          success: false,
          locked: true,
          error:
            "Too many incorrect OTP attempts. Please try again after 24 hours.",
          lockedUntil:
            lockedUntil.toISOString()
        });
      }


      // --------------------------------------------------------
      // Verify OTP using Supabase Auth
      // --------------------------------------------------------

      const {
        data: verifyData,
        error: verifyError
      } = await sb.auth.verifyOtp({
        email,
        token,
        type: "email"
      });


      // ========================================================
      // INVALID OTP
      // ========================================================

      if (
        verifyError ||
        !verifyData?.user
      ) {

        let currentAttempts =
          Number(
            otpControl?.attempts || 0
          );


        const newAttempts =
          currentAttempts + 1;


        // ------------------------------------------------------
        // Third incorrect OTP
        // ------------------------------------------------------

        if (newAttempts >= 3) {

          const lockedUntil =
            new Date(
              Date.now() +
                24 *
                  60 *
                  60 *
                  1000
            ).toISOString();


          await adminSb
            .from("otp_control")
            .upsert(
              {
                email,
                attempts: newAttempts,
                locked_until:
                  lockedUntil,
                updated_at:
                  new Date().toISOString()
              },
              {
                onConflict: "email"
              }
            );


          await adminSb
            .from("audit_log")
            .insert({
              action:
                "contributor_otp_locked",
              target_email: email,
              details: {
                attempts: newAttempts,
                reason:
                  "Three invalid OTP attempts"
              }
            });


          return res.status(429).json({
            success: false,
            locked: true,
            error:
              "Three invalid OTP attempts. OTP generation is locked for 24 hours.",
            lockedUntil
          });
        }


        // ------------------------------------------------------
        // Record invalid attempt
        // ------------------------------------------------------

        await adminSb
          .from("otp_control")
          .upsert(
            {
              email,
              attempts: newAttempts,
              locked_until: null,
              updated_at:
                new Date().toISOString()
            },
            {
              onConflict: "email"
            }
          );


        await adminSb
          .from("audit_log")
          .insert({
            action:
              "contributor_invalid_otp",
            target_email: email,
            details: {
              attempt: newAttempts
            }
          });


        return res.status(401).json({
          success: false,
          error: "Invalid OTP.",
          attemptsRemaining:
            3 - newAttempts
        });
      }


      // ========================================================
      // OTP SUCCESS
      // ========================================================

      const userId =
        verifyData.user.id;


      // --------------------------------------------------------
      // Reset OTP attempts
      // --------------------------------------------------------

      await adminSb
        .from("otp_control")
        .upsert(
          {
            email,
            attempts: 0,
            locked_until: null,
            last_sent_at: null,
            updated_at:
              new Date().toISOString()
          },
          {
            onConflict: "email"
          }
        );


      // --------------------------------------------------------
      // Link contributor to Auth user
      // --------------------------------------------------------

      if (!contributor.user_id) {

        const {
          error: contributorUpdateError
        } = await adminSb
          .from("contributor_allowlist")
          .update({
            user_id: userId,
            registered_at:
              new Date().toISOString(),
            updated_at:
              new Date().toISOString()
          })
          .eq("email", email);


        if (contributorUpdateError) {

          console.error(
            "Contributor update error:",
            contributorUpdateError
          );

          return res.status(500).json({
            success: false,
            error:
              "Email verified, but contributor registration could not be completed."
          });
        }
      }


      // --------------------------------------------------------
      // Audit successful verification
      // --------------------------------------------------------

      const {
        error: auditError
      } = await adminSb
        .from("audit_log")
        .insert({
          actor_id: userId,
          action:
            "contributor_otp_verified",
          target_email: email,
          target_id: userId,
          details: {
            verified: true
          }
        });


      if (auditError) {
        console.error(
          "OTP verification audit error:",
          auditError
        );
      }


      // --------------------------------------------------------
      // Create short-lived registration token
      // --------------------------------------------------------

      const registrationToken =
        createRegistrationToken(
          email,
          userId
        );


      // --------------------------------------------------------
      // Return registration token
      // --------------------------------------------------------

      return res.json({
        success: true,
        verified: true,
        userId,
        registrationToken,
        message:
          "Email verified successfully. You can now set your password."
      });


    } catch (error) {

      console.error(
        "Verify OTP error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Something went wrong while verifying the OTP."
      });
    }
  }
);


// ============================================================
// CONTRIBUTOR REGISTRATION
// STEP 3 — SET PASSWORD
// ============================================================

app.post(
  "/api/contributor/set-password",
  async (req, res) => {

    try {

      if (!adminSb) {
        return res.status(503).json({
          success: false,
          error:
            "Authentication service is not configured."
        });
      }


      // --------------------------------------------------------
      // Read values
      // --------------------------------------------------------

      const registrationToken =
        String(
          req.body.registrationToken ||
            ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );


      // --------------------------------------------------------
      // Verify registration token
      // --------------------------------------------------------

      const tokenData =
        verifyRegistrationToken(
          registrationToken
        );


      if (!tokenData) {
        return res.status(401).json({
          success: false,
          error:
            "Your email verification has expired. Please verify your email again."
        });
      }


      // --------------------------------------------------------
      // Validate password
      // --------------------------------------------------------

      if (password.length < 10) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be at least 10 characters long."
        });
      }


      // Require:
      // lowercase
      // uppercase
      // number
      // special character

      const hasLower =
        /[a-z]/.test(password);

      const hasUpper =
        /[A-Z]/.test(password);

      const hasNumber =
        /\d/.test(password);

      const hasSpecial =
        /[^A-Za-z0-9]/.test(
          password
        );


      if (
        !hasLower ||
        !hasUpper ||
        !hasNumber ||
        !hasSpecial
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Password must contain at least one uppercase letter, lowercase letter, number and special character."
        });
      }


      // --------------------------------------------------------
      // Verify contributor still exists and is active
      // --------------------------------------------------------

      const contributor =
        await getContributor(
          tokenData.email
        );


      if (!contributor) {
        return res.status(403).json({
          success: false,
          error:
            "Contributor account not found."
        });
      }


      if (contributor.active !== true) {
        return res.status(403).json({
          success: false,
          error:
            "Contributor account is inactive."
        });
      }


      // --------------------------------------------------------
      // Set password using Supabase Admin API
      // --------------------------------------------------------

      const {
        data: updatedUser,
        error: passwordError
      } = await adminSb.auth.admin.updateUserById(
        tokenData.userId,
        {
          password
        }
      );


      if (passwordError) {

        console.error(
          "Password update error:",
          passwordError
        );

        return res.status(500).json({
          success: false,
          error:
            "Unable to set password. Please try again."
        });
      }


      // --------------------------------------------------------
      // Update contributor record
      // --------------------------------------------------------

      await adminSb
        .from("contributor_allowlist")
        .update({
          user_id:
            tokenData.userId,
          registered_at:
            contributor.registered_at ||
            new Date().toISOString(),
          updated_at:
            new Date().toISOString()
        })
        .eq(
          "email",
          tokenData.email
        );


      // --------------------------------------------------------
      // Audit
      // --------------------------------------------------------

      await adminSb
        .from("audit_log")
        .insert({
          actor_id:
            tokenData.userId,
          action:
            "contributor_password_created",
          target_email:
            tokenData.email,
          target_id:
            tokenData.userId,
          details: {
            passwordCreated: true
          }
        });


      return res.json({
        success: true,
        message:
          "Password created successfully. You can now log in."
      });


    } catch (error) {

      console.error(
        "Set password error:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Something went wrong while setting your password."
      });
    }
  }
);


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


    res.json(data || []);
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
          "slug,category"
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
            )}/${encodeURIComponent(
              article.slug
            )}`
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

    const article =
      await published(
        req.params[2]
      );


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
      )}/${encodeURIComponent(
        article.slug
      )}`;


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
    res.sendFile(
      path.join(
        PUB,
        "admin.html"
      )
    );
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
    res.sendFile(
      path.join(
        PUB,
        "contributor-register.html"
      )
    );
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
