"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

// ==========================================
// CONFIGURATION
// ==========================================

const app = express();
const PORT = process.env.PORT || 3000;

const {
  JWT_SECRET,
  OWNER_EMAIL,
  OWNER_PASSWORD_HASH,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  FRONTEND_URL
} = process.env;

// Vérifications importantes en production.
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET est obligatoire.");
}

if (!OWNER_EMAIL || !OWNER_PASSWORD_HASH) {
  throw new Error(
    "OWNER_EMAIL et OWNER_PASSWORD_HASH sont obligatoires."
  );
}

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  throw new Error(
    "SUPABASE_URL et SUPABASE_SECRET_KEY sont obligatoires."
  );
}

// ==========================================
// SUPABASE
// ==========================================

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// ==========================================
// SÉCURITÉ GÉNÉRALE
// ==========================================

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

// Si ton frontend et ton backend sont sur le même domaine,
// cette configuration ne gêne pas.
// Tu pourras ajouter ton domaine personnalisé dans FRONTEND_URL.
const allowedOrigins = [
  FRONTEND_URL,
  "http://localhost:3000"
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Autorise les requêtes sans Origin (tests serveur, outils API).
      if (!origin || allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origine non autorisée par CORS."));
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json({ limit: "100kb" }));

// Sert ton site actuel.
app.use(express.static
