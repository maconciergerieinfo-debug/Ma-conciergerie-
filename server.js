const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_BEFORE_PRODUCTION";
const OWNER_EMAIL = process.env.OWNER_EMAIL || "admin@example.com";
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "ChangeMoi123!";

// Connexion sécurisée à Supabase.
// Les vraies valeurs seront ajoutées dans Render, jamais dans GitHub.
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.warn("⚠️ Variables Supabase manquantes.");
}

const supabase = createClient(
  SUPABASE_URL || "https://placeholder.supabase.co",
  SUPABASE_SECRET_KEY || "placeholder"
);

app.use(express.json());
app.use(express.static(__dirname));


// ===============================
// UTILISATEUR ADMINISTRATEUR
// ===============================

// Pour le moment, on conserve l'administratrice dans les variables Render.
// Plus tard, nous pourrons aussi créer une vraie gestion des comptes.
async function loginAdmin(email, password) {
  if (
    String(email || "").toLowerCase() === OWNER_EMAIL.toLowerCase() &&
    String(password || "") === OWNER_PASSWORD
  ) {
    return {
      id: "admin-1",
      email: OWNER_EMAIL.toLowerCase(),
      role: "admin",
      name: "Administratrice"
    };
  }

  return null;
}


// ===============================
// SÉCURITÉ
// ===============================

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Non authentifiée" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expirée" });
  }
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Accès réservé" });
  }

  next();
}


// ===============================
// CONNEXION
// ===============================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    const user = await loginAdmin(email, password);

    if (!user) {
      return res
        .status(401)
        .json({ error: "E-mail ou mot de passe incorrect" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name
      },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      token,
      user: {
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Erreur connexion :", error);
    res.status(500).json({ error: "Erreur lors de la connexion" });
  }
});


// ===============================
// TABLEAU DE BORD
// ===============================

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const { count: clients, error: clientsError } = await supabase
      .from("clients")
      .select("*", { count: "exact", head: true });

    const { count: dossiers, error: dossiersError } = await supabase
      .from("dossiers")
      .select("*", { count: "exact", head: true });

    const { count: dossiersOuverts, error: ouvertsError } = await supabase
      .from("dossiers")
      .select("*", { count: "exact", head: true })
      .neq("status", "Terminé");

    if (clientsError || dossiersError || ouvertsError) {
  console.error("Erreur clients :", clientsError);
  console.error("Erreur dossiers :", dossiersError);
  console.error("Erreur dossiers ouverts :", ouvertsError);

  return res.status(500).json({
    error: "Erreur lors du chargement du tableau de bord"
  });
}

    res.json({
      clients: clients || 0,
      dossiers: dossiers || 0,
      dossiersOuverts: dossiersOuverts || 0
    });
  } catch (error) {
    console.error("Erreur dashboard :", error);
    res.status(500).json({ error: "Impossible de charger le tableau de bord" });
  }
});


// ===============================
// CLIENTES
// ===============================

app.get("/api/clients", auth, admin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("clients")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) throw error;

    res.json(data || []);
  } catch (error) {
    console.error("Erreur clientes :", error);
    res.status(500).json({ error: "Impossible de charger les clientes" });
  }
});

app.post("/api/clients", auth, admin, async (req, res) => {
  try {
    const { name, email, phone } = req.body || {};

    if (!name || !email) {
      return res
        .status(400)
        .json({ error: "Nom et e-mail obligatoires" });
    }

    const client = {
      id: "c-" + Date.now(),
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      phone: phone ? String(phone).trim() : ""
    };

    const { data, error } = await supabase
      .from("clients")
      .insert(client)
      .select()
      .single();

    if (error) {
      if (error.code === "23505") {
        return res
          .status(400)
          .json({ error: "Cette cliente existe déjà." });
      }

      throw error;
    }

    res.status(201).json(data);
  } catch (error) {
    console.error("Erreur ajout cliente :", error);
    res.status(500).json({ error: "Impossible d'ajouter la cliente" });
  }
});

// ===============================
// MODIFIER UNE CLIENTE
// ===============================

app.put("/api/clients/:id", auth, admin, async (req, res) => {
  try {
    const { name, email, phone } = req.body || {};
    const { id } = req.params;

    if (!name || !email) {
      return res.status(400).json({
        error: "Le nom et l'e-mail sont obligatoires."
      });
    }

    const updatedClient = {
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      phone: phone ? String(phone).trim() : ""
    };

    const { data, error } = await supabase
      .from("clients")
      .update(updatedClient)
      .eq("id", id)
      .select()
      .single();

    if (error) {
      if (error.code === "23505") {
        return res.status(400).json({
          error: "Une cliente utilise déjà cette adresse e-mail."
        });
      }
      throw error;
    }

    res.json(data);
  } catch (error) {
    console.error("Erreur modification cliente :", error);
    res.status(500).json({
      error: "Impossible de modifier la cliente."
    });
  }
});

// ===============================
// DOSSIERS
// ===============================

app.get("/api/dossiers", auth, async (req, res) => {
  try {
    let query = supabase
      .from("dossiers")
      .select("*")
      .order("created_at", { ascending: false });

    if (req.user.role !== "admin") {
      query = query.eq("client_email", req.user.email);
    }

    const { data, error } = await query;

    if (error) throw error;

    res.json(data || []);
  } catch (error) {
    console.error("Erreur dossiers :", error);
    res.status(500).json({ error: "Impossible de charger les dossiers" });
  }
});

app.post("/api/dossiers", auth, admin, async (req, res) => {
  try {
    const { title, clientEmail, status, notes } = req.body || {};

    if (!title || !clientEmail) {
      return res
        .status(400)
        .json({ error: "Titre et cliente obligatoires" });
    }

    const dossier = {
      id: "d-" + Date.now(),
      title: String(title).trim(),
      client_email: String(clientEmail).trim().toLowerCase(),
      status: status || "Nouveau",
      notes: notes || ""
    };

    const { data, error } = await supabase
      .from("dossiers")
      .insert(dossier)
      .select()
      .single();

    if (error) throw error;

    res.status(201).json(data);
  } catch (error) {
    console.error("Erreur ajout dossier :", error);
    res.status(500).json({ error: "Impossible de créer le dossier" });
  }
});

// ===============================
// MODIFIER UN DOSSIER
// ===============================

app.put("/api/dossiers/:id", auth, admin, async (req, res) => {
  try {
    const { title, clientEmail, status, notes } = req.body || {};
    const { id } = req.params;

    if (!title || !clientEmail) {
      return res.status(400).json({
        error: "Le titre et l'e-mail de la cliente sont obligatoires."
      });
    }

    const updatedDossier = {
      title: String(title).trim(),
      client_email: String(clientEmail).trim().toLowerCase(),
      status: String(status || "Nouveau"),
      notes: notes ? String(notes).trim() : ""
    };

    const { data, error } = await supabase
      .from("dossiers")
      .update(updatedDossier)
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error("Erreur modification dossier :", error);
    res.status(500).json({
      error: "Impossible de modifier le dossier."
    });
  }
});

// ===============================
// TEST API
// ===============================

app.get("/api/test", (req, res) => {
  res.json({ message: "API fonctionne !" });
});


// ===============================
// DÉMARRAGE
// ===============================

app.listen(PORT, () => {
  console.log(`Ma Conciergerie lancée sur le port ${PORT}`);
});
