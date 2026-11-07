"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");


/* =========================================
   CONFIGURATION
========================================= */

const app = express();

const PORT =
  process.env.PORT || 3000;

const {
  JWT_SECRET,
  OWNER_EMAIL,
  OWNER_PASSWORD_HASH,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  FRONTEND_URL
} = process.env;


/* =========================================
   VÉRIFICATION CONFIGURATION
========================================= */

const requiredVariables = {
  JWT_SECRET,
  OWNER_EMAIL,
  OWNER_PASSWORD_HASH,
  SUPABASE_URL,
  SUPABASE_SECRET_KEY
};


for (const [name, value] of Object.entries(requiredVariables)) {

  if (!value) {

    console.error(
      `❌ Variable d'environnement manquante : ${name}`
    );

    process.exit(1);

  }

}


/* =========================================
   SUPABASE
========================================= */

const supabase =
  createClient(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    }
  );


/* =========================================
   CONSTANTES
========================================= */

const VALID_STATUSES = [
  "Nouveau",
  "En cours",
  "En attente",
  "Terminé"
];


/* =========================================
   SÉCURITÉ
========================================= */

app.disable("x-powered-by");


app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);


/*
  CORS :
  Si FRONTEND_URL est défini, seul ce domaine
  pourra appeler l'API depuis un navigateur.

  Les requêtes sans origin restent autorisées
  pour les outils serveur et les tests.
*/

const allowedOrigins =
  [
    FRONTEND_URL,
    "http://localhost:3000"
  ].filter(Boolean);


app.use(
  cors({
    origin(origin, callback) {

      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.length === 0) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("Origine non autorisée.")
      );

    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "DELETE"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);


app.use(
  express.json({
    limit: "100kb"
  })
);


/* =========================================
   LIMITATION DES REQUÊTES
========================================= */

const apiLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    max:
      300,

    standardHeaders:
      true,

    legacyHeaders:
      false,

    message: {
      error:
        "Trop de requêtes. Veuillez réessayer dans quelques minutes."
    }
  });


const loginLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    max:
      10,

    standardHeaders:
      true,

    legacyHeaders:
      false,

    message: {
      error:
        "Trop de tentatives de connexion. Réessayez dans quelques minutes."
    }
  });


app.use(
  "/api",
  apiLimiter
);


/* =========================================
   FICHIERS STATIQUES
========================================= */

app.use(
  express.static(
    __dirname
  )
);


/* =========================================
   OUTILS
========================================= */

function normalizeEmail(email) {

  return String(
    email || ""
  )
    .trim()
    .toLowerCase();

}


function isValidEmail(email) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);

}


function sanitizeText(
  value,
  maxLength = 5000
) {

  return String(
    value || ""
  )
    .trim()
    .slice(0, maxLength);

}


function createId() {

  return crypto.randomUUID();

}


/* =========================================
   AUTHENTIFICATION
========================================= */

function auth(
  req,
  res,
  next
) {

  const header =
    req.headers.authorization || "";

  const token =
    header.startsWith("Bearer ")
      ? header.slice(7)
      : null;


  if (!token) {

    return res
      .status(401)
      .json({
        error:
          "Veuillez vous connecter."
      });

  }


  try {

    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch {

    return res
      .status(401)
      .json({
        error:
          "Votre session a expiré. Veuillez vous reconnecter."
      });

  }

}


function admin(
  req,
  res,
  next
) {

  if (
    req.user.role !== "admin"
  ) {

    return res
      .status(403)
      .json({
        error:
          "Accès réservé à l'administration."
      });

  }

  next();

}


/* =========================================
   CONNEXION ADMIN
========================================= */

async function loginAdmin(
  email,
  password
) {

  const normalizedEmail =
    normalizeEmail(email);


  if (
    normalizedEmail !==
    normalizeEmail(OWNER_EMAIL)
  ) {

    return null;

  }


  const passwordValid =
    await bcrypt.compare(
      String(password || ""),
      OWNER_PASSWORD_HASH
    );


  if (!passwordValid) {

    return null;

  }


  return {

    id:
      "admin",

    email:
      normalizeEmail(
        OWNER_EMAIL
      ),

    role:
      "admin",

    name:
      "Administratrice"

  };

}


/* =========================================
   ROUTE CONNEXION
========================================= */

app.post(
  "/api/login",
  loginLimiter,
  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        email,
        password
      } =
        req.body || {};


      if (
        !email ||
        !password
      ) {

        return res
          .status(400)
          .json({
            error:
              "Veuillez renseigner votre e-mail et votre mot de passe."
          });

      }


      const user =
        await loginAdmin(
          email,
          password
        );


      if (!user) {

        return res
          .status(401)
          .json({
            error:
              "E-mail ou mot de passe incorrect."
          });

      }


      const token =
        jwt.sign(
          {
            id:
              user.id,

            email:
              user.email,

            role:
              user.role,

            name:
              user.name
          },

          JWT_SECRET,

          {
            expiresIn:
              "12h"
          }
        );


      res.json({
        token,

        user: {
          name:
            user.name,

          email:
            user.email,

          role:
            user.role
        }
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   TABLEAU DE BORD
========================================= */

app.get(
  "/api/dashboard",
  auth,
  async (
    req,
    res,
    next
  ) => {

    try {

      /*
        ADMIN :
        voit toutes les statistiques.

        FUTUR COMPTE CLIENT :
        verra uniquement ses dossiers.
      */

      if (
        req.user.role !== "admin"
      ) {

        const {
          count: dossiers,
          error
        } =
          await supabase
            .from("dossiers")
            .select(
              "*",
              {
                count:
                  "exact",

                head:
                  true
              }
            )
            .eq(
              "client_email",
              req.user.email
            );


        if (error) {
          throw error;
        }


        const {
          count: dossiersOuverts,
          error: ouvertsError
        } =
          await supabase
            .from("dossiers")
            .select(
              "*",
              {
                count:
                  "exact",

                head:
                  true
              }
            )
            .eq(
              "client_email",
              req.user.email
            )
            .neq(
              "status",
              "Terminé"
            );


        if (ouvertsError) {
          throw ouvertsError;
        }


        return res.json({
          clients: 0,

          dossiers:
            dossiers || 0,

          dossiersOuverts:
            dossiersOuverts || 0
        });

      }


      const [
        clientsResult,
        dossiersResult,
        ouvertsResult
      ] =
        await Promise.all([

          supabase
            .from("clients")
            .select(
              "*",
              {
                count:
                  "exact",

                head:
                  true
              }
            ),

          supabase
            .from("dossiers")
            .select(
              "*",
              {
                count:
                  "exact",

                head:
                  true
              }
            ),

          supabase
            .from("dossiers")
            .select(
              "*",
              {
                count:
                  "exact",

                head:
                  true
              }
            )
            .neq(
              "status",
              "Terminé"
            )

        ]);


      if (
        clientsResult.error ||
        dossiersResult.error ||
        ouvertsResult.error
      ) {

        throw (
          clientsResult.error ||
          dossiersResult.error ||
          ouvertsResult.error
        );

      }


      res.json({

        clients:
          clientsResult.count || 0,

        dossiers:
          dossiersResult.count || 0,

        dossiersOuverts:
          ouvertsResult.count || 0

      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   CLIENTES - LISTE
========================================= */

app.get(
  "/api/clients",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        data,
        error
      } =
        await supabase
          .from("clients")
          .select("*")
          .order(
            "created_at",
            {
              ascending:
                false
            }
          );


      if (error) {
        throw error;
      }


      res.json(
        data || []
      );

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   CLIENTES - AJOUT
========================================= */

app.post(
  "/api/clients",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        name,
        email,
        phone
      } =
        req.body || {};


      const cleanName =
        sanitizeText(
          name,
          120
        );

      const cleanEmail =
        normalizeEmail(
          email
        );

      const cleanPhone =
        sanitizeText(
          phone,
          40
        );


      if (
        !cleanName ||
        !cleanEmail
      ) {

        return res
          .status(400)
          .json({
            error:
              "Le nom et l'e-mail sont obligatoires."
          });

      }


      if (
        !isValidEmail(
          cleanEmail
        )
      ) {

        return res
          .status(400)
          .json({
            error:
              "L'adresse e-mail n'est pas valide."
          });

      }


      const {
        data,
        error
      } =
        await supabase
          .from("clients")
          .insert({
            id:
              createId(),

            name:
              cleanName,

            email:
              cleanEmail,

            phone:
              cleanPhone
          })
          .select()
          .single();


      if (error) {

        if (
          error.code === "23505"
        ) {

          return res
            .status(409)
            .json({
              error:
                "Une cliente utilise déjà cette adresse e-mail."
            });

        }

        throw error;

      }


      res
        .status(201)
        .json(data);

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   CLIENTES - MODIFICATION
========================================= */

app.put(
  "/api/clients/:id",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        sanitizeText(
          req.params.id,
          100
        );

      const {
        name,
        email,
        phone
      } =
        req.body || {};


      const cleanName =
        sanitizeText(
          name,
          120
        );

      const cleanEmail =
        normalizeEmail(
          email
        );

      const cleanPhone =
        sanitizeText(
          phone,
          40
        );


      if (
        !cleanName ||
        !isValidEmail(
          cleanEmail
        )
      ) {

        return res
          .status(400)
          .json({
            error:
              "Veuillez fournir un nom et une adresse e-mail valide."
          });

      }


      /*
        Récupération de la cliente actuelle.
        Cela permet de synchroniser les dossiers
        si son adresse e-mail change.
      */

      const {
        data: existingClient,
        error: existingError
      } =
        await supabase
          .from("clients")
          .select("id, email")
          .eq(
            "id",
            id
          )
          .maybeSingle();


      if (existingError) {
        throw existingError;
      }


      if (!existingClient) {

        return res
          .status(404)
          .json({
            error:
              "Cliente introuvable."
          });

      }


      const {
        data,
        error
      } =
        await supabase
          .from("clients")
          .update({
            name:
              cleanName,

            email:
              cleanEmail,

            phone:
              cleanPhone
          })
          .eq(
            "id",
            id
          )
          .select()
          .single();


      if (error) {

        if (
          error.code === "23505"
        ) {

          return res
            .status(409)
            .json({
              error:
                "Une cliente utilise déjà cette adresse e-mail."
            });

        }

        throw error;

      }


      /*
        Si l'e-mail a changé, on met également
        à jour les dossiers existants.
      */

      if (
        existingClient.email !==
        cleanEmail
      ) {

        const {
          error: dossiersError
        } =
          await supabase
            .from("dossiers")
            .update({
              client_email:
                cleanEmail
            })
            .eq(
              "client_email",
              existingClient.email
            );


        if (dossiersError) {
          throw dossiersError;
        }

      }


      res.json(data);

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   CLIENTES - SUPPRESSION
========================================= */

app.delete(
  "/api/clients/:id",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        sanitizeText(
          req.params.id,
          100
        );


      const {
        data: client,
        error: clientError
      } =
        await supabase
          .from("clients")
          .select("id, email")
          .eq(
            "id",
            id
          )
          .maybeSingle();


      if (clientError) {
        throw clientError;
      }


      if (!client) {

        return res
          .status(404)
          .json({
            error:
              "Cliente introuvable."
          });

      }


      const {
        count,
        error: dossiersError
      } =
        await supabase
          .from("dossiers")
          .select(
            "*",
            {
              count:
                "exact",

              head:
                true
            }
          )
          .eq(
            "client_email",
            client.email
          );


      if (dossiersError) {
        throw dossiersError;
      }


      if (
        (count || 0) > 0
      ) {

        return res
          .status(409)
          .json({
            error:
              "Impossible de supprimer cette cliente car elle possède encore des dossiers."
          });

      }


      const {
        error
      } =
        await supabase
          .from("clients")
          .delete()
          .eq(
            "id",
            id
          );


      if (error) {
        throw error;
      }


      res.json({
        success:
          true,

        message:
          "Cliente supprimée définitivement."
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   DOSSIERS - LISTE
========================================= */

app.get(
  "/api/dossiers",
  auth,
  async (
    req,
    res,
    next
  ) => {

    try {

      let query =
        supabase
          .from("dossiers")
          .select("*")
          .order(
            "created_at",
            {
              ascending:
                false
            }
          );


      if (
        req.user.role !==
        "admin"
      ) {

        query =
          query.eq(
            "client_email",
            req.user.email
          );

      }


      const {
        data,
        error
      } =
        await query;


      if (error) {
        throw error;
      }


      res.json(
        data || []
      );

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   DOSSIERS - AJOUT
========================================= */

app.post(
  "/api/dossiers",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const {
        title,
        clientEmail,
        status,
        notes
      } =
        req.body || {};


      const cleanTitle =
        sanitizeText(
          title,
          200
        );

      const cleanEmail =
        normalizeEmail(
          clientEmail
        );

      const cleanStatus =
        VALID_STATUSES.includes(status)
          ? status
          : "Nouveau";

      const cleanNotes =
        sanitizeText(
          notes,
          5000
        );


      if (
        !cleanTitle ||
        !cleanEmail
      ) {

        return res
          .status(400)
          .json({
            error:
              "Le titre et l'adresse e-mail de la cliente sont obligatoires."
          });

      }


      if (
        !isValidEmail(
          cleanEmail
        )
      ) {

        return res
          .status(400)
          .json({
            error:
              "L'adresse e-mail de la cliente n'est pas valide."
          });

      }


      /*
        Vérifie que la cliente existe.
        Cela évite la création de dossiers orphelins.
      */

      const {
        data: client,
        error: clientError
      } =
        await supabase
          .from("clients")
          .select("id")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();


      if (clientError) {
        throw clientError;
      }


      if (!client) {

        return res
          .status(400)
          .json({
            error:
              "Cette adresse e-mail ne correspond à aucune cliente enregistrée."
          });

      }


      const {
        data,
        error
      } =
        await supabase
          .from("dossiers")
          .insert({
            id:
              createId(),

            title:
              cleanTitle,

            client_email:
              cleanEmail,

            status:
              cleanStatus,

            notes:
              cleanNotes
          })
          .select()
          .single();


      if (error) {
        throw error;
      }


      res
        .status(201)
        .json(data);

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   DOSSIERS - MODIFICATION
========================================= */

app.put(
  "/api/dossiers/:id",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        sanitizeText(
          req.params.id,
          100
        );

      const {
        title,
        clientEmail,
        status,
        notes
      } =
        req.body || {};


      const cleanTitle =
        sanitizeText(
          title,
          200
        );

      const cleanEmail =
        normalizeEmail(
          clientEmail
        );

      const cleanStatus =
        VALID_STATUSES.includes(status)
          ? status
          : null;

      const cleanNotes =
        sanitizeText(
          notes,
          5000
        );


      if (
        !cleanTitle ||
        !isValidEmail(
          cleanEmail
        ) ||
        !cleanStatus
      ) {

        return res
          .status(400)
          .json({
            error:
              "Veuillez vérifier le titre, l'adresse e-mail et le statut."
          });

      }


      const {
        data: existingDossier,
        error: existingError
      } =
        await supabase
          .from("dossiers")
          .select("id")
          .eq(
            "id",
            id
          )
          .maybeSingle();


      if (existingError) {
        throw existingError;
      }


      if (!existingDossier) {

        return res
          .status(404)
          .json({
            error:
              "Dossier introuvable."
          });

      }


      /*
        Vérifie que la nouvelle cliente existe.
      */

      const {
        data: client,
        error: clientError
      } =
        await supabase
          .from("clients")
          .select("id")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();


      if (clientError) {
        throw clientError;
      }


      if (!client) {

        return res
          .status(400)
          .json({
            error:
              "Cette adresse e-mail ne correspond à aucune cliente enregistrée."
          });

      }


      const {
        data,
        error
      } =
        await supabase
          .from("dossiers")
          .update({
            title:
              cleanTitle,

            client_email:
              cleanEmail,

            status:
              cleanStatus,

            notes:
              cleanNotes
          })
          .eq(
            "id",
            id
          )
          .select()
          .single();


      if (error) {
        throw error;
      }


      res.json(data);

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   DOSSIERS - SUPPRESSION
========================================= */

app.delete(
  "/api/dossiers/:id",
  auth,
  admin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        sanitizeText(
          req.params.id,
          100
        );


      const {
        data: dossier,
        error: findError
      } =
        await supabase
          .from("dossiers")
          .select("id")
          .eq(
            "id",
            id
          )
          .maybeSingle();


      if (findError) {
        throw findError;
      }


      if (!dossier) {

        return res
          .status(404)
          .json({
            error:
              "Dossier introuvable."
          });

      }


      const {
        error
      } =
        await supabase
          .from("dossiers")
          .delete()
          .eq(
            "id",
            id
          );


      if (error) {
        throw error;
      }


      res.json({
        success:
          true,

        message:
          "Dossier supprimé définitivement."
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================
   TEST API
========================================= */

app.get(
  "/api/test",
  (
    req,
    res
  ) => {

    res.json({
      success:
        true,

      message:
        "API Ma Conciergerie fonctionne correctement."
    });

  }
);


/* =========================================
   GESTION DES ERREURS
========================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "Erreur serveur :",
      error
    );


    if (
      error.message ===
      "Origine non autorisée."
    ) {

      return res
        .status(403)
        .json({
          error:
            "Cette origine n'est pas autorisée."
        });

    }


    res
      .status(500)
      .json({
        error:
          "Une erreur interne est survenue."
      });

  }
);


/* =========================================
   ROUTES INCONNUES API
========================================= */

app.use(
  "/api",
  (
    req,
    res
  ) => {

    res
      .status(404)
      .json({
        error:
          "Route API introuvable."
      });

  }
);


/* =========================================
   DÉMARRAGE
========================================= */

app.listen(
  PORT,
  () => {

    console.log(
      `🌸 Ma Conciergerie est lancée sur le port ${PORT}`
    );

  }
);
