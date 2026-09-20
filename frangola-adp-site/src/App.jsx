import { useState, useEffect, useRef } from "react";
import { storage } from "./storage";
import { supabase } from "./supabaseClient";
import {
  Shield, Users, Building2, Upload, FileText, CheckCircle2, Clock,
  Bell, LogOut, Download, Plus, ArrowLeft, Copy, Check, AlertCircle,
  FileCheck2, Landmark, X, Folder, FolderOpen, ChevronDown, Trash2, RotateCcw, BarChart3, StickyNote, History, Home, Target, Eye, EyeOff, ImagePlus, Sparkles, ArrowLeftRight, TrendingUp, Key, Wallet, RefreshCw
} from "lucide-react";
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

const STATUS_STEPS = ["Déposé", "En vérification", "Devis en cours", "Souscrit", "Bordereau émis", "Payé"];
const ADMIN_STATUS_OPTIONS = ["Déposé", "En vérification", "Devis en cours", "Souscrit", "KO", "Bordereau émis", "Payé"];
const KO_REASONS = ["Refus banque / assureur", "Client a annulé", "Concurrent moins cher", "Sans nouvelles du client", "Autre"];
const PAYMENT_METHODS = ["Virement", "Carte cadeau"];
const STATUS_COLORS = {
  "Déposé": "bg-amber-100 text-amber-800 border-amber-300",
  "En vérification": "bg-sky-100 text-sky-800 border-sky-300",
  "Devis en cours": "bg-teal-100 fa-teal-text border-teal-300",
  "Souscrit": "bg-emerald-100 text-emerald-800 border-emerald-300",
  "Bordereau émis": "bg-violet-100 text-violet-800 border-violet-300",
  "Payé": "bg-green-100 text-green-800 border-green-300",
  "KO": "bg-red-100 text-red-800 border-red-300",
};
// Dès le devis, le dossier est engagé auprès de l'assureur : le partenaire ne
// peut plus renommer le client ni retirer une pièce, sous peine de créer un
// écart entre le contrat et la fiche. Il peut toujours en ajouter une.
const STATUTS_MODIFIABLES = ["Déposé", "En vérification"];
function dossierVerrouille(dossier) {
  return !STATUTS_MODIFIABLES.includes(dossier?.status);
}

const DOC_LABELS = { offre: "Offre de prêt", tableau: "Tableau d'amortissement", cni: "Carte d'identité" };
const MAX_FILE_BYTES = 3.5 * 1024 * 1024;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32ToBytes(base32) {
  let bits = "";
  for (const char of base32.replace(/=+$/, "").toUpperCase()) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substring(i, i + 8), 2));
  return new Uint8Array(bytes);
}
function randomBase32Secret(length = 16) {
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  let secret = "";
  for (let i = 0; i < length; i++) secret += BASE32_ALPHABET[randomValues[i] % 32];
  return secret;
}
function formatSecretForDisplay(secret) {
  return secret.match(/.{1,4}/g)?.join(" ") || secret;
}
async function hotp(secretBase32, counter) {
  const keyBytes = base32ToBytes(secretBase32);
  const counterBuf = new ArrayBuffer(8);
  new DataView(counterBuf).setUint32(4, counter, false);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBuf));
  const offset = hmac[hmac.length - 1] & 0xf;
  const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (binCode % 1000000).toString().padStart(6, "0");
}
async function verifyTotp(secretBase32, code, windowSteps = 1) {
  const now = Date.now();
  for (let e = -windowSteps; e <= windowSteps; e++) {
    const counter = Math.floor(now / 1000 / 30) + e;
    if ((await hotp(secretBase32, counter)) === code.trim()) return true;
  }
  return false;
}

function uid() {
  return (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now());
}
// La session est désormais tenue par Supabase Auth, qui la conserve et la
// renouvelle lui-même. L'ancienne session maison, stockée en clair dans le
// navigateur, est effacée au démarrage pour ne laisser aucune trace.
const SESSION_KEY = "adp:session";
function purgeAncienneSession() {
  try { localStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
}

// =============================================================================
// APPAREIL DE CONFIANCE
//
// Permet de ne pas redemander l'Authenticator à chaque rechargement, mais
// UNIQUEMENT sur les machines que la personne a explicitement désignées, en
// cochant une case. Rien n'est mémorisé sans ce geste : sur un ordinateur
// tiers, le second facteur reste exigé.
//
// La marque est liée au compte : si quelqu'un d'autre se connecte sur cette
// machine, elle ne lui sert à rien. Elle expire au bout de 30 jours.
// =============================================================================
const APPAREIL_KEY = "adp:appareilConnu";
const APPAREIL_DUREE_MS = 30 * 24 * 60 * 60 * 1000;

function cleAppareil(kind, account) {
  return kind === "admin" ? "admin:" + (account?.email || "") : "mandataire:" + (account?.id || "");
}
function appareilReconnu(cle) {
  try {
    const brut = localStorage.getItem(APPAREIL_KEY);
    if (!brut) return false;
    const marque = JSON.parse(brut);
    return !!marque && marque.cle === cle && typeof marque.jusqu === "number" && Date.now() < marque.jusqu;
  } catch (e) { return false; }
}
function memoriserAppareil(cle) {
  try { localStorage.setItem(APPAREIL_KEY, JSON.stringify({ cle, jusqu: Date.now() + APPAREIL_DUREE_MS })); } catch (e) { /* ignore */ }
}
function oublierAppareil() {
  try { localStorage.removeItem(APPAREIL_KEY); } catch (e) { /* ignore */ }
}

// Adresse de la fonction serveur qui crée ou réinitialise un accès.
const URL_ACTIVATION = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/activer-compte`;

async function appelerActivation(corps) {
  const reponse = await fetch(URL_ACTIVATION, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: import.meta.env.VITE_SUPABASE_ANON_KEY,
      Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`,
    },
    body: JSON.stringify(corps),
  });
  let resultat = {};
  try { resultat = await reponse.json(); } catch (e) { /* réponse vide */ }
  if (!reponse.ok) throw new Error(resultat.error || "Activation impossible. Réessayez dans un instant.");
  return resultat;
}
function getStoredTab(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch (e) { return fallback; }
}
function setStoredTab(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
}

// ── Onglets de l'espace admin ───────────────────────────────────────────────
// Catalogue de référence : c'est lui qui fait foi. L'ordre choisi par
// l'utilisateur n'est qu'une liste d'identifiants rangée à côté, ce qui permet
// d'ajouter un onglet plus tard sans casser la personnalisation existante.
const ONGLETS_ADMIN = [
  { id: "accueil", label: "Accueil", icone: "Home" },
  { id: "dossiers", label: "Dossiers", icone: "FileText" },
  { id: "partenaires", label: "Partenaires", icone: "Building2" },
  { id: "facturation", label: "Facturation", icone: "Wallet" },
  { id: "corbeille", label: "Corbeille", icone: "Trash2" },
  { id: "stats", label: "Statistiques", icone: "BarChart3" },
  { id: "challenge", label: "Challenge", emoji: "🏆" },
  { id: "mandataires", label: "Mandataires", icone: "Landmark", fullAdmin: true },
];
const ICONES_ONGLETS = { Home, FileText, Building2, Wallet, Trash2, BarChart3, Landmark };
const ORDRE_ONGLETS_DEFAUT = ONGLETS_ADMIN.map(o => o.id);
function lireOrdreOnglets() {
  try {
    const brut = JSON.parse(localStorage.getItem("adp:ordreOnglets") || "null");
    if (!Array.isArray(brut)) return ORDRE_ONGLETS_DEFAUT;
    // On repart toujours du catalogue : un onglet ajouté après coup doit
    // apparaître même si l'ordre enregistré date d'avant lui, et un onglet
    // supprimé ne doit pas laisser de trou.
    const gardes = brut.filter(id => ORDRE_ONGLETS_DEFAUT.includes(id));
    return [...gardes, ...ORDRE_ONGLETS_DEFAUT.filter(id => !gardes.includes(id))];
  } catch (e) { return ORDRE_ONGLETS_DEFAUT; }
}
function ecrireOrdreOnglets(ids) {
  try { localStorage.setItem("adp:ordreOnglets", JSON.stringify(ids)); } catch (e) { /* ignore */ }
}
function genCode() {
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}
function generateRecoveryCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = Math.random().toString(36).slice(2, 10).toUpperCase().padEnd(8, "X");
    codes.push({ code: `${raw.slice(0, 4)}-${raw.slice(4, 8)}`, used: false });
  }
  return codes;
}
function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.split(",")[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
// Réduit un logo avant de le ranger dans les données. Il est affiché en
// petit : le conserver en pleine définition alourdirait chaque enregistrement,
// puisque le bloc de données est relu et réécrit à chaque action.
// La transparence est préservée (PNG) ; une photo est convertie en JPEG.
function reduireImage(file, largeurMax = 320) {
  return new Promise((resolve, reject) => {
    const lecteur = new FileReader();
    lecteur.onerror = reject;
    lecteur.onload = () => {
      const img = new Image();
      img.onerror = reject;
      img.onload = () => {
        try {
          const ratio = Math.min(1, largeurMax / (img.width || largeurMax));
          const l = Math.max(1, Math.round((img.width || largeurMax) * ratio));
          const h = Math.max(1, Math.round((img.height || largeurMax) * ratio));
          const toile = document.createElement("canvas");
          toile.width = l; toile.height = h;
          const ctx = toile.getContext("2d");
          ctx.drawImage(img, 0, 0, l, h);
          const transparent = /png|webp|svg/i.test(file.type || "");
          const reduit = toile.toDataURL(transparent ? "image/png" : "image/jpeg", 0.85);
          // Si la réduction n'apporte rien (déjà minuscule), on garde l'original.
          resolve(reduit.length < lecteur.result.length ? reduit : lecteur.result);
        } catch (e) { resolve(lecteur.result); }
      };
      img.src = lecteur.result;
    };
    lecteur.readAsDataURL(file);
  });
}

function fileToDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
function fmtDate(ts) {
  return new Date(ts).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtSize(bytes) {
  if (!bytes) return "";
  return (bytes / 1024 / 1024).toFixed(1) + " Mo";
}
// Ancienneté lisible d'un élément en attente : c'est l'information qui dit
// s'il faut s'en occuper maintenant ou non.
function joursDepuis(ts) {
  if (!ts) return "";
  const h = Math.floor((Date.now() - ts) / 3600000);
  if (h < 1) return "à l'instant";
  if (h < 24) return `depuis ${h} h`;
  const j = Math.floor(h / 24);
  return `depuis ${j} j`;
}

// ── Mode discret ────────────────────────────────────────────────────────────
// En visio avec un futur partenaire, l'outil doit pouvoir se montrer sans
// montrer nos chiffres. Le drapeau est volontairement global : il est lu par
// les quelques fonctions par lesquelles passent TOUS les affichages sensibles
// (montants, noms de clients, noms de partenaires, logos de réseau). Une seule
// bascule suffit donc à couvrir l'application entière, sans avoir à retoucher
// les centaines d'endroits qui affichent une valeur.
// Aucun useMemo n'existe dans ce fichier : un simple re-rendu suffit à ce que
// tout soit recalculé avec le drapeau à jour.
let MODE_DISCRET = false;
function setModeDiscret(v) {
  MODE_DISCRET = !!v;
  try { localStorage.setItem("adp:discret", MODE_DISCRET ? "1" : "0"); } catch { /* navigation privée */ }
}
// Le mode est mémorisé : si la page se recharge en pleine démonstration,
// les chiffres ne réapparaissent pas à l'écran.
function initModeDiscret() {
  let v = false;
  try { v = localStorage.getItem("adp:discret") === "1"; } catch { v = false; }
  MODE_DISCRET = v;
  return v;
}
// Masque un compteur (effectifs, volumes) qui n'est pas un montant.
function masqueNb(n) {
  return MODE_DISCRET ? "•••" : n;
}
// Noms de substitution : plutôt qu'un pavé noir, on affiche une identité
// crédible et stable (le même dossier montre toujours le même faux nom),
// pour que la démonstration reste lisible et réaliste.
const NOMS_DEMO = ["MARTIN", "BERNARD", "DUBOIS", "THOMAS", "ROBERT", "RICHARD", "PETIT", "DURAND", "LEROY", "MOREAU", "SIMON", "LAURENT", "LEFEBVRE", "MICHEL", "GARCIA", "DAVID", "BERTRAND", "ROUX", "VINCENT", "FOURNIER"];
const PRENOMS_DEMO = ["Julie", "Marc", "Sophie", "Thomas", "Camille", "Nicolas", "Laura", "Julien", "Emma", "Antoine", "Chloé", "Maxime", "Léa", "Pierre", "Sarah", "Hugo", "Manon", "Lucas", "Inès", "Paul"];
const RESEAUX_DEMO = ["Agence Horizon", "Immo Panorama", "Cap Habitat", "Résidence & Co", "Atlas Immobilier", "Optima Immo", "Via Nova", "Le Clos Immobilier"];
function hachage(s) {
  let h = 0;
  const t = String(s || "");
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) >>> 0;
  return h;
}
function nomFictif(cle) {
  const h = hachage(cle);
  // Décalage NON signé : avec `>>` un hachage haut devient négatif et l'index
  // sort du tableau (prénom « undefined »).
  return `${NOMS_DEMO[h % NOMS_DEMO.length]} ${PRENOMS_DEMO[(h >>> 5) % PRENOMS_DEMO.length]}`;
}
function reseauFictif(cle) {
  return RESEAUX_DEMO[hachage(cle) % RESEAUX_DEMO.length];
}
// Nom de réseau / société affiché à l'écran.
function afficheReseau(c) {
  if (!c) return c;
  return MODE_DISCRET ? reseauFictif(c) : c;
}

function fmtEuro(n) {
  if (MODE_DISCRET) return "••• €";
  return (n || 0).toLocaleString("fr-FR", { style: "currency", currency: "EUR", maximumFractionDigits: 0 });
}
function fmtEuroPrecis(n) {
  if (MODE_DISCRET) return "••• €";
  return (n || 0).toLocaleString("fr-FR", { style: "currency", currency: "EUR", minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function up(s) {
  return (s || "").toUpperCase();
}
function clientName(d) {
  if (MODE_DISCRET) return nomFictif(d?.id || "");
  const full = `${(d.clientLastName || "").toUpperCase()} ${d.clientFirstName || ""}`.trim();
  return full || "(Sans nom)";
}
// Identité affichée d'un partenaire (ou d'un filleul). Point de passage unique
// pour que le mode discret n'en laisse échapper aucun.
function nomPartenaire(p) {
  if (!p) return "—";
  if (MODE_DISCRET) return nomFictif(p.id || p.email || p.name || "");
  return p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name);
}
const MOTIFS_REFUS = [
  "Ce confrère fait déjà partie du réseau FRANGOLA.",
  "Ce confrère a déjà été présenté antérieurement.",
  "Les coordonnées transmises sont incomplètes ou erronées.",
  "Le confrère ne souhaite pas donner suite.",
  "Autre",
];

function siretValide(siret) {
  const s = (siret || "").replace(/\D/g, "");
  if (s.length !== 14) return false;
  let somme = 0;
  for (let i = 0; i < 14; i++) {
    let n = Number(s[i]);
    if (i % 2 === 0) { n *= 2; if (n > 9) n -= 9; }
    somme += n;
  }
  return somme % 10 === 0;
}

function normaliseTel(t) {
  return (t || "").replace(/\D/g, "").slice(-9);
}

function mesDeclarations(partnerId) {
  return (_colorDataRef?.parrainages || [])
    .filter(p => p.parrainId === partnerId)
    .sort((a, b) => b.at - a.at);
}

// Ne bloque jamais : signale, l'arbitrage reste humain.
function detecterDoublon(decl) {
  if (!_colorDataRef) return { niveau: null, messages: [] };
  const messages = [];
  let niveau = null;
  const siret = (decl.siret || "").replace(/\D/g, "");
  const tel = normaliseTel(decl.telephone);
  const nom = (decl.nom || "").trim().toLowerCase();
  const reseau = (decl.reseau || "").trim().toLowerCase();

  for (const p of _colorDataRef.partners || []) {
    const memeSiret = siret && (p.siret || "").replace(/\D/g, "") === siret;
    const memeTel = tel && normaliseTel(p.telephone || p.phone) === tel;
    const nomP = (p.name || "").trim().toLowerCase();
    const reseauP = (p.company || "").trim().toLowerCase();
    const etiquette = `${p.firstName || ""} ${(p.name || "").toUpperCase()}`.trim();
    const etat = p.deleted ? " (supprimé)" : (p.active === false ? " (inactif)" : "");
    if (memeSiret) {
      niveau = "rouge";
      messages.push(`SIRET identique à ${etiquette}${etat}, inscrit le ${fmtDate(p.createdAt)}.`);
    } else if (memeTel) {
      niveau = "rouge";
      messages.push(`Téléphone identique à ${etiquette}${etat}, inscrit le ${fmtDate(p.createdAt)}.`);
    } else if (nom && nomP === nom && reseau && reseauP === reseau) {
      if (niveau !== "rouge") niveau = "orange";
      messages.push(`Même nom et même réseau que ${etiquette}${etat}.`);
    }
  }

  for (const d of _colorDataRef.parrainages || []) {
    if (d.id === decl.id || d.statut === "refuse") continue;
    const memeSiret = siret && (d.siret || "").replace(/\D/g, "") === siret;
    const memeTel = tel && normaliseTel(d.telephone) === tel;
    if ((memeSiret || memeTel) && d.at < decl.at) {
      niveau = "rouge";
      messages.push(`Déjà présenté par un autre partenaire le ${fmtDate(d.at)}.`);
    }
  }

  if (decl.siret && !siretValide(decl.siret)) {
    if (niveau !== "rouge") niveau = "orange";
    messages.push("Le numéro SIRET saisi est mal formé — à vérifier.");
  }

  return { niveau, messages };
}
// =============================================================================
// ÉCHÉANCIER D'ENCAISSEMENT
//
// Les honoraires ne rentrent pas à la signature. Soit Frangola facture le
// client en direct — encaissement immédiat —, soit l'assureur les collecte
// avec les mensualités et les reverse en 1 à 12 fois, la première un mois
// après la date d'effet du contrat.
//
// La rétrocession du partenaire et la prime du parrain suivent le même
// rythme : on ne verse que de l'argent réellement reçu.
//
// L'échéancier ne stocke que les DATES et ce qui est encaissé. Les montants
// se recalculent à partir du total, pour qu'une correction d'honoraires se
// répercute partout plutôt que de figer une valeur périmée.
// =============================================================================
const MODES_REGLEMENT = [
  { valeur: "direct", libelle: "Facturé au client en direct" },
  { valeur: "assureur", libelle: "Collecté par l'assureur" },
];

function libelleMode(valeur) {
  return (MODES_REGLEMENT.find(m => m.valeur === valeur) || {}).libelle || "Mode non défini";
}

// Répartit une somme en n parts égales au centime près, le reliquat tombant
// sur la dernière : 350 € en 12 fois donnent onze fois 29,17 € puis 29,13 €.
function repartir(total, n) {
  const centimes = Math.round((Number(total) || 0) * 100);
  const nb = Math.max(1, Math.min(12, Math.round(n) || 1));
  const part = Math.round(centimes / nb);
  const parts = Array(nb).fill(part);
  parts[nb - 1] = centimes - part * (nb - 1);
  return parts.map(c => c / 100);
}

function ajouterMois(dateIso, mois) {
  const d = new Date(dateIso + "T12:00:00");
  if (isNaN(d.getTime())) return null;
  const jour = d.getDate();
  d.setDate(1);
  d.setMonth(d.getMonth() + mois);
  // Un contrat à effet du 31 janvier n'a pas de 31 février : on retombe sur
  // le dernier jour du mois plutôt que de déborder sur le mois suivant.
  const dernier = new Date(d.getFullYear(), d.getMonth() + 1, 0).getDate();
  d.setDate(Math.min(jour, dernier));
  return d.toISOString().slice(0, 10);
}

// Construit les dates prévisionnelles. En direct, une seule échéance à la
// date d'effet. Par l'assureur, n échéances mensuelles à partir de
// date d'effet + 1 mois.
function genererEcheancier(dossier) {
  const mode = dossier.modeReglement || "direct";
  const nb = mode === "direct" ? 1 : Math.max(1, Math.min(12, dossier.nombreEcheances || 1));
  const base = dossier.dateEffet || null;
  const anciennes = dossier.echeances || [];
  return Array.from({ length: nb }, (_, i) => {
    const ancienne = anciennes[i];
    // Une échéance déjà encaissée, ou dont la date a été corrigée à la main,
    // n'est jamais réécrite par une régénération.
    if (ancienne && (ancienne.encaisseLe || ancienne.dateForcee)) return ancienne;
    const datePrevue = base ? (mode === "direct" ? base : ajouterMois(base, i + 1)) : null;
    return { numero: i + 1, datePrevue, encaisseLe: null, dateForcee: false };
  });
}

// Échéancier effectif d'un dossier. Les dossiers antérieurs à cette
// mécanique n'en ont pas : leur statut « Payé » vaut alors encaissement
// intégral, pour que l'historique reste juste.
function echeancesDe(dossier) {
  if (Array.isArray(dossier.echeances) && dossier.echeances.length > 0) return dossier.echeances;
  const paye = dossier.status === "Payé";
  return [{ numero: 1, datePrevue: dossier.paymentDate || null, encaisseLe: paye ? (dossier.paymentDate || null) : null, dateForcee: false, implicite: true, payeSansDate: paye }];
}

// Part encaissée d'un montant total, au prorata des échéances reçues.
function partEncaissee(dossier, total) {
  const ech = echeancesDe(dossier);
  const parts = repartir(total, ech.length);
  return ech.reduce((s, e, i) => s + ((e.encaisseLe || e.payeSansDate) ? parts[i] : 0), 0);
}

function partAVenir(dossier, total) {
  const ech = echeancesDe(dossier);
  const parts = repartir(total, ech.length);
  return ech.reduce((s, e, i) => s + ((e.encaisseLe || e.payeSansDate) ? 0 : parts[i]), 0);
}

// Date du dernier encaissement constaté — sert à dater le C.A. dans le temps.
function dernierEncaissement(dossier) {
  const dates = echeancesDe(dossier).map(e => e.encaisseLe).filter(Boolean);
  if (dates.length === 0) return null;
  return dates.sort().slice(-1)[0];
}

const PARRAINAGE_TAUX = 0.10;

function filleulsDe(partnerId) {
  if (!_colorDataRef || !partnerId) return [];
  return _colorDataRef.partners.filter(p => !p.deleted && p.parrainId === partnerId);
}

// C.A. réellement encaissé grâce à ce partenaire. Un dossier réglé en douze
// fois ne compte que pour les échéances déjà reçues : c'est ce qui autorise
// à verser la prime du parrain sans avancer d'argent.
function caGenerePar(partnerId) {
  if (!_colorDataRef) return 0;
  return _colorDataRef.dossiers
    .filter(d => d.partnerId === partnerId && d.status !== "KO")
    .reduce((s, d) => s + partEncaissee(d, d.caAmount || 0), 0);
}

// Toutes les échéances de rétrocession d'un partenaire, mises à plat et
// datées. C'est ce qui permet de lui montrer non seulement ce qu'il a touché,
// mais ce qui va tomber et quand.
// Calendrier mensuel des rétrocessions d'un partenaire : un mois par ligne,
// avec son état. « Réglé » quand l'ordre de virement est déposé, « à régler »
// quand Frangola a encaissé mais n'a pas encore reversé, « à venir » sinon.
// Apporteur hors immobilier : forfait fixe par contrat, réglé EN UNE FOIS dès
// que Frangola a encaissé au moins le montant du forfait sur ce dossier. Douze
// cartes cadeaux de huit euros n'auraient aucun sens — ni pour lui, ni pour la
// gestion.
function forfaitsRetrocession(partner, dossiers) {
  const versements = partner?.retrocessionVersements || [];
  const forfaitPartenaire = Number(partner?.flatFee) || 0;
  return (dossiers || [])
    .filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status))
    .map(d => {
      const montant = (d.commissionAmount || 0) > 0 ? d.commissionAmount : forfaitPartenaire;
      const encaisse = partEncaissee(d, d.caAmount || 0);
      const cle = "d:" + d.id;
      const versement = versements.find(v => (v.cle ?? v.mois) === cle) || null;
      const couvert = montant > 0 && encaisse + 0.005 >= montant;
      return {
        dossier: d, cle, libelle: clientName(d), montant, encaisse, couvert, versement,
        etat: versement ? "regle" : (couvert ? "a_regler" : "a_venir"),
      };
    })
    .filter(x => x.montant > 0);
}

function calendrierRetrocession(partner, dossiers) {
  const lignes = echeancesRetrocession(dossiers);
  const versements = partner?.retrocessionVersements || [];
  const mois = [];
  for (const l of lignes) {
    if (!l.datePrevue) continue;
    const cle = l.datePrevue.slice(0, 7);
    let m = mois.find(x => x.cle === cle);
    if (!m) {
      m = {
        cle, montant: 0, nb: 0, recus: 0,
        libelle: new Date(l.datePrevue + "T12:00:00").toLocaleDateString("fr-FR", { month: "long", year: "numeric" }),
      };
      mois.push(m);
    }
    m.montant += l.montant; m.nb += 1; if (l.recu) m.recus += 1;
  }
  for (const m of mois) {
    // Tolérance de lecture : les versements enregistrés avant le renommage
    // portent `mois` au lieu de `cle`. Les ignorer ferait repasser au jaune des
    // lignes déjà réglées, et l'ordre de virement deviendrait introuvable.
    m.versement = versements.find(v => (v.cle ?? v.mois) === m.cle) || null;
    m.encaisse = m.nb > 0 && m.recus === m.nb;
    m.etat = m.versement ? "regle" : (m.encaisse ? "a_regler" : "a_venir");
  }
  mois.sort((a, b) => a.cle.localeCompare(b.cle));
  const sansDate = lignes.filter(l => !l.datePrevue).length;
  return { mois, sansDate };
}

function echeancesRetrocession(dossiers) {
  return (dossiers || []).filter(d => d.status !== "KO").flatMap(d => {
    const ech = echeancesDe(d);
    const parts = repartir(d.commissionAmount || 0, ech.length);
    return ech.map((e, i) => ({
      cle: d.id + "-" + (e.numero || i + 1),
      dossier: d,
      numero: e.numero || i + 1,
      total: ech.length,
      montant: parts[i],
      datePrevue: e.datePrevue,
      encaisseLe: e.encaisseLe || null,
      recu: !!(e.encaisseLe || e.payeSansDate),
    }));
  });
}

// Ce que le partenaire a déjà gagné, et ce qui lui reste à venir.
function remunerationEncaissee(dossier) {
  return partEncaissee(dossier, dossier.commissionAmount || 0);
}
function remunerationAVenir(dossier) {
  if (dossier.status === "KO") return 0;
  return partAVenir(dossier, dossier.commissionAmount || 0);
}

function bilanParrainage(partnerId) {
  const filleuls = filleulsDe(partnerId).map(f => {
    const ca = caGenerePar(f.id);
    const dossiers = (_colorDataRef?.dossiers || []).filter(d => d.partnerId === f.id).length;
    return { partner: f, ca, dossiers, gain: ca * PARRAINAGE_TAUX };
  });
  return {
    filleuls,
    actifs: filleuls.filter(f => f.dossiers > 0).length,
    caTotal: filleuls.reduce((s, f) => s + f.ca, 0),
    gainTotal: filleuls.reduce((s, f) => s + f.gain, 0),
  };
}

function nomParrain(partnerId) {
  const p = _colorDataRef?.partners.find(x => x.id === partnerId);
  if (!p) return null;
  return nomPartenaire(p);
}

function CoEmprunteurBadge({ d }) {
  if (!d.hasCoEmprunteur) return null;
  const full = `${(d.coClientLastName || "").toUpperCase()} ${d.coClientFirstName || ""}`.trim();
  return (
    <span className="text-xs bg-violet-50 border border-violet-200 text-violet-700 px-2 py-0.5 rounded-full font-medium">
      👥 Co-emprunteur : {full || "non renseigné"}{d.coClientPhone && ` · ${d.coClientPhone}`}
    </span>
  );
}

async function loadFile(key) {
  try {
    const res = await storage.get(key, true);
    if (!res || !res.value) return null;
    return JSON.parse(res.value);
  } catch (e) {
    return null;
  }
}
// N'existent que sur le vrai site (build Vite) — restent null dans le bac à sable Claude,
// où la fonction d'analyse IA n'est de toute façon pas déployée.
const SUPABASE_URL = (typeof import.meta !== "undefined" ? import.meta.env?.VITE_SUPABASE_URL : null) || null;
const SUPABASE_ANON_KEY = (typeof import.meta !== "undefined" ? import.meta.env?.VITE_SUPABASE_ANON_KEY : null) || null;
async function downloadStoredFile(key, fallbackName) {
  const file = await loadFile(key);
  if (!file) return;
  const link = document.createElement("a");
  link.href = `data:${file.mime || "application/pdf"};base64,${file.data}`;
  link.download = file.name || fallbackName || "document.pdf";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

async function previewStoredFile(key) {
  const file = await loadFile(key);
  if (!file) return;
  const mime = file.mime || "application/pdf";
  const byteChars = atob(file.data);
  const byteNumbers = new Array(byteChars.length);
  for (let i = 0; i < byteChars.length; i++) byteNumbers[i] = byteChars.charCodeAt(i);
  const blob = new Blob([new Uint8Array(byteNumbers)], { type: mime });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

function csvEscape(val) {
  const s = String(val ?? "");
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function downloadCsv(filename, rows) {
  const csv = rows.map(row => row.map(csvEscape).join(";")).join("\r\n");
  const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
function exportDossiersCsv(dossiers, partners) {
  const partnerName = (id) => { const p = partners.find(p => p.id === id); return p ? (nomPartenaire(p)) : "—"; };
  const rows = [
    ["Client Nom", "Client Prénom", "Client Téléphone", "Partenaire", "Statut", "Déposé le", "Dernière mise à jour", "CA généré (€)", "Rétrocession (€)", "Mode de paiement", "Date de paiement", "Notes"],
    ...dossiers.map(d => [d.clientLastName, d.clientFirstName, d.clientPhone || "", partnerName(d.partnerId), d.status, fmtDate(d.createdAt), fmtDate(d.updatedAt || d.createdAt), d.caAmount ?? "", d.commissionAmount ?? "", d.paymentMethod || "", d.paymentDate || "", d.notes || ""]),
  ];
  downloadCsv(`frangola-adp-dossiers-${new Date().toISOString().slice(0, 10)}.csv`, rows);
}
function exportPartnersCsv(partners) {
  const rows = [
    ["Nom", "Prénom", "Agence", "Ville", "Code postal", "Département", "Email", "Commercial", "Statut", "Créé le"],
    ...partners.map(p => [p.name, p.firstName || "", p.company || "", p.ville || "", p.postalCode || "", p.departement || "", p.email || "", p.commercial || "", p.active === false ? "Inactif" : "Actif", fmtDate(p.createdAt)]),
  ];
  downloadCsv(`frangola-adp-partenaires-${new Date().toISOString().slice(0, 10)}.csv`, rows);
}

const BRAND_STYLES = `
@import url('https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600;700&family=Nunito:wght@400;600;700;800&display=swap');
/* Mode discret : les graphiques n'ont pas de point de passage commun où
   masquer leurs valeurs, on les floute donc en bloc. */
.mode-discret .recharts-wrapper,
.mode-discret .recharts-surface { filter: blur(7px); }
:root{
  --fa-teal:#008BA8;
  --fa-teal-dark:#006C82;
  --fa-navy:#1C2243;
  --fa-pink:#FAD3D1;
  --fa-offwhite:#F3F3F3;
  --fa-gold:#FCD947;
  --fa-gold-dark:#F0C61A;
}
.font-display{ font-family:'Fredoka', sans-serif; }
.font-body{ font-family:'Nunito', sans-serif; }
.fa-navy{ color:var(--fa-navy) !important; }
.fa-teal-text{ color:var(--fa-teal) !important; }
.fa-bg-teal{ background:var(--fa-teal) !important; color:#fff; }
.fa-bg-teal:hover{ background:var(--fa-teal-dark) !important; }
.fa-bg-offwhite{ background:var(--fa-offwhite) !important; }
.fa-bg-gold{ background:var(--fa-gold) !important; color:var(--fa-navy); }
.fa-bg-gold:hover{ background:var(--fa-gold-dark) !important; }
.fa-bg-pink{ background:var(--fa-pink) !important; }

/* Confort mobile : évite le zoom automatique d'iPhone sur les champs de saisie */
input, select, textarea{ font-size:16px; }
@media (min-width: 640px){
  input, select, textarea{ font-size:14px; }
}

/* Confort mobile : cibles tactiles plus généreuses pour les petits boutons texte */
.fa-tap{ padding-top:8px; padding-bottom:8px; min-height:36px; display:inline-flex; align-items:center; }
`;

function SunburstLogo({ size = 34 }) {
  const rays = Array.from({ length: 12 });
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" className="shrink-0">
      <g stroke="var(--fa-gold)" strokeWidth="7" strokeLinecap="round">
        {rays.map((_, i) => {
          const angle = (i / 12) * 2 * Math.PI - Math.PI / 2;
          const r1 = 30, r2 = i % 2 === 0 ? 46 : 40;
          const x1 = 50 + r1 * Math.cos(angle), y1 = 50 + r1 * Math.sin(angle);
          const x2 = 50 + r2 * Math.cos(angle), y2 = 50 + r2 * Math.sin(angle);
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} />;
        })}
      </g>
      <circle cx="50" cy="50" r="22" fill="var(--fa-gold)" />
      <path d="M14 62c10-10 26-10 36 0s26 10 36 0v14c-10 10-26 10-36 0s-26-10-36 0z" fill="var(--fa-teal)" />
    </svg>
  );
}

function Logo({ size = "text-2xl", withMark = true }) {
  return (
    <div className={`font-display font-semibold ${size} tracking-tight fa-navy flex items-center gap-2`}>
      {withMark && <SunburstLogo size={size === "text-lg" ? 26 : 34} />}
      <span>Frangola <span className="fa-teal-text">ADP</span></span>
    </div>
  );
}

function StatusBadge({ status }) {
  return (
    <span className={`inline-block text-xs font-semibold px-2.5 py-1 rounded-full border ${STATUS_COLORS[status] || "bg-gray-100 text-gray-700 border-gray-300"}`}>
      {status}
    </span>
  );
}

// Un dossier au statut « Payé » dont les honoraires rentrent en douze fois
// n'est pas soldé. Afficher « Payé » seul ferait croire au partenaire que tout
// est versé, et le premier relevé bancaire démentirait l'application.
// État de paiement d'un dossier, utilisé par la pastille et par le tri.
function etatPaiement(dossier) {
  if (!dossier || dossier.status === "KO") return "ko";
  if (!STATUTS_CONTRAT_VIVANT.includes(dossier.status)) return "encours";
  const total = dossier.caAmount || 0;
  if (total <= 0) return "encours";
  const recu = partEncaissee(dossier, total);
  if (recu / total >= 0.9999) return "solde";
  return recu > 0.005 ? "partiel" : "avenir";
}

function PaiementBadge({ dossier }) {
  const etat = etatPaiement(dossier);
  if (etat === "ko" || etat === "encours") return null;

  const total = dossier.caAmount || 0;
  const recu = partEncaissee(dossier, total);
  const pct = Math.round((recu / total) * 100);
  const ech = echeancesDe(dossier);

  if (etat === "solde") {
    return (
      <span className="inline-block text-xs font-semibold px-2.5 py-1 rounded-full border bg-emerald-50 text-emerald-700 border-emerald-300">
        Soldé
      </span>
    );
  }
  if (etat === "partiel") {
    return (
      <span className="inline-block text-xs font-semibold px-2.5 py-1 rounded-full border bg-amber-50 text-amber-800 border-amber-300"
        title={`${fmtEuroPrecis(recu)} reçus sur ${fmtEuroPrecis(total)}`}>
        Paiement partiel {pct} %
      </span>
    );
  }
  return (
    <span className="inline-block text-xs font-semibold px-2.5 py-1 rounded-full border bg-gray-100 text-gray-600 border-gray-300"
      title={ech.length > 1 ? `Réglé en ${ech.length} fois — rien encore reçu` : "Aucun encaissement enregistré"}>
      Paiement à venir
    </span>
  );
}

function Stepper({ status }) {
  if (status === "KO") {
    const koSteps = ["Déposé", "En vérification", "Devis en cours", "KO"];
    const koProgress = Math.round(((koSteps.length - 1) / STATUS_STEPS.length) * 100);
    return (
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs font-semibold text-red-700">Clôturé sans suite</span>
          <span className="text-xs font-semibold text-red-700">{koProgress}%</span>
        </div>
        <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden mb-3">
          <div className="h-full bg-red-500 transition-all" style={{ width: `${koProgress}%` }} />
        </div>
        <div className="flex items-center w-full">
        {koSteps.map((s, i) => {
          const isLast = i === koSteps.length - 1;
          return (
            <div key={s} className="flex items-center flex-1 last:flex-none">
              <div className="flex flex-col items-center gap-1 min-w-[64px]">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2
                  ${isLast ? "bg-red-600 border-red-600 text-white" : "bg-teal-700 border-teal-700 text-white"}`}>
                  {isLast ? <X size={14} /> : <Check size={14} />}
                </div>
                <span className={`text-[10px] text-center leading-tight ${isLast ? "text-red-700 font-semibold" : "fa-teal-text font-medium"}`}>{s}</span>
              </div>
              {!isLast && <div className="h-0.5 flex-1 mx-1 bg-teal-700" />}
            </div>
          );
        })}
        </div>
      </div>
    );
  }
  const idx = STATUS_STEPS.indexOf(status);
  const progress = Math.round(((idx + 1) / STATUS_STEPS.length) * 100);
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-semibold fa-teal-text">Avancement du dossier</span>
        <span className="text-xs font-semibold fa-teal-text">{progress}%</span>
      </div>
      <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden mb-3">
        <div className="h-full fa-bg-teal transition-all" style={{ width: `${progress}%` }} />
      </div>
      <div className="flex items-center w-full">
      {STATUS_STEPS.map((s, i) => (
        <div key={s} className="flex items-center flex-1 last:flex-none">
          <div className="flex flex-col items-center gap-1 min-w-[64px]">
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2
              ${i <= idx ? "bg-teal-700 border-teal-700 text-white" : "bg-white border-gray-300 text-gray-400"}`}>
              {i < idx ? <Check size={14} /> : i + 1}
            </div>
            <span className={`text-[10px] text-center leading-tight ${i <= idx ? "fa-teal-text font-medium" : "text-gray-400"}`}>{s}</span>
          </div>
          {i < STATUS_STEPS.length - 1 && (
            <div className={`h-0.5 flex-1 mx-1 ${i < idx ? "bg-teal-700" : "bg-gray-200"}`} />
          )}
        </div>
      ))}
      </div>
    </div>
  );
}

function FileDrop({ label, file, onChange, required }) {
  return (
    <div>
      <label className="block text-sm font-medium fa-navy mb-1">
        {label} {required && <span className="text-amber-600">*</span>}
      </label>
      <div className={`w-full flex items-center gap-2 border-2 border-dashed rounded-xl px-4 py-3 text-sm transition
          ${file ? "border-teal-400 bg-teal-50 fa-teal-text" : "border-gray-300 hover:border-teal-400 text-gray-500"}`}>
        <label className="flex items-center gap-2 flex-1 min-w-0 cursor-pointer">
          {file ? <FileCheck2 size={18} className="text-teal-600 shrink-0" /> : <Upload size={18} className="shrink-0" />}
          <span className="truncate">{file ? file.name : "Choisir un fichier PDF"}</span>
          <input type="file" accept="application/pdf,image/*" className="hidden"
            onChange={(e) => onChange(e.target.files?.[0] || null)} />
        </label>
        {file && (
          <button type="button" onClick={() => onChange(null)} className="fa-tap text-teal-600 hover:text-red-600 shrink-0" title="Retirer le fichier">
            <X size={16} />
          </button>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [view, setView] = useState("landing");
  const [currentPartner, setCurrentPartner] = useState(null);
  const [currentAdmin, setCurrentAdmin] = useState(null);
  const [currentMandataire, setCurrentMandataire] = useState(null);
  const [globalError, setGlobalError] = useState("");
  const [apercuPartnerId, setApercuPartnerId] = useState(null);
  const [busy, setBusy] = useState(false);

  const [loadError, setLoadError] = useState(false);
  useEffect(() => { if (data) setColorDataRef(data); }, [data]);

  // ==========================================================================
  // DÉMARRAGE — l'authentification d'abord, les données ensuite
  //
  // Auparavant les données étaient chargées avant même l'écran de connexion :
  // n'importe qui pouvait donc les lire sans compte. Désormais rien n'est lu
  // tant que Supabase n'a pas reconnu la personne.
  // ==========================================================================
  const [authUser, setAuthUser] = useState(null);
  const [authPret, setAuthPret] = useState(false);

  useEffect(() => {
    purgeAncienneSession();
    let vivant = true;
    supabase.auth.getSession().then(({ data: s }) => {
      if (!vivant) return;
      setAuthUser(s?.session?.user || null);
      setAuthPret(true);
    }).catch(() => { if (vivant) setAuthPret(true); });
    const { data: abo } = supabase.auth.onAuthStateChange((_evt, session) => {
      setAuthUser(session?.user || null);
    });
    return () => { vivant = false; abo?.subscription?.unsubscribe?.(); };
  }, []);

  const emailConnecte = (authUser?.email || "").trim().toLowerCase();

  // --- Chargement des données, uniquement une fois authentifié
  useEffect(() => {
    if (!authPret) return;
    if (!authUser) { setData(null); setLoadError(false); setLoading(false); return; }
    let vivant = true;
    setLoading(true); setLoadError(false);
    (async () => {
      try {
        const res = await storage.get("adp:data", true);
        // Une absence de données ne peut plus signifier « premier démarrage » :
        // avec les règles d'accès, elle signifie « lecture refusée ». On ne
        // réinitialise donc JAMAIS ici, sous peine de tout effacer.
        if (!res || !res.value) { if (vivant) setLoadError(true); return; }
        const loaded = JSON.parse(res.value);
        let changed = false;
        if (!loaded.settings) loaded.settings = {};
        if (!loaded.mandataires) { loaded.mandataires = []; changed = true; }
        if (!loaded.reseaux) { loaded.reseaux = []; changed = true; }
        if (!loaded.partners) { loaded.partners = []; changed = true; }
        if (!loaded.dossiers) { loaded.dossiers = []; changed = true; }
        if (!loaded.parrainages) { loaded.parrainages = []; changed = true; }
        if (!loaded.activityLog) { loaded.activityLog = []; changed = true; }
        if (loaded.mandataires.some(m => !m.role)) {
          loaded.mandataires = loaded.mandataires.map(m => m.role ? m : { ...m, role: /^nelson$/i.test((m.name || "").trim()) ? "manager" : "standard" });
          changed = true;
        }
        if (!loaded.settings.admin) { loaded.settings.admin = { email: "contact@frangola.fr", color: "#2F448B" }; changed = true; }
        if (!loaded.settings.admin.color) { loaded.settings.admin.color = "#2F448B"; changed = true; }
        if (changed) { try { await storage.set("adp:data", JSON.stringify(loaded), true); } catch (e) { /* lecture seule : on continue */ } }
        if (vivant) { revRef.current = loaded.rev ?? 0; setData(loaded); }
      } catch (e) {
        console.error("Échec du chargement des données :", e);
        if (vivant) setLoadError(true);
      } finally { if (vivant) setLoading(false); }
    })();
    return () => { vivant = false; };
  }, [authPret, authUser?.id]);

  // --- Qui est cette personne ? Le rôle se déduit des données, pas du bouton
  //     sur lequel elle a cliqué à l'accueil.
  const [pendingAuth, setPendingAuth] = useState(null);
  const roleResolu = useRef(null);

  useEffect(() => {
    if (!data || !authUser) return;
    if (roleResolu.current === authUser.id) return;
    roleResolu.current = authUser.id;

    // Le second facteur n'est sauté que si TROIS conditions sont réunies :
    // il est déjà configuré, la personne a coché « se souvenir » sur CETTE
    // machine, et la marque n'a pas expiré.
    const passeLeSecondFacteur = (kind, compte) =>
      !!(compte?.totpEnabled && compte?.totpSecret && appareilReconnu(cleAppareil(kind, compte)));

    if (emailConnecte && emailConnecte === (data.settings?.admin?.email || "").trim().toLowerCase()) {
      const adm = data.settings.admin;
      if (passeLeSecondFacteur("admin", adm)) {
        setCurrentAdmin(true); setView("adminDash");
        updateAdmin({ lastLoginAt: Date.now() });
        sauvegardeAuto(data);
      } else {
        setPendingAuth({ kind: "admin", account: adm });
      }
      return;
    }
    const m = data.mandataires.find(x => !x.deleted && (x.email || "").trim().toLowerCase() === emailConnecte);
    if (m) {
      if (m.active === false) { deconnexion("desactive"); return; }
      if (passeLeSecondFacteur("mandataire", m)) {
        setCurrentMandataire(m); setView("mandataireDash");
        updateMandataire(m.id, { lastLoginAt: Date.now() });
      } else {
        setPendingAuth({ kind: "mandataire", account: m });
      }
      return;
    }
    const p = data.partners.find(x => !x.deleted && (x.email || "").trim().toLowerCase() === emailConnecte);
    if (p) {
      if (p.active === false) { deconnexion("desactive"); return; }
      setCurrentPartner(p); setView("partnerDash");
      updatePartner(p.id, { lastLoginAt: Date.now() });
      return;
    }
    deconnexion("sansFiche");
  }, [data, authUser, emailConnecte]);

  // Numéro de version réellement écrit, mis à jour immédiatement après chaque
  // enregistrement réussi. React met son état à jour de façon différée : s'y
  // fier faisait refuser à tort la deuxième écriture d'une même action.
  const revRef = useRef(null);

  // Écrit en repartant TOUJOURS de l'état réellement stocké, jamais de la copie
  // chargée au démarrage — sinon deux personnes connectées en même temps
  // s'écrasent mutuellement (partenaire disparu, Authenticator réinitialisé).
  async function mutateData(mutator) {
    let base = data;
    try {
      const res = await storage.get("adp:data", true);
      if (res && res.value) base = JSON.parse(res.value);
    } catch (e) {
      setGlobalError("Impossible de relire les données — modification annulée.");
      return false;
    }
    const next = mutator(base);
    if (!next) return false;
    const versionne = { ...next, rev: (base?.rev ?? 0) + 1 };
    setData(versionne);
    try {
      await storage.set("adp:data", JSON.stringify(versionne), true);
      revRef.current = versionne.rev;
      return true;
    } catch (e) {
      setGlobalError("Échec de l'enregistrement — réessaie.");
      return false;
    }
  }
  function withLog(nextData, message) {
    const actor = currentAdmin ? "Sébastien" : (currentMandataire?.firstName || currentMandataire?.name || "Inconnu");
    const entry = { id: uid(), at: Date.now(), actor, message };
    const base = nextData.activityLog || data.activityLog || [];
    return { ...nextData, activityLog: [entry, ...base].slice(0, 300) };
  }

  const [logoutReason, setLogoutReason] = useState(null);
  // Ferme la session côté Supabase ET côté application. Tant que la session
  // Supabase n'est pas fermée, un rechargement de page reconnecterait la
  // personne : c'est elle qui fait foi maintenant, plus l'état React.
  async function deconnexion(reason) {
    roleResolu.current = null;
    setPendingAuth(null);
    setCurrentPartner(null); setCurrentAdmin(null); setCurrentMandataire(null);
    setApercuPartnerId(null);
    setData(null);
    setView("landing");
    setLogoutReason(reason || null);
    purgeAncienneSession();
    try { await supabase.auth.signOut(); } catch (e) { /* session déjà close */ }
  }
  function logout(reason) { deconnexion(reason); }

  const INACTIVITY_LIMIT_MS = 60 * 60 * 1000; // 1 heure
  const lastActivityRef = useRef(Date.now());
  const isLoggedIn = !!(currentAdmin || currentMandataire || currentPartner);
  useEffect(() => {
    if (!isLoggedIn) return;
    lastActivityRef.current = Date.now();
    const markActive = () => { lastActivityRef.current = Date.now(); };
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    events.forEach(ev => window.addEventListener(ev, markActive, { passive: true }));
    const interval = setInterval(() => {
      if (Date.now() - lastActivityRef.current > INACTIVITY_LIMIT_MS) logout("inactivity");
    }, 30000);
    return () => {
      events.forEach(ev => window.removeEventListener(ev, markActive));
      clearInterval(interval);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoggedIn]);

    // Dépose une copie horodatée des données, une par jour, 7 jours glissants.
  async function sauvegardeAuto(donnees) {
    if (!donnees) return;
    const jour = new Date().toISOString().slice(0, 10);
    try {
      const existant = await storage.list("adp:backup:", true);
      const cles = (existant?.keys || []).sort();
      if (cles.includes("adp:backup:" + jour)) return;
      await storage.set("adp:backup:" + jour, JSON.stringify({
        at: Date.now(),
        partenaires: donnees.partners?.length || 0,
        dossiers: donnees.dossiers?.length || 0,
        data: donnees,
      }), true);
      const apres = [...cles, "adp:backup:" + jour].sort();
      for (const vieille of apres.slice(0, Math.max(0, apres.length - 7))) {
        try { await storage.delete(vieille, true); } catch (e) { /* ignore */ }
      }
    } catch (e) {
      console.error("Sauvegarde automatique impossible :", e);
    }
  }
  async function updateAdmin(fields) {
    await mutateData(base => ({ ...base, settings: { ...base.settings, admin: { ...base.settings.admin, ...fields } } }));
  }

  async function addMandataire(fields) {
    const m = { id: uid(), ...fields, code: genCode(), active: true, createdAt: Date.now() };
    await mutateData(base => withLog({ ...base, mandataires: [...base.mandataires, m] }, `a ajouté le mandataire ${fields.name}`));
    return m;
  }

  async function updateMandataire(id, fields) {
        await mutateData(base => ({
      ...base,
      mandataires: base.mandataires.map(m => m.id === id ? { ...m, ...fields } : m),
    }));
  }

   // Réinitialise le second facteur d'un mandataire : il reconfigurera son
  // application d'authentification à sa prochaine connexion.
    async function declarerParrainage(parrainId, fields) {
    const decl = {
      id: uid(), parrainId, ...fields,
      at: Date.now(), statut: "en_attente", motif: "",
    };
    return await mutateData(base => ({
      ...base,
      parrainages: [...(base.parrainages || []), decl],
    }));
  }

  // Valider une déclaration crée directement la fiche du filleul, déjà
  // rattachée à son parrain : il ne reste qu'à compléter ce qui manque.
  async function traiterParrainage(id, statut, motif) {
    await mutateData(base => {
      const decl = (base.parrainages || []).find(p => p.id === id);
      let partners = base.partners;
      let partnerId = null;

      if (statut === "valide" && decl && !decl.partnerId) {
        const parrain = base.partners.find(p => p.id === decl.parrainId);
        const nouveau = {
          id: uid(),
          name: decl.nom || "",
          firstName: decl.prenom || "",
          company: decl.reseau || "",
          telephone: decl.telephone || "",
          siret: decl.siret || "",
          email: "",
          ville: "", postalCode: "", departement: "",
          commercial: parrain?.commercial || "Sébastien",
          parrainId: decl.parrainId || null,
          issuDuParrainage: true,
          active: true,
          code: genCode(),
          createdAt: Date.now(),
        };
        partnerId = nouveau.id;
        partners = [...base.partners, nouveau];
      }

      const etiquette = decl ? `${decl.prenom || ""} ${(decl.nom || "").toUpperCase()}`.trim() : "";
      return withLog({
        ...base,
        partners,
        parrainages: (base.parrainages || []).map(p => p.id === id
          ? { ...p, statut, motif: motif || "", traiteAt: Date.now(), ...(partnerId ? { partnerId } : {}) }
          : p),
      }, statut === "valide"
        ? `a validé le parrainage de ${etiquette} et créé sa fiche partenaire`
        : `a refusé le parrainage de ${etiquette}`);
    });
  }
  // Challenge à destination des partenaires : un objectif, une récompense,
  // une période. Compté en dossiers SOUSCRITS — c'est le seul critère qui
  // aligne sa motivation sur celle de Frangola.
  async function setAssureurs(liste) {
    await mutateData(base => ({
      ...base,
      settings: { ...base.settings, assureurs: liste },
    }));
  }

  async function setChallengePartenaires(fields) {
    await mutateData(base => ({
      ...base,
      settings: {
        ...base.settings,
        challengePartenaires: { ...(base.settings.challengePartenaires || {}), ...fields },
      },
    }));
  }

  async function setChallengeGoals(fields) {
    await mutateData(base => ({
      ...base,
      settings: {
        ...base.settings,
        challenge: { ...(base.settings.challenge || {}), ...fields },
      },
    }));
  }
  async function resetMandataireTotp(id) {
    const m = data.mandataires.find(m => m.id === id);
    await mutateData(base => withLog({
      ...base,
      mandataires: base.mandataires.map(x => x.id === id
        ? { ...x, totpSecret: null, totpEnabled: false, recoveryCodes: [] }
        : x),
    }, `a réinitialisé l'authentification de ${m?.name || ""}`));
  }
  async function deleteMandataire(id) {
    await mutateData(base => {
      const m = base.mandataires.find(m => m.id === id);
      const mandataires = base.mandataires.map(m => m.id === id ? { ...m, deleted: true, deletedAt: Date.now() } : m);
      return withLog({ ...base, mandataires }, `a supprimé le mandataire ${m?.name || ""}`);
    });
  }

  async function restoreMandataire(id) {
    await mutateData(base => {
      const m = base.mandataires.find(m => m.id === id);
      const mandataires = base.mandataires.map(m => m.id === id ? { ...m, deleted: false, deletedAt: null } : m);
      return withLog({ ...base, mandataires }, `a restauré le mandataire ${m?.name || ""}`);
    });
  }

  async function addPartner(fields) {
    const p = { id: uid(), ...fields, active: true, code: genCode(), createdAt: Date.now() };
    await mutateData(base => withLog({ ...base, partners: [...base.partners, p] }, `a ajouté le partenaire ${fields.name}`));
    return p;
  }

  async function updatePartner(id, fields) {
       await mutateData(base => ({
      ...base,
      partners: base.partners.map(p => p.id === id ? { ...p, ...fields } : p),
    }));
  }

  async function setPartnerGoal(partnerId, monthlyGoal) {
    await mutateData(base => ({
      ...base,
      partners: base.partners.map(p => p.id === partnerId ? { ...p, monthlyGoal } : p),
    }));
  }

  // Contrat de partenariat commun à tout le réseau. Déposé une fois, il sert
  // à tous : à cent partenaires, on ne gère pas cent PDF différents.
  async function uploadContratType(file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const key = "adp:file:" + uid();
      await storage.set(key, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      return await mutateData(base => ({
        ...base,
        settings: { ...base.settings, contratType: { name: file.name, key, at: Date.now() } },
      }));
    } finally { setBusy(false); }
  }

  async function uploadPartnerContract(partnerId, file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      await mutateData(base => ({
        ...base,
        partners: base.partners.map(p => p.id === partnerId
          ? { ...p, contractFile: { name: file.name, key: fileKey, size: file.size, uploadedAt: Date.now() } }
          : p),
      }));
      return true;
    } finally { setBusy(false); }
  }

  // Le partenaire dépose sa facture de commission ; l'admin en suit le paiement.
  async function uploadFacture(partnerId, file, montant) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      const facture = {
        id: uid(), name: file.name, key: fileKey, size: file.size,
        at: Date.now(), statut: "Déposée", motif: "",
        montant: montant === "" || montant == null ? null : Number(montant),
      };
      const ok = await mutateData(base => ({
        ...base,
        partners: base.partners.map(p => p.id === partnerId
          ? { ...p, factures: [...(p.factures || []), facture] }
          : p),
      }));
      return ok !== false;
    } finally { setBusy(false); }
  }

  // Un versement s'ajoute à un historique daté : un simple cumul ne permet
  // ni de justifier un paiement, ni de retrouver ce qui a été réglé quand.
  // Règlement d'une échéance de rétrocession à un partenaire, mois par mois.
  // L'ordre de virement est joint : le partenaire n'a pas à demander la preuve,
  // il la télécharge depuis son calendrier.
  async function enregistrerVirementPartenaire(partnerId, cle, libelle, montant, dateVirement, file, mode) {
    if (!cle || !dateVirement) { setGlobalError("Échéance et date de règlement requises."); return false; }
    setBusy(true);
    try {
      let ordre = null;
      if (file) {
        if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return false; }
        const b64 = await fileToBase64(file);
        const key = "adp:file:" + uid();
        await storage.set(key, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
        ordre = { name: file.name, key, size: file.size };
      }
      const versement = { id: uid(), cle, libelle: libelle || cle, montant: Number(montant) || 0, dateVirement, ordre, mode: mode || "Virement", at: Date.now() };
      return await mutateData(base => withLog({
        ...base,
        partners: base.partners.map(p => p.id === partnerId
          ? { ...p, retrocessionVersements: [...(p.retrocessionVersements || []).filter(v => (v.cle ?? v.mois) !== cle), versement] }
          : p),
      }, `a réglé la rétrocession « ${libelle || cle} » à un partenaire`));
    } finally { setBusy(false); }
  }

  async function annulerVirementPartenaire(partnerId, versementId) {
    return await mutateData(base => ({
      ...base,
      partners: base.partners.map(p => p.id === partnerId
        ? { ...p, retrocessionVersements: (p.retrocessionVersements || []).filter(v => v.id !== versementId) }
        : p),
    }));
  }

  async function addVersementParrainage(partnerId, montant, note) {
    const valeur = Number(montant);
    if (!valeur || valeur <= 0) return false;
    const versement = { id: uid(), at: Date.now(), montant: valeur, note: (note || "").trim() };
    return await mutateData(base => ({
      ...base,
      partners: base.partners.map(p => p.id === partnerId
        ? { ...p, parrainageVersements: [...(p.parrainageVersements || []), versement] }
        : p),
    }));
  }

  async function setFactureStatut(partnerId, factureId, statut, motif) {
    await mutateData(base => ({
      ...base,
      partners: base.partners.map(p => p.id === partnerId
        ? {
            ...p,
            factures: (p.factures || []).map(f => f.id === factureId
              ? { ...f, statut, motif: motif || "", traiteAt: Date.now() }
              : f),
          }
        : p),
    }));
  }

  async function uploadPartnerRib(partnerId, file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      await mutateData(base => ({
        ...base,
        partners: base.partners.map(p => p.id === partnerId
          ? { ...p, ribFile: { name: file.name, key: fileKey, size: file.size, uploadedAt: Date.now() } }
          : p),
      }));
      return true;
    } finally { setBusy(false); }
  }

  async function uploadReseauLogo(reseauName, file) {
    const name = reseauName.trim();
    if (!name) return false;
    if (!/^image\//.test(file.type || "")) { setGlobalError(`"${file.name}" n'est pas une image.`); return false; }
    if (file.size > 8 * 1024 * 1024) { setGlobalError(`"${file.name}" dépasse 8 Mo — utilise une image plus légère.`); return false; }
    setBusy(true);
    try {
      let dataUrl;
      try { dataUrl = await reduireImage(file); }
      catch (e) { dataUrl = await fileToDataURL(file); }
      await mutateData(base => {
        const existing = base.reseaux.find(r => r.name.trim().toLowerCase() === name.toLowerCase());
        const reseaux = existing
          ? base.reseaux.map(r => r === existing ? { ...r, logoData: dataUrl, uploadedAt: Date.now() } : r)
          : [...base.reseaux, { id: uid(), name, logoData: dataUrl, uploadedAt: Date.now() }];
        return { ...base, reseaux };
      });
      return true;
    } finally { setBusy(false); }
  }

  async function removeReseauLogo(reseauName) {
    const name = reseauName.trim().toLowerCase();
    await mutateData(base => ({
      ...base,
      reseaux: base.reseaux.filter(r => r.name.trim().toLowerCase() !== name),
    }));
  }

  async function deletePartner(id) {
    await mutateData(base => {
      const p = base.partners.find(p => p.id === id);
      const partners = base.partners.map(p => p.id === id ? { ...p, deleted: true, deletedAt: Date.now() } : p);
      return withLog({ ...base, partners }, `a supprimé le partenaire ${p?.name || ""}`);
    });
  }

  async function restorePartner(id) {
    await mutateData(base => {
      const p = base.partners.find(p => p.id === id);
      const partners = base.partners.map(p => p.id === id ? { ...p, deleted: false, deletedAt: null } : p);
      return withLog({ ...base, partners }, `a restauré le partenaire ${p?.name || ""}`);
    });
  }

  async function createDossier(clientFirstName, clientLastName, clientPhone, files, hasCoEmprunteur, coClientLastName, coClientFirstName, coClientPhone, clientInforme) {
    setBusy(true); setGlobalError("");
    try {
      const docs = {};
      for (const key of Object.keys(files)) {
        const file = files[key];
        if (!file) continue;
        if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo — compresse le PDF avant de le déposer.`); setBusy(false); return false; }
        const b64 = await fileToBase64(file);
        const fileKey = "adp:file:" + uid();
        await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
        docs[key] = { name: file.name, key: fileKey, size: file.size };
      }
      const dossier = {
        id: uid(), partnerId: currentPartner.id, clientFirstName, clientLastName, clientPhone, status: "Déposé",
        clientInformeLe: clientInforme ? Date.now() : null,
        hasCoEmprunteur: !!hasCoEmprunteur,
        coClientLastName: hasCoEmprunteur ? coClientLastName : "",
        coClientFirstName: hasCoEmprunteur ? coClientFirstName : "",
        coClientPhone: hasCoEmprunteur ? coClientPhone : "",
        docs, bordereau: null, createdAt: Date.now(), updatedAt: Date.now(),
        history: [{ status: "Déposé", at: Date.now() }], notes: "",
      };
            await mutateData(base => ({ ...base, dossiers: [...base.dossiers, dossier] }));
      return true;
    } finally { setBusy(false); }
  }

  async function updateStatus(dossierId, newStatus) {
    await mutateData(base => {
      const target = base.dossiers.find(d => d.id === dossierId);
      const dossiers = base.dossiers.map(d => {
        if (d.id !== dossierId) return d;
        const history = [...(d.history || []), { status: newStatus, at: Date.now() }];
        return { ...d, status: newStatus, updatedAt: Date.now(), history };
      });
      const cname = target ? `${target.clientLastName || ""} ${target.clientFirstName || ""}`.trim() || "(sans nom)" : "";
      return withLog({ ...base, dossiers }, `a changé le statut de ${cname} → ${newStatus}`);
    });
  }

  async function updateDossierClient(dossierId, fields) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, ...fields, updatedAt: Date.now() } : d),
    }));
  }

  async function deleteDossierPermanently(dossierId) {
    await mutateData(base => {
      const target = base.dossiers.find(d => d.id === dossierId);
      const dossiers = base.dossiers.filter(d => d.id !== dossierId);
      return withLog({ ...base, dossiers }, `a supprimé le dossier ${target ? clientName(target) : ""}`);
    });
  }

  async function updateDossierNotes(dossierId, notes) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, notes } : d),
    }));
  }

  async function updateDossierSimulation(dossierId, fields) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, simulation: { ...(d.simulation || {}), ...fields } } : d),
    }));
  }

  async function analyzeDossierIA(dossierId) {
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      return { error: "Analyse IA indisponible dans cet aperçu — fonctionne uniquement sur le site en ligne." };
    }
    const d = data.dossiers.find(x => x.id === dossierId);
    if (!d) return { error: "Dossier introuvable." };
    try {
      const offreFile = d.docs?.offre ? await loadFile(d.docs.offre.key) : null;
      const tableauFile = d.docs?.tableau ? await loadFile(d.docs.tableau.key) : null;
      const cniFile = d.docs?.cni ? await loadFile(d.docs.cni.key) : null;
      if (!offreFile && !tableauFile) return { error: "Aucun document (offre ou tableau) déposé sur ce dossier." };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 150000);
      let res;
      try {
        res = await fetch(`${SUPABASE_URL}/functions/v1/analyse-documents`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${SUPABASE_ANON_KEY}` },
          body: JSON.stringify({
            offreDoc: offreFile ? { data: offreFile.data, mime: offreFile.mime || "application/pdf" } : null,
            tableauDoc: tableauFile ? { data: tableauFile.data, mime: tableauFile.mime || "application/pdf" } : null,
            cniDoc: cniFile ? { data: cniFile.data, mime: cniFile.mime || "application/pdf" } : null,
          }),
          signal: controller.signal,
        });
      } catch (fetchErr) {
        if (fetchErr.name === "AbortError") {
          return { error: "L'analyse a pris trop de temps et a été interrompue. Réessaie, ou dépose des documents moins volumineux (moins de pages) si le problème persiste." };
        }
        throw fetchErr;
      } finally {
        clearTimeout(timeoutId);
      }
      const json = await res.json();
      if (!res.ok || json.error) return { error: json.error || "Erreur pendant l'analyse." };
      return { result: json };
    } catch (e) {
      return { error: "Erreur réseau pendant l'analyse : " + String(e) };
    }
  }

  async function updateDossierPartnerMessage(dossierId, partnerMessage) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, partnerMessage, partnerMessageRead: false } : d),
    }));
  }

  async function markDossierMessageRead(dossierId) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, partnerMessageRead: true } : d),
    }));
  }

  async function adminUploadDoc(dossierId, docKey, file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo — compresse le PDF avant de le déposer.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      await mutateData(base => ({
        ...base,
        dossiers: base.dossiers.map(d => d.id === dossierId
          ? { ...d, docs: { ...(d.docs || {}), [docKey]: { name: file.name, key: fileKey, size: file.size } } }
          : d),
      }));
      return true;
    } finally { setBusy(false); }
  }

  async function removeDoc(dossierId, docKey) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => {
        if (d.id !== dossierId) return d;
        const docs = { ...(d.docs || {}) };
        delete docs[docKey];
        return { ...d, docs };
      }),
    }));
  }

  async function swapDocs(dossierId, keyA, keyB) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => {
        if (d.id !== dossierId) return d;
        const docs = { ...(d.docs || {}) };
        const tmp = docs[keyA];
        if (docs[keyB]) docs[keyA] = docs[keyB]; else delete docs[keyA];
        if (tmp) docs[keyB] = tmp; else delete docs[keyB];
        return { ...d, docs };
      }),
    }));
  }

  async function removeExtraDoc(dossierId, index) {
    await mutateData(base => ({
      ...base,
      dossiers: base.dossiers.map(d => {
        if (d.id !== dossierId) return d;
        const extraDocs = (d.extraDocs || []).filter((_, i) => i !== index);
        return { ...d, extraDocs };
      }),
    }));
  }

  async function addExtraDoc(dossierId, label, file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo — compresse le PDF avant de le déposer.`); return false; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      const newDoc = { label: label || file.name, name: file.name, key: fileKey, size: file.size, addedAt: Date.now() };
      await mutateData(base => ({
        ...base,
        dossiers: base.dossiers.map(d => d.id === dossierId ? { ...d, extraDocs: [...(d.extraDocs || []), newDoc] } : d),
      }));
      return true;
    } finally { setBusy(false); }
  }

  async function uploadBordereau(dossierId, file) {
    if (file.size > MAX_FILE_BYTES) { setGlobalError(`"${file.name}" dépasse 3,5 Mo.`); return; }
    setBusy(true);
    try {
      const b64 = await fileToBase64(file);
      const fileKey = "adp:file:" + uid();
      await storage.set(fileKey, JSON.stringify({ name: file.name, mime: file.type, data: b64 }), true);
      await mutateData(base => ({
        ...base,
        dossiers: base.dossiers.map(d => d.id === dossierId
          ? { ...d, bordereau: { name: file.name, key: fileKey, size: file.size }, status: "Bordereau émis", updatedAt: Date.now(), history: [...(d.history || []), { status: "Bordereau émis", at: Date.now() }] }
          : d),
      }));
    } finally { setBusy(false); }
  }

  // ==========================================================================
  // ÉCRANS PUBLICS — tant que personne n'est authentifié, aucune donnée
  // n'est chargée : il n'y a donc rien à afficher d'autre que la connexion.
  // ==========================================================================
  if (!authPret) {
    return <div className="min-h-screen flex items-center justify-center fa-bg-offwhite fa-teal-text">Chargement…</div>;
  }

  if (!authUser) {
    return (
      <div className="min-h-screen fa-bg-offwhite font-body">
        <style>{BRAND_STYLES}</style>
        {globalError && (
          <div className="bg-red-50 border-b border-red-200 text-red-700 text-sm px-4 py-2 flex items-center gap-2">
            <AlertCircle size={16} /> {globalError}
            <button className="ml-auto text-red-400 hover:text-red-600" onClick={() => setGlobalError("")}>✕</button>
          </div>
        )}
        {view === "partnerLogin" ? (
          <ConnexionFlow titre="Espace partenaire" variante="partenaire" onBack={() => setView("landing")} />
        ) : view === "adminLogin" ? (
          <ConnexionFlow titre="Espace Frangola" variante="frangola" onBack={() => setView("landing")} />
        ) : (
          <Landing logoutReason={logoutReason} onSelect={(target) => { setLogoutReason(null); setView(target); }} />
        )}
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="min-h-screen flex items-center justify-center fa-bg-offwhite px-6">
        <div className="max-w-sm text-center">
          <div className="text-2xl mb-3">⚠️</div>
          <h2 className="font-display text-lg font-semibold fa-navy mb-2">Impossible de charger les données</h2>
          <p className="text-sm text-gray-500 mb-5">Vérifie ta connexion internet et réessaie. Tes données déjà enregistrées n'ont pas été touchées.</p>
          <button onClick={() => window.location.reload()} className="fa-bg-teal text-sm font-medium px-5 py-2.5 rounded-lg transition">Réessayer</button>
          <button onClick={() => deconnexion()} className="block mx-auto mt-4 text-xs text-gray-400 hover:fa-teal-text">Se déconnecter</button>
        </div>
      </div>
    );
  }

  if (loading || !data) {
    return <div className="min-h-screen flex items-center justify-center fa-bg-offwhite fa-teal-text">Chargement…</div>;
  }

  // Authentifié, données chargées, mais le second facteur reste à franchir
  // pour l'administrateur et les mandataires. Il est exigé ici, au niveau de
  // l'application : impossible de le contourner par un autre écran d'entrée.
  if (pendingAuth) {
    return (
      <SecondFacteurGate
        kind={pendingAuth.kind}
        account={pendingAuth.account}
        onUpdateAccount={(fields) => pendingAuth.kind === "admin"
          ? updateAdmin(fields)
          : updateMandataire(pendingAuth.account.id, fields)}
        onCancel={() => deconnexion()}
        onDone={() => {
          const k = pendingAuth.kind; const a = pendingAuth.account;
          setPendingAuth(null);
          if (k === "admin") { setCurrentAdmin(true); setView("adminDash"); sauvegardeAuto(data); }
          else { setCurrentMandataire(a); setView("mandataireDash"); }
        }}
      />
    );
  }

  // Le partenaire doit avoir accepté le contrat de partenariat avant d'entrer.
  // Tant qu'aucun contrat type n'est déposé, aucune porte ne se ferme.
  const contratType = data.settings?.contratType || null;
  const partenaireVivant = currentPartner ? (data.partners.find(p => p.id === currentPartner.id) || currentPartner) : null;
  if (view === "partnerDash" && partenaireVivant && contratType && !partenaireVivant.contratAccepteLe) {
    return (
      <AcceptationContrat
        partner={partenaireVivant}
        contrat={contratType}
        onAccepter={() => updatePartner(partenaireVivant.id, { contratAccepteLe: Date.now() })}
        onLogout={() => deconnexion()}
      />
    );
  }

  return (
    <div className="min-h-screen fa-bg-offwhite font-body">
      <style>{BRAND_STYLES}</style>
      {globalError && (
        <div className="bg-red-50 border-b border-red-200 text-red-700 text-sm px-4 py-2 flex items-center gap-2">
          <AlertCircle size={16} /> {globalError}
          <button className="ml-auto text-red-400 hover:text-red-600" onClick={() => setGlobalError("")}>✕</button>
        </div>
      )}

      {apercuPartnerId && (() => {
        const cible = data.partners.find(p => p.id === apercuPartnerId);
        if (!cible) return null;
        // Aperçu strictement consultatif : toute action d'écriture est neutralisée
        // pour qu'un clic de curiosité n'écrive jamais au nom du partenaire.
        const bloque = () => { setGlobalError("Aperçu en lecture seule — action désactivée."); return false; };
        return (
          <div className="fixed inset-0 z-50 bg-gray-50 overflow-y-auto">
            <div className="sticky top-0 z-10 fa-bg-gold px-5 py-2.5 flex items-center justify-between flex-wrap gap-2">
              <span className="text-sm fa-navy">
                👁 Aperçu de l'espace de <strong>{nomPartenaire(cible)}</strong> — lecture seule
              </span>
              <button onClick={() => setApercuPartnerId(null)}
                className="text-xs font-semibold fa-navy bg-white/70 hover:bg-white px-3 py-1.5 rounded-lg transition">
                Quitter l'aperçu
              </button>
            </div>
            <PartnerDashboard
              partner={cible}
              dossiers={data.dossiers.filter(d => d.partnerId === cible.id)}
              challenge={data.settings?.challengePartenaires || null}
              onLogout={() => setApercuPartnerId(null)}
              onCreateDossier={bloque}
              onDeclarerParrainage={bloque}
              onAddExtraDoc={bloque}
              onUploadRib={bloque}
              onUploadFacture={bloque}
              onSetGoal={bloque}
              onMarkMessageRead={() => {}}
              onUpdateDossierClient={bloque}
              onUploadDocToSlot={bloque}
              onRemoveDoc={bloque}
              onRemoveExtraDoc={bloque}
              busy={false}
            />
          </div>
        );
      })()}
      {view === "partnerDash" && currentPartner && (
        <PartnerDashboard
          partner={data.partners.find(p => p.id === currentPartner.id) || currentPartner}
          dossiers={data.dossiers.filter(d => d.partnerId === currentPartner.id)}
          challenge={data.settings?.challengePartenaires || null}
          onLogout={logout}
          onCreateDossier={createDossier}
                    onDeclarerParrainage={declarerParrainage}
          onAddExtraDoc={addExtraDoc}
          onUploadRib={uploadPartnerRib}
          onUploadFacture={uploadFacture}
          onSetGoal={setPartnerGoal}
          onMarkMessageRead={markDossierMessageRead}
          onUpdateDossierClient={updateDossierClient}
          onUploadDocToSlot={adminUploadDoc}
          onRemoveDoc={removeDoc}
          onRemoveExtraDoc={removeExtraDoc}
          busy={busy}
        />
      )}
      {view === "mandataireDash" && currentMandataire && (() => {
        const liveMandataire = data.mandataires.find(m => m.id === currentMandataire.id) || currentMandataire;
        if (liveMandataire.role !== "manager") {
          return <MandataireDashboard mandataire={liveMandataire} data={data} onLogout={logout} />;
        }
        return (
        <AdminDashboard
          data={data}
          currentAdmin={currentAdmin}
          isFullAdmin={true}
          viewerLabel={currentMandataire.firstName || currentMandataire.name}
          viewerTelephone={liveMandataire.telephone || ""}
          onSetViewerTelephone={(tel) => updateMandataire(liveMandataire.id, { telephone: tel })}
          onLogout={logout}
          onAddPartner={addPartner}
          onUpdatePartner={updatePartner}
          onUploadPartnerContract={uploadPartnerContract}
          onUploadContratType={uploadContratType}
          onDeletePartner={deletePartner}
          onRestorePartner={restorePartner}
          onAddMandataire={addMandataire}
          onUpdateMandataire={updateMandataire}
          onDeleteMandataire={deleteMandataire}
                    onResetMandataireTotp={resetMandataireTotp}
                    onSetChallengeGoals={setChallengeGoals}
          onSetChallengePartenaires={setChallengePartenaires}
          onSetAssureurs={setAssureurs}
          onUpdateAdmin={updateAdmin}
                    onTraiterParrainage={traiterParrainage}
                    onSetFactureStatut={setFactureStatut}
                    onAddVersementParrainage={addVersementParrainage}
          onVirementPartenaire={enregistrerVirementPartenaire}
          onAnnulerVirement={annulerVirementPartenaire}
                    onApercuPartner={setApercuPartnerId}
          onRestoreMandataire={restoreMandataire}
          onUploadReseauLogo={uploadReseauLogo}
          onRemoveReseauLogo={removeReseauLogo}
          onUpdateStatus={updateStatus}
          onUpdateDossierClient={updateDossierClient}
          onDeleteDossier={deleteDossierPermanently}
          onUpdateDossierNotes={updateDossierNotes}
          onUpdateDossierSimulation={updateDossierSimulation}
          onAnalyzeDossierIA={analyzeDossierIA}
          onUpdateDossierPartnerMessage={updateDossierPartnerMessage}
          onUploadBordereau={uploadBordereau}
          onAdminUploadDoc={adminUploadDoc}
          onRemoveDoc={removeDoc}
          onSwapDocs={swapDocs}
          onAddExtraDoc={addExtraDoc}
          onRemoveExtraDoc={removeExtraDoc}
          busy={busy}
        />
        );
      })()}
      {view === "adminDash" && (
        <AdminDashboard
          data={data}
          currentAdmin={currentAdmin}
          isFullAdmin={true}
          viewerLabel="Sébastien"
          viewerTelephone={data.settings.admin.telephone || ""}
          onSetViewerTelephone={(tel) => updateAdmin({ telephone: tel })}
          onLogout={logout}
          onAddPartner={addPartner}
          onUpdatePartner={updatePartner}
          onUploadPartnerContract={uploadPartnerContract}
          onUploadContratType={uploadContratType}
          onDeletePartner={deletePartner}
          onRestorePartner={restorePartner}
          onAddMandataire={addMandataire}
          onUpdateMandataire={updateMandataire}
          onDeleteMandataire={deleteMandataire}
                    onResetMandataireTotp={resetMandataireTotp}
                    onSetChallengeGoals={setChallengeGoals}
          onSetChallengePartenaires={setChallengePartenaires}
          onSetAssureurs={setAssureurs}
          onUpdateAdmin={updateAdmin}
                    onTraiterParrainage={traiterParrainage}
                    onSetFactureStatut={setFactureStatut}
                    onAddVersementParrainage={addVersementParrainage}
          onVirementPartenaire={enregistrerVirementPartenaire}
          onAnnulerVirement={annulerVirementPartenaire}
                    onApercuPartner={setApercuPartnerId}
          onRestoreMandataire={restoreMandataire}
          onUploadReseauLogo={uploadReseauLogo}
          onRemoveReseauLogo={removeReseauLogo}
          onUpdateStatus={updateStatus}
          onUpdateDossierClient={updateDossierClient}
          onDeleteDossier={deleteDossierPermanently}
          onUpdateDossierNotes={updateDossierNotes}
          onUpdateDossierSimulation={updateDossierSimulation}
          onAnalyzeDossierIA={analyzeDossierIA}
          onUpdateDossierPartnerMessage={updateDossierPartnerMessage}
          onUploadBordereau={uploadBordereau}
          onAdminUploadDoc={adminUploadDoc}
          onRemoveDoc={removeDoc}
          onSwapDocs={swapDocs}
          onAddExtraDoc={addExtraDoc}
          onRemoveExtraDoc={removeExtraDoc}
          busy={busy}
        />
      )}
    </div>
  );
}

function Landing({ onSelect, logoutReason }) {
  const [showLegal, setShowLegal] = useState(false);
  return (
    <div className="min-h-screen flex flex-col">
      {logoutReason === "inactivity" && (
        <div className="fa-bg-gold fa-navy text-sm font-medium text-center py-2.5 px-4">
          Vous avez été déconnecté après 1h d'inactivité, par sécurité.
        </div>
      )}
      {logoutReason === "desactive" && (
        <div className="fa-bg-gold fa-navy text-sm font-medium text-center py-2.5 px-4">
          Votre accès a été suspendu. Contactez Frangola.
        </div>
      )}
      {logoutReason === "sansFiche" && (
        <div className="fa-bg-gold fa-navy text-sm font-medium text-center py-2.5 px-4">
          Aucun espace n'est associé à cette adresse email. Contactez Frangola.
        </div>
      )}
      <header className="px-6 py-5 flex items-center justify-between fa-bg-offwhite">
        <Logo />
        <div className="flex items-center gap-4">
          <span className="text-xs font-bold fa-navy uppercase tracking-wider hidden sm:block">Assurance de prêt</span>
          <button onClick={() => onSelect("adminLogin")}
            className="text-xs text-gray-400 hover:fa-teal-text underline underline-offset-2 transition">
            Espace Frangola
          </button>
        </div>
      </header>

      <section className="fa-bg-teal px-6 py-16">
        <div className="max-w-3xl mx-auto text-center">
          <span className="inline-block text-xs font-bold uppercase tracking-widest fa-navy fa-bg-gold px-3 py-1.5 rounded-full mb-6">
            Assurance de prêt
          </span>
          <h1 className="font-display text-3xl md:text-4xl font-semibold fa-navy mb-4 leading-tight">
            Le lien direct entre vous et <span style={{ color: "#FCD947" }}>Frangola Assure</span>
          </h1>
          <p className="text-white/90 max-w-xl mx-auto mb-10">
            Déposez, suivez, avancez — tout depuis votre espace personnel.
          </p>
          <div className="max-w-sm mx-auto">
            <button onClick={() => onSelect("partnerLogin")}
              className="w-full bg-white rounded-2xl p-6 shadow-lg hover:-translate-y-1 transition text-center flex flex-col items-center">
              <Users className="fa-teal-text mb-3" size={26} />
              <div className="font-display font-semibold fa-navy mb-1">Espace partenaire</div>
              <div className="text-xs text-gray-400">Connexion</div>
            </button>
          </div>
        </div>
      </section>

      <section className="fa-bg-pink px-6 py-14">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="font-display text-2xl md:text-3xl font-semibold fa-navy mb-10">Comment ça marche ?</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8 text-left">
            {[
              { n: "1", t: "Vous déposez", d: "Les informations nécessaires à la bonne prise en charge du prospect." },
              { n: "2", t: "Frangola vérifie", d: "Le dossier est contrôlé et le prospect contacté sous 24h." },
              { n: "3", t: "Vous suivez", d: "Du devis à la signature du contrat, suivez chaque étape en temps réel." },
              { n: "4", t: "Vous encaissez", d: "Le bordereau est déposé dans votre espace pour percevoir votre commission." },
            ].map(step => (
              <div key={step.n} className="bg-white rounded-2xl p-6 shadow-sm">
                <div className="fa-bg-gold w-9 h-9 rounded-full flex items-center justify-center font-display font-bold fa-navy mb-4">{step.n}</div>
                <div className="font-display font-semibold fa-navy mb-1">{step.t}</div>
                <div className="text-sm text-gray-500">{step.d}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer className="text-center text-xs text-gray-400 py-6 fa-bg-offwhite">
        FRANGOLA ADP — Frangola Assure, courtier en assurance
        {" · "}
        <button onClick={() => setShowLegal(true)} className="underline underline-offset-2 hover:fa-teal-text">Mentions légales</button>
      </footer>

      {showLegal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-6 z-50" onClick={() => setShowLegal(false)}>
          <div className="bg-white rounded-2xl max-w-lg w-full max-h-[80vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-lg font-semibold fa-navy">Mentions légales</h2>
              <button onClick={() => setShowLegal(false)} className="text-gray-400 hover:text-red-600"><X size={18} /></button>
            </div>
            <div className="text-sm text-gray-600 space-y-3">
              <p><strong className="fa-navy">Éditeur.</strong> FRANGOLA, EURL au capital de 1 000 €, 6 bis Boulevard Berthelot, Bureau 3, 34000 Montpellier — RCS Montpellier, SIRET 108 672 452 00019, TVA FR77108672452. Directeur de la publication : Sébastien Lesne, gérant. Contact : contact@frangola.fr — 07 62 56 15 00.</p>
              <p><strong className="fa-navy">Activité réglementée.</strong> FRANGOLA est courtier en assurance immatriculé à l'ORIAS sous le n° 26010830 (orias.fr), sans détention ni maniement de fonds de tiers. Assurance Responsabilité Civile Professionnelle souscrite auprès de Hiscox S.A. (contrat n° HXFRIA000000423), par l'intermédiaire de +Simple.fr. Activité contrôlée par l'ACPR — 4 Place de Budapest, CS 92459, 75436 Paris Cedex 09.</p>
              <p><strong className="fa-navy">Hébergement.</strong> Hostinger International Ltd., 61 Lordou Vironos Street, 6023 Larnaca, Chypre — hostinger.fr/contact.</p>
              <p><strong className="fa-navy">Données personnelles.</strong> Les données saisies dans cet espace sont traitées conformément au RGPD, dans le cadre strict de l'activité de courtage. Droit d'accès, de rectification ou de suppression : contact@frangola.fr.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function PasswordField({ value, onChange, onKeyDown, placeholder, autoFocus, className }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <input value={value} onChange={onChange} onKeyDown={onKeyDown}
        type={visible ? "text" : "password"} placeholder={placeholder} autoFocus={autoFocus}
        className={`${className} pr-10`} />
      <button type="button" onClick={() => setVisible(v => !v)}
        className="absolute right-0 top-0 h-full px-3 flex items-center text-gray-400 hover:text-gray-600" tabIndex={-1}>
        {visible ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  );
}

// =============================================================================
// ÉCRAN DE CONNEXION
//
// Le mot de passe n'est plus comparé dans le navigateur : il est vérifié par
// Supabase, qui ne stocke qu'une empreinte et ne renvoie jamais le mot de
// passe. Le rôle n'est pas choisi ici — il se déduit de l'adresse email une
// fois la personne authentifiée.
// =============================================================================
function ConnexionFlow({ titre, variante, onBack }) {
  const [etape, setEtape] = useState("password"); // password | activation
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [nouveau, setNouveau] = useState("");
  const [nouveau2, setNouveau2] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const Icone = variante === "frangola" ? Shield : Users;

  async function seConnecter() {
    const mail = email.trim().toLowerCase();
    if (!mail || !password) { setError("Adresse email et mot de passe requis."); return; }
    setError(""); setBusy(true);
    try {
      const { error: err } = await supabase.auth.signInWithPassword({ email: mail, password });
      if (err) {
        setError(/invalid/i.test(err.message)
          ? "Adresse email ou mot de passe incorrect."
          : "Connexion impossible : " + err.message);
        return;
      }
      // La suite est prise en charge par l'application : chargement des
      // données, puis orientation vers le bon espace.
    } catch (e) {
      setError("Connexion impossible. Vérifiez votre accès internet.");
    } finally { setBusy(false); }
  }

  async function activer() {
    const mail = email.trim().toLowerCase();
    if (!mail || !code.trim()) { setError("Adresse email et code d'activation requis."); return; }
    if (nouveau.length < 8) { setError("8 caractères minimum pour le mot de passe."); return; }
    if (nouveau !== nouveau2) { setError("Les deux mots de passe ne correspondent pas."); return; }
    setError(""); setBusy(true);
    try {
      await appelerActivation({ email: mail, code: code.trim(), password: nouveau });
      const { error: err } = await supabase.auth.signInWithPassword({ email: mail, password: nouveau });
      if (err) { setError("Compte créé, mais la connexion a échoué. Réessayez avec votre nouveau mot de passe."); setEtape("password"); setPassword(""); }
    } catch (e) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  const champ = "w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500 mb-3";

  return (
    <div className="min-h-screen flex items-center justify-center fa-bg-offwhite px-6">
      <div className="max-w-sm w-full bg-white border border-gray-200 rounded-2xl shadow-sm p-8">
        <button onClick={etape === "password" ? onBack : () => { setEtape("password"); setError(""); }}
          className="flex items-center gap-1 text-sm text-gray-400 hover:fa-teal-text mb-6">
          <ArrowLeft size={15} /> Retour
        </button>
        <div className="flex items-center gap-2 mb-1">
          <Icone className="fa-teal-text" size={20} />
          <h2 className="font-display text-lg font-semibold fa-navy">{titre}</h2>
        </div>

        {etape === "password" && (
          <>
            <p className="text-sm text-gray-500 mb-5">Entrez vos identifiants.</p>
            <input value={email} onChange={e => setEmail(e.target.value)} type="email" placeholder="vous@exemple.fr"
              autoComplete="username" autoFocus className={champ} />
            <PasswordField value={password} onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && seConnecter()}
              placeholder="Mot de passe" autoComplete="current-password" className={champ} />
            {error && <div className="text-sm text-red-600 mb-3">{error}</div>}
            <button onClick={seConnecter} disabled={busy}
              className="w-full fa-bg-teal disabled:opacity-50 font-medium rounded-lg py-2.5 text-sm transition">
              {busy ? "Vérification…" : "Se connecter"}
            </button>
            <button onClick={() => { setEtape("activation"); setError(""); setPassword(""); setNouveau(""); setNouveau2(""); setCode(""); }}
              className="w-full text-center text-xs text-gray-400 hover:fa-teal-text mt-3">
              Première connexion, ou mot de passe oublié ?
            </button>
          </>
        )}

        {etape === "activation" && (
          <>
            <p className="text-sm text-gray-500 mb-4">
              Entrez le code d'activation que Frangola vous a transmis, puis choisissez votre mot de passe.
            </p>
            <input value={email} onChange={e => setEmail(e.target.value)} type="email" placeholder="vous@exemple.fr"
              autoComplete="username" autoFocus className={champ} />
            <input value={code} onChange={e => setCode(e.target.value.toUpperCase().replace(/\s/g, ""))}
              placeholder="Code d'activation"
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono tracking-widest text-center focus:outline-none focus:ring-2 focus:ring-teal-500 mb-3" />
            <PasswordField value={nouveau} onChange={e => setNouveau(e.target.value)}
              placeholder="Mot de passe (8 caractères min.)" autoComplete="new-password" className={champ} />
            <PasswordField value={nouveau2} onChange={e => setNouveau2(e.target.value)}
              onKeyDown={e => e.key === "Enter" && activer()}
              placeholder="Confirmer le mot de passe" autoComplete="new-password" className={champ} />
            {error && <div className="text-sm text-red-600 mb-3">{error}</div>}
            <button onClick={activer} disabled={busy}
              className="w-full fa-bg-teal disabled:opacity-50 font-medium rounded-lg py-2.5 text-sm transition">
              {busy ? "Activation…" : "Activer mon accès"}
            </button>
            <p className="text-xs text-gray-400 mt-4 leading-relaxed">
              Vous n'avez pas de code ? Demandez-le à votre interlocuteur Frangola : lui seul peut le délivrer.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// =============================================================================
// SECOND FACTEUR — exigé de l'administrateur et des mandataires
//
// Rendu par l'application elle-même une fois le mot de passe validé, et non
// par l'écran de connexion : on ne peut donc pas l'éviter en entrant par une
// autre porte.
// =============================================================================
function SecondFacteurGate({ kind, account, onUpdateAccount, onDone, onCancel }) {
  const dejaConfigure = !!(account?.totpEnabled && account?.totpSecret);
  const [etape, setEtape] = useState(dejaConfigure ? "verify" : "setup");
  const [pendingSecret, setPendingSecret] = useState(() => dejaConfigure ? "" : randomBase32Secret());
  const [code, setCode] = useState("");
  const [recoveryCodeInput, setRecoveryCodeInput] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);
  const [generatedRecoveryCodes, setGeneratedRecoveryCodes] = useState([]);
  const [memoriser, setMemoriser] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Décochée par défaut, volontairement : sur une machine qui n'est pas la
  // sienne, ne rien faire est le comportement sûr.
  const cle = cleAppareil(kind, account);
  function terminer() {
    if (memoriser) memoriserAppareil(cle); else oublierAppareil();
    onDone();
  }

  const caseAppareil = (
    <label className="flex items-start gap-2 text-xs text-gray-500 mb-4 cursor-pointer select-none">
      <input type="checkbox" checked={memoriser} onChange={e => setMemoriser(e.target.checked)}
        className="mt-0.5 accent-teal-600" />
      <span>
        Se souvenir de cet appareil pendant 30 jours.
        <span className="block text-gray-400">
          À ne cocher que sur vos propres machines — le mot de passe restera demandé, pas le code.
        </span>
      </span>
    </label>
  );

  async function confirmSetup() {
    setBusy(true); setError("");
    try {
      const ok = await verifyTotp(pendingSecret, code);
      if (!ok) { setError("Code incorrect — vérifie l'heure de ton téléphone et réessaie."); return; }
      const codes = generateRecoveryCodes();
      await onUpdateAccount({ totpSecret: pendingSecret, totpEnabled: true, lastLoginAt: Date.now(), recoveryCodes: codes });
      setGeneratedRecoveryCodes(codes);
      setEtape("showRecoveryCodes");
    } finally { setBusy(false); }
  }

  async function confirmVerify() {
    setBusy(true); setError("");
    try {
      if (useRecoveryCode) {
        const match = (account.recoveryCodes || []).find(rc => !rc.used && rc.code === recoveryCodeInput.trim().toUpperCase());
        if (!match) { setError("Code de récupération invalide ou déjà utilisé."); return; }
        const updatedCodes = account.recoveryCodes.map(rc => rc.code === match.code ? { ...rc, used: true } : rc);
        await onUpdateAccount({ recoveryCodes: updatedCodes, lastLoginAt: Date.now() });
        terminer();
        return;
      }
      const ok = await verifyTotp(account.totpSecret, code);
      if (!ok) { setError("Code incorrect."); return; }
      await onUpdateAccount({ lastLoginAt: Date.now() });
      terminer();
    } finally { setBusy(false); }
  }

  return (
    <div className="min-h-screen flex items-center justify-center fa-bg-offwhite px-6">
      <div className="max-w-sm w-full bg-white border border-gray-200 rounded-2xl shadow-sm p-8">
        <button onClick={onCancel} className="flex items-center gap-1 text-sm text-gray-400 hover:fa-teal-text mb-6">
          <ArrowLeft size={15} /> Se déconnecter
        </button>
        <div className="flex items-center gap-2 mb-1">
          <Shield className="fa-teal-text" size={20} />
          <h2 className="font-display text-lg font-semibold fa-navy">
            {kind === "admin" ? "Administration" : "Espace mandataire"}
          </h2>
        </div>

        {etape === "setup" && (
          <>
            <p className="text-sm text-gray-500 mb-1">Configurez la double authentification.</p>
            <ol className="text-xs text-gray-500 list-decimal list-inside space-y-1 my-4 bg-gray-50 rounded-lg p-3">
              <li>Ouvre Google Authenticator, Authy ou équivalent</li>
              <li>Choisis "Saisir une clé de configuration" (pas de QR ici)</li>
              <li>Nom du compte : FRANGOLA ADP — Type : basée sur le temps</li>
            </ol>
            <div className="bg-teal-50 border border-teal-200 rounded-lg px-4 py-3 mb-4 text-center">
              <div className="font-mono font-bold tracking-widest fa-navy text-sm break-all">{formatSecretForDisplay(pendingSecret)}</div>
            </div>
            <p className="text-sm text-gray-500 mb-2">Entre ensuite le code à 6 chiffres généré par l'application :</p>
            <input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              onKeyDown={e => e.key === "Enter" && code.length === 6 && confirmSetup()}
              placeholder="000000" inputMode="numeric" autoFocus
              className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono tracking-[0.4em] text-center focus:outline-none focus:ring-2 focus:ring-teal-500 mb-3" />
            {error && <div className="text-sm text-red-600 mb-3">{error}</div>}
            {caseAppareil}
            <button onClick={confirmSetup} disabled={busy || code.length !== 6}
              className="w-full fa-bg-teal disabled:opacity-50 font-medium rounded-lg py-2.5 text-sm transition">
              {busy ? "Vérification…" : "Activer et accéder"}
            </button>
          </>
        )}

        {etape === "showRecoveryCodes" && (
          <>
            <p className="text-sm fa-navy font-semibold mb-1">⚠️ Notez ces codes maintenant</p>
            <p className="text-sm text-gray-500 mb-4">
              Ils permettent de récupérer l'accès si vous perdez votre téléphone. Chaque code ne fonctionne qu'une seule fois.
              Ils ne seront plus jamais affichés après cet écran — gardez-les en lieu sûr (imprimés, ou dans un gestionnaire de mots de passe).
            </p>
            <div className="grid grid-cols-2 gap-2 bg-gray-50 rounded-lg p-4 mb-4">
              {generatedRecoveryCodes.map(rc => (
                <div key={rc.code} className="font-mono text-sm fa-navy text-center">{rc.code}</div>
              ))}
            </div>
            <button onClick={terminer} className="w-full fa-bg-teal font-medium rounded-lg py-2.5 text-sm transition">
              J'ai noté mes codes — continuer
            </button>
          </>
        )}

        {etape === "verify" && (
          <>
            <p className="text-sm text-gray-500 mb-5">
              {useRecoveryCode ? "Entrez l'un de vos codes de récupération (à usage unique)." : "Entre le code de ton application d'authentification."}
            </p>
            {useRecoveryCode ? (
              <input value={recoveryCodeInput} onChange={e => setRecoveryCodeInput(e.target.value.toUpperCase())}
                onKeyDown={e => e.key === "Enter" && confirmVerify()}
                placeholder="XXXX-XXXX" autoFocus
                className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono tracking-widest text-center focus:outline-none focus:ring-2 focus:ring-teal-500 mb-3" />
            ) : (
              <input value={code} onChange={e => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                onKeyDown={e => e.key === "Enter" && code.length === 6 && confirmVerify()}
                placeholder="000000" inputMode="numeric" autoFocus
                className="w-full border border-gray-300 rounded-lg px-3 py-2.5 text-sm font-mono tracking-[0.4em] text-center focus:outline-none focus:ring-2 focus:ring-teal-500 mb-3" />
            )}
            {error && <div className="text-sm text-red-600 mb-3">{error}</div>}
            {caseAppareil}
            <button onClick={confirmVerify} disabled={busy || (useRecoveryCode ? recoveryCodeInput.trim().length < 9 : code.length !== 6)}
              className="w-full fa-bg-teal disabled:opacity-50 font-medium rounded-lg py-2.5 text-sm transition">
              {busy ? "Vérification…" : "Accéder"}
            </button>
            <button onClick={() => { setUseRecoveryCode(v => !v); setError(""); setCode(""); setRecoveryCodeInput(""); }}
              className="w-full text-center text-xs text-gray-400 hover:fa-teal-text mt-3">
              {useRecoveryCode ? "J'ai accès à mon Authenticator" : "Je n'ai plus accès à mon Authenticator"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

const SITE_URL = "https://frangola-adp.fr";

// =============================================================================
// MESSAGE D'INVITATION
//
// Prépare le courrier d'accueil qu'on envoie à un nouveau partenaire ou à un
// nouveau mandataire avec son code d'activation. Le contenu diffère : un
// mandataire doit en plus configurer son application d'authentification.
// =============================================================================
function piedDeSignature(expediteur, telephone) {
  const lignes = [
    "À très vite,",
    expediteur || "Sébastien",
    "Frangola — Assurance de prêt",
  ];
  if ((telephone || "").trim()) lignes.push((telephone || "").trim());
  lignes.push("");
  lignes.push("FRANGOLA — Courtier en assurance · ORIAS n°26010830");
  lignes.push("6 bis boulevard Berthelot, Bureau 3 — 34000 Montpellier");
  return lignes;
}

// Le presse-papier accepte deux versions d'un même contenu : le texte brut
// (WhatsApp, SMS) et le HTML (Gmail, Outlook). Le second porte la police.
const POLICE_MAIL = "Verdana, Geneva, sans-serif";
const TAILLE_MAIL = "14px";

function echapperHtml(t) {
  return String(t)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Transforme le message en HTML : police Verdana, taille moyenne, le code
// d'activation mis en évidence pour qu'on ne le cherche pas dans le texte.
function messageEnHtml(corps) {
  const lignes = corps.split("\n").map(l => {
    if (l.trim() === "") return '<div style="height:12px"></div>';
    const m = l.match(/^Votre code d'activation : (.+)$/);
    if (m) {
      return `<div style="margin:14px 0"><span style="font-family:${POLICE_MAIL};font-size:${TAILLE_MAIL}">Votre code d'activation : </span>`
        + `<span style="font-family:${POLICE_MAIL};font-size:16px;font-weight:bold;letter-spacing:2px;background:#FFE9A8;padding:4px 10px;border-radius:5px">${echapperHtml(m[1])}</span></div>`;
    }
    const url = l.match(/^(\d\. Rendez-vous sur )(https?:\/\/\S+)$/);
    if (url) {
      return `<div>${echapperHtml(url[1])}<a href="${url[2]}" style="color:#008BA8">${echapperHtml(url[2])}</a></div>`;
    }
    return `<div>${echapperHtml(l)}</div>`;
  }).join("");
  return `<div style="font-family:${POLICE_MAIL};font-size:${TAILLE_MAIL};line-height:1.55;color:#2b2b2b">${lignes}</div>`;
}

// Dépose les deux versions dans le presse-papier. Si le navigateur ne sait pas
// faire, on retombe sur le texte brut plutôt que de ne rien copier du tout.
async function copierRiche(html, texte) {
  try {
    if (typeof ClipboardItem !== "undefined" && navigator.clipboard?.write) {
      await navigator.clipboard.write([new ClipboardItem({
        "text/html": new Blob([html], { type: "text/html" }),
        "text/plain": new Blob([texte], { type: "text/plain" }),
      })]);
      return true;
    }
  } catch (e) { /* on tente le texte simple */ }
  try { await navigator.clipboard.writeText(texte); return true; } catch (e) { return false; }
}

function messageInvitation(cible, expediteur, genre, telephone) {
  const prenom = (cible.firstName || "").trim();
  const bonjour = prenom ? `Bonjour ${prenom},` : "Bonjour,";
  const email = (cible.email || "").trim();
  const code = cible.code || "—";

  if (genre === "mandataire") {
    return {
      sujet: "Votre accès à Frangola ADP",
      corps: [
        bonjour,
        "",
        "Votre accès à Frangola ADP est ouvert. Vous y suivrez les dossiers d'assurance de prêt, vos partenaires et leur production.",
        "",
        "Pour l'activer :",
        "",
        `1. Rendez-vous sur ${SITE_URL}`,
        "2. En haut à droite, cliquez sur « Espace Frangola »",
        "3. Cliquez sur « Première connexion, ou mot de passe oublié ? »",
        `4. Saisissez votre adresse email (${email}), le code ci-dessous, et choisissez votre mot de passe`,
        "5. Configurez ensuite la double authentification avec Google Authenticator, Authy ou équivalent — l'écran vous guide pas à pas",
        "",
        `Votre code d'activation : ${code}`,
        "",
        "Ce code est personnel, à usage unique, et valable 30 jours.",
        "Notez bien vos codes de récupération à la fin de la configuration : ils sont affichés une seule fois.",
        "",
        "Une question ? Répondez simplement à ce message.",
        "",
        ...piedDeSignature(expediteur, telephone),
      ].join("\n"),
    };
  }

  return {
    sujet: "Bienvenue chez Frangola — vos accès",
    corps: [
      bonjour,
      "",
      "Bienvenue chez Frangola, et merci de votre confiance.",
      "",
      "Votre espace partenaire est ouvert. Vous y déposerez vos dossiers d'assurance de prêt, vous suivrez leur avancement en temps réel, et vous y retrouverez vos bordereaux de commission.",
      "",
      "Pour l'activer, trois minutes :",
      "",
      `1. Rendez-vous sur ${SITE_URL}`,
      "2. Cliquez sur « Espace partenaire »",
      "3. Cliquez sur « Première connexion, ou mot de passe oublié ? »",
      `4. Saisissez votre adresse email (${email}), le code ci-dessous, et choisissez votre mot de passe`,
      "",
      `Votre code d'activation : ${code}`,
      "",
      "Ce code est personnel, à usage unique, et valable 30 jours.",
      "",
      "Une fois connecté, vous pourrez déposer votre premier dossier immédiatement. Nous le prenons en charge sous 24 heures.",
      "",
      "Une question ? Répondez simplement à ce message, ou appelez-moi.",
      "",
      ...piedDeSignature(expediteur, telephone),
    ].join("\n"),
  };
}

// =============================================================================
// CODE D'ACTIVATION — ce qu'un partenaire ou un mandataire doit recevoir pour
// créer son mot de passe la première fois, ou le reprendre s'il l'a perdu.
//
// Le mot de passe n'apparaît nulle part : il est détenu par Supabase sous
// forme d'empreinte. Personne, pas même l'administrateur, ne peut le lire.
// =============================================================================
// Numéro repris dans la signature des messages d'invitation. Chacun le sien :
// c'est l'expéditeur du message qu'un partenaire doit pouvoir rappeler.
function ChampTelephoneSignature({ valeur, onEnregistrer }) {
  const [ouvert, setOuvert] = useState(false);
  const [saisie, setSaisie] = useState(valeur || "");
  useEffect(() => { setSaisie(valeur || ""); }, [valeur]);

  if (!onEnregistrer) return null;

  if (!ouvert) {
    return (
      <button onClick={() => setOuvert(true)}
        title="Numéro affiché dans la signature de vos messages d'invitation"
        className="hidden sm:inline text-xs text-gray-400 hover:fa-teal-text underline underline-offset-2">
        {valeur ? `☎ ${valeur}` : "☎ ajouter mon numéro"}
      </button>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <input value={saisie} onChange={e => setSaisie(e.target.value)} type="tel" placeholder="06 12 34 56 78" autoFocus
        onKeyDown={e => { if (e.key === "Enter") { onEnregistrer(saisie.trim()); setOuvert(false); } if (e.key === "Escape") setOuvert(false); }}
        className="border border-gray-300 rounded-lg px-2 py-1 text-xs w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
      <button onClick={() => { onEnregistrer(saisie.trim()); setOuvert(false); }}
        className="text-xs font-semibold fa-teal-text hover:underline">OK</button>
      <button onClick={() => setOuvert(false)} className="text-xs text-gray-400 hover:text-gray-600">✕</button>
    </span>
  );
}

// =============================================================================
// ACCEPTATION DU CONTRAT DE PARTENARIAT
//
// Une case cochée ne vaut pas une signature manuscrite, mais elle est datée,
// horodatée et opposable comme commencement de preuve — et c'est le seul
// dispositif qui tienne à cent partenaires. Le contrat reste consultable et
// téléchargeable à tout moment depuis son espace.
// =============================================================================
// Dépôt du contrat de partenariat commun, et suivi de qui l'a accepté.
function ContratTypePanel({ contrat, partners, onUpload, canEdit, busy }) {
  const champ = useRef(null);
  const vivants = (partners || []).filter(p => !p.deleted);
  const acceptes = vivants.filter(p => p.contratAccepteLe).length;
  const manquants = vivants.length - acceptes;

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-6">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <div className="font-display font-semibold fa-navy">Contrat de partenariat</div>
          <div className="text-sm text-gray-500">
            {contrat
              ? <>Déposé le {fmtDate(contrat.at)} — <strong className="fa-navy">{contrat.name}</strong>. Chaque partenaire doit l'accepter à sa première connexion.</>
              : "Aucun contrat déposé. Tant qu'il manque, les partenaires accèdent à leur espace sans rien signer."}
          </div>
          {contrat && vivants.length > 0 && (
            <div className="text-xs mt-1">
              <span className="text-emerald-700 font-medium">{acceptes} accepté{acceptes > 1 ? "s" : ""}</span>
              {manquants > 0 && <span className="text-red-700 font-medium"> · {manquants} en attente</span>}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {contrat && (
            <button onClick={() => downloadStoredFile(contrat.key, contrat.name)}
              className="flex items-center gap-1.5 text-xs font-medium fa-navy fa-bg-gold px-3 py-1.5 rounded-lg transition">
              <Download size={14} /> Télécharger
            </button>
          )}
          {canEdit && (
            <>
              <button onClick={() => champ.current?.click()} disabled={busy}
                className="text-xs font-semibold bg-gray-50 text-gray-600 hover:bg-gray-100 border border-gray-200 px-3 py-1.5 rounded-lg transition disabled:opacity-50">
                {contrat ? "Remplacer" : "Déposer le contrat"}
              </button>
              <input type="file" accept="application/pdf" className="hidden" ref={champ}
                onChange={e => e.target.files?.[0] && onUpload(e.target.files[0])} />
            </>
          )}
        </div>
      </div>
      {contrat && (
        <p className="text-xs text-gray-400 mt-3">
          Remplacer le contrat ne remet pas les acceptations à zéro : les partenaires déjà entrés resteront
          sur la version qu'ils ont acceptée. Pour une nouvelle version opposable, il faut leur redemander.
        </p>
      )}
    </div>
  );
}

function AcceptationContrat({ partner, contrat, onAccepter, onLogout }) {
  const [lu, setLu] = useState(false);
  const [busy, setBusy] = useState(false);
  const [telecharge, setTelecharge] = useState(false);

  async function valider() {
    setBusy(true);
    try { await onAccepter(); } finally { setBusy(false); }
  }

  return (
    <div className="min-h-screen fa-bg-offwhite flex items-center justify-center px-6 py-10">
      <div className="max-w-lg w-full bg-white border border-gray-200 rounded-2xl shadow-sm p-8">
        <div className="flex items-center gap-2 mb-1">
          <FileCheck2 className="fa-teal-text" size={20} />
          <h2 className="font-display text-lg font-semibold fa-navy">Contrat de partenariat</h2>
        </div>
        <p className="text-sm text-gray-500 mb-5">
          Bonjour {partner.firstName || up(partner.name)}. Avant d'accéder à votre espace, merci de prendre
          connaissance du contrat qui encadre notre collaboration.
        </p>

        <button
          onClick={() => { downloadStoredFile(contrat.key, contrat.name); setTelecharge(true); }}
          className="w-full flex items-center justify-center gap-2 text-sm font-medium fa-navy fa-bg-gold px-4 py-3 rounded-lg transition mb-5">
          <Download size={16} /> Lire le contrat — {contrat.name}
        </button>

        <label className="flex items-start gap-2.5 text-sm text-gray-600 mb-5 cursor-pointer select-none">
          <input type="checkbox" checked={lu} onChange={e => setLu(e.target.checked)} className="mt-0.5 accent-teal-600" />
          <span>
            J'ai lu et j'accepte le contrat de partenariat Frangola.
            <span className="block text-xs text-gray-400 mt-0.5">
              Votre acceptation sera enregistrée avec la date et l'heure.
            </span>
          </span>
        </label>

        {!telecharge && lu && (
          <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
            Vous n'avez pas encore ouvert le contrat. Prenez le temps de le lire — il reste consultable
            depuis votre espace ensuite.
          </div>
        )}

        <button onClick={valider} disabled={!lu || busy}
          className="w-full fa-bg-teal disabled:opacity-50 font-medium rounded-lg py-2.5 text-sm transition">
          {busy ? "Enregistrement…" : "Accepter et accéder à mon espace"}
        </button>

        <button onClick={onLogout} className="w-full text-center text-xs text-gray-400 hover:fa-teal-text mt-4">
          Se déconnecter
        </button>
      </div>
    </div>
  );
}

function BlocAcces({ cible, onReinitialiser, expediteur, telephone, genre = "partenaire" }) {
  const [copie, setCopie] = useState(false);
  const [pret, setPret] = useState(null); // "email" | "whatsapp" | "echec"
  const [confirme, setConfirme] = useState(false);

  // Un seul geste : le presse-papier reçoit les deux versions du message.
  // Gmail et Outlook collent la version mise en forme, WhatsApp et les SMS
  // prennent d'eux-mêmes la version texte. Rien ne s'ouvre, rien ne part.
  async function copierLeMessage() {
    const { corps } = messageInvitation(cible, expediteur, genre, telephone);
    const ok = await copierRiche(messageEnHtml(corps), corps);
    setPret(ok ? "ok" : "echec");
    setTimeout(() => setPret(null), 4000);
  }
  // Le code ne s'affiche que tant qu'il sert : première connexion en attente,
  // ou accès réinitialisé par l'administrateur. Une fois consommé, il est
  // effacé côté serveur et seul le bouton de réinitialisation subsiste.
  const codeUtile = !!cible.code && (!cible.lastLoginAt || cible.accesReinitialise);

  function copier() {
    try {
      navigator.clipboard.writeText(cible.code || "");
      setCopie(true); setTimeout(() => setCopie(false), 1800);
    } catch (e) { /* presse-papier indisponible */ }
  }

  return (
    <span className="inline-flex items-center gap-2 flex-wrap">
      {codeUtile && (
        <span className="inline-flex items-center gap-1.5 text-xs bg-amber-50 border border-amber-200 text-amber-800 px-2.5 py-1 rounded-lg">
          <Key size={12} />
          <span>Code d'activation</span>
          <button onClick={copier} title="Copier"
            className="font-mono font-bold tracking-widest hover:underline">{cible.code}</button>
          {copie && <span className="text-emerald-700">copié</span>}
        </span>
      )}
      {codeUtile && (
        <button onClick={copierLeMessage}
          title="Copie le message d'accueil complet — mise en forme conservée dans Gmail, texte simple dans WhatsApp"
          className="text-xs font-semibold bg-teal-50 text-teal-700 hover:bg-teal-100 border border-teal-200 px-2.5 py-1 rounded-lg transition">
          ✉ Copier le message d'accueil
        </button>
      )}
      {pret === "ok" && <span className="text-xs text-emerald-700 font-medium">Message copié</span>}
      {pret === "echec" && <span className="text-xs text-red-600 font-medium">Copie impossible — presse-papier bloqué par le navigateur</span>}
      {!codeUtile && (
        confirme ? (
          <span className="inline-flex items-center gap-1.5 text-xs">
            <span className="text-amber-800">Générer un nouveau code ?</span>
            <button onClick={() => { setConfirme(false); onReinitialiser(); }} className="font-semibold text-amber-800 hover:underline">Oui</button>
            <button onClick={() => setConfirme(false)} className="text-gray-500 hover:underline">Non</button>
          </span>
        ) : (
          <button onClick={() => setConfirme(true)}
            title="Délivre un nouveau code d'activation, avec lequel la personne choisira un nouveau mot de passe"
            className="text-xs font-semibold bg-gray-50 text-gray-600 hover:bg-gray-100 border border-gray-200 px-2.5 py-1 rounded-lg transition">
            Réinitialiser l'accès
          </button>
        )
      )}
    </span>
  );
}

function ParrainageCard({ partner, onDeclarer }) {
  const [ouvert, setOuvert] = useState(false);
  const [form, setForm] = useState({ nom: "", prenom: "", telephone: "", reseau: "", siret: "" });
  const [erreur, setErreur] = useState("");
  const [busy, setBusy] = useState(false);
  const [envoye, setEnvoye] = useState(false);
  const declarations = mesDeclarations(partner.id);

  async function envoyer() {
    if (!form.nom.trim() || !form.prenom.trim()) { setErreur("Le nom et le prénom sont obligatoires."); return; }
    if (normaliseTel(form.telephone).length < 9) { setErreur("Le numéro de téléphone est incomplet."); return; }
    if ((form.siret || "").replace(/\D/g, "").length !== 14) { setErreur("Le SIRET doit comporter 14 chiffres."); return; }
    setErreur(""); setBusy(true);
    try {
      const ok = await onDeclarer(partner.id, {
        nom: form.nom.trim(), prenom: form.prenom.trim(),
        telephone: form.telephone.trim(), reseau: form.reseau.trim(),
        siret: form.siret.replace(/\D/g, ""),
      });
      if (ok !== false) {
        setForm({ nom: "", prenom: "", telephone: "", reseau: "", siret: "" });
        setOuvert(false); setEnvoye(true);
        setTimeout(() => setEnvoye(false), 6000);
      }
    } finally { setBusy(false); }
  }

  const champ = (cle, label) => (
    <div>
      <label className="block text-xs text-gray-500 mb-1">{label}</label>
      <input value={form[cle]} onChange={e => setForm(f => ({ ...f, [cle]: e.target.value }))}
        className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
    </div>
  );

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-6">
      <div className="font-display font-bold fa-navy text-lg mb-1 flex items-center gap-2 flex-wrap">
        🤝 Parrainer c'est gagner +
        <TrendingUp size={20} className="text-emerald-600" strokeWidth={2.5} />
      </div>
      <p className="text-sm fa-navy font-medium mb-1">
        Recevez {Math.round(PARRAINAGE_TAUX * 100)} % du chiffre d'affaires qu'il générera*
      </p>
      <p className="text-xs text-gray-400 mb-4">
        *Seuls les confrères inconnus de notre réseau sont éligibles.
      </p>

      {envoye && (
        <div className="flex items-start gap-2 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2.5 mb-4">
          <Check size={14} className="text-emerald-600 shrink-0 mt-0.5" />
          <span className="text-xs text-emerald-800">Déclaration enregistrée. Frangola revient vers vous après vérification.</span>
        </div>
      )}

      {!ouvert ? (
        <button onClick={() => setOuvert(true)}
          className="fa-bg-gold fa-navy text-sm font-medium px-5 py-2.5 rounded-lg transition">
          Présenter un confrère
        </button>
      ) : (
        <div className="space-y-3">
          <div className="grid sm:grid-cols-2 gap-3">
            {champ("nom", "Nom")}
            {champ("prenom", "Prénom")}
            {champ("telephone", "Téléphone")}
            {champ("reseau", "Réseau / agence")}
          </div>
          {champ("siret", "N° SIRET (14 chiffres)")}
          <p className="text-xs text-gray-400">Le SIRET nous permet de vérifier que ce confrère n'est pas déjà référencé.</p>
          {erreur && <div className="text-xs text-red-600">{erreur}</div>}
          <div className="flex gap-2">
            <button onClick={envoyer} disabled={busy}
              className="fa-bg-teal disabled:opacity-50 text-sm font-medium px-5 py-2 rounded-lg transition">
              {busy ? "Envoi…" : "Envoyer la déclaration"}
            </button>
            <button onClick={() => { setOuvert(false); setErreur(""); }}
              className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
          </div>
        </div>
      )}

      {declarations.length > 0 && (
        <div className="mt-5 pt-4 border-t border-gray-100 space-y-2">
          <div className="text-xs font-semibold fa-navy mb-1">Vos déclarations</div>
          {declarations.map(d => (
            <div key={d.id} className="fa-bg-offwhite rounded-lg px-3 py-2.5">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <span className="text-sm fa-navy font-bold">{d.prenom} {(d.nom || "").toUpperCase()}</span>
                <span className="flex items-center gap-2 ml-auto">
                  {/* Ce que ce filleul a rapporté au parrain depuis le début :
                      la promesse du parrainage, rendue tangible. */}
                  {d.statut === "valide" && d.partnerId && (() => {
                    const gain = caGenerePar(d.partnerId) * PARRAINAGE_TAUX;
                    return (
                      <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${gain > 0.005 ? "fa-bg-gold fa-navy" : "bg-gray-100 text-gray-400"}`}
                        title="Votre part de 10 % sur le chiffre d'affaires encaissé grâce à ce confrère">
                        {gain > 0.005 ? `+${fmtEuroPrecis(gain)}` : "pas encore de production"}
                      </span>
                    );
                  })()}
                  <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                    d.statut === "valide" ? "bg-emerald-50 text-emerald-700"
                    : d.statut === "refuse" ? "bg-red-50 text-red-700"
                    : "bg-amber-50 text-amber-700"}`}>
                    {d.statut === "valide" ? "Validée" : d.statut === "refuse" ? "Refusée" : "En cours de vérification"}
                  </span>
                </span>
              </div>
              <div className="text-xs text-gray-400 mt-0.5">Déclaré le {fmtDate(d.at)}{d.reseau && ` · ${d.reseau}`}</div>
              {d.statut === "refuse" && d.motif && (
                <div className="text-xs text-red-700 mt-1.5">{d.motif}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
// Bannière de challenge dans l'espace du partenaire. Elle n'a d'intérêt que
// si elle dit combien il en reste et combien de temps : « plus que 2 avant le
// 30 » agit, « participez à notre challenge » n'agit pas.
function BanniereChallenge({ challenge, partner, dossiers }) {
  if (!challenge?.actif || !challenge.debut || !challenge.fin || !challenge.recompense) return null;
  const debut = new Date(challenge.debut + "T00:00:00").getTime();
  const fin = new Date(challenge.fin + "T23:59:59").getTime();
  if (!(fin > debut) || Date.now() > fin || Date.now() < debut) return null;

  const objectif = Math.max(1, Number(challenge.objectif) || 1);
  const n = (dossiers || []).filter(d => {
    const t = dateGain(d);
    return t !== null && t >= debut && t <= fin;
  }).length;
  const restants = Math.max(0, objectif - n);
  const jours = Math.max(0, Math.ceil((fin - Date.now()) / 86400000));
  const pct = Math.min(100, Math.round((n / objectif) * 100));
  const gagne = n >= objectif;
  const dateFin = new Date(fin).toLocaleDateString("fr-FR", { day: "numeric", month: "long" });

  return (
    <div className={`rounded-2xl p-5 mb-6 ${gagne ? "bg-emerald-50 border border-emerald-300" : "fa-bg-gold"}`}>
      <div className="flex items-baseline justify-between gap-2 flex-wrap mb-2">
        <span className="font-display font-semibold fa-navy">
          {gagne ? "🏆 Objectif atteint !" : "🎯 " + (challenge.titre || "Challenge en cours")}
        </span>
        <span className="text-xs text-teal-900/70">
          jusqu'au {dateFin} · {jours} jour{jours > 1 ? "s" : ""} restant{jours > 1 ? "s" : ""}
        </span>
      </div>

      <div className="text-sm fa-navy mb-2">
        {gagne
          ? <>Vous avez souscrit {n} dossier{n > 1 ? "s" : ""} — <strong>{challenge.recompense}</strong> vous revient. Nous vous contactons.</>
          : <>Plus que <strong>{restants} dossier{restants > 1 ? "s" : ""} souscrit{restants > 1 ? "s" : ""}</strong> pour gagner <strong>{challenge.recompense}</strong>.</>}
      </div>

      <div className="h-3 bg-white/60 rounded-full overflow-hidden">
        <div className={`h-full ${gagne ? "bg-emerald-500" : "fa-bg-teal"}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="text-xs text-teal-900/70 mt-1">{n} / {objectif} dossiers souscrits</div>
    </div>
  );
}

function PartnerDashboard({ partner, dossiers, challenge, onLogout, onCreateDossier, onDeclarerParrainage, onAddExtraDoc, onUploadDocToSlot, onRemoveDoc, onRemoveExtraDoc, onUploadRib, onUploadFacture, onSetGoal, onMarkMessageRead, onUpdateDossierClient, busy }) {
  const [tab, setTabRaw] = useState(() => getStoredTab("adp:partnerTab", "encours"));
  const setTab = (t) => { setTabRaw(t); setStoredTab("adp:partnerTab", t); };
  const [showForm, setShowForm] = useState(false);
  const [filtrePaiement, setFiltrePaiement] = useState("tous");
  const [clientFirstName, setClientFirstName] = useState("");
  const [clientLastName, setClientLastName] = useState("");
  const [clientPhone, setClientPhone] = useState("");
  const [hasCoEmprunteur, setHasCoEmprunteur] = useState(false);
  const [coClientFirstName, setCoClientFirstName] = useState("");
  const [coClientLastName, setCoClientLastName] = useState("");
  const [coClientPhone, setCoClientPhone] = useState("");
  const [files, setFiles] = useState({ offre: null, tableau: null, cni: null });
  // Déclaration du partenaire : le client sait que ses pièces nous sont
  // transmises. L'accord se noue entre eux ; ici on l'enregistre, daté.
  const [clientInforme, setClientInforme] = useState(false);

  function isFormComplete() {
    return clientInforme;
  }
  async function submit() {
    if (!isFormComplete()) return;
    const ok = await onCreateDossier(
      clientFirstName.trim(), clientLastName.trim(), clientPhone.trim(), files,
      hasCoEmprunteur, coClientLastName.trim(), coClientFirstName.trim(), coClientPhone.trim(),
      true
    );
    if (ok) {
      setShowForm(false); setClientFirstName(""); setClientLastName(""); setClientPhone(""); setFiles({ offre: null, tableau: null, cni: null });
      setHasCoEmprunteur(false); setCoClientFirstName(""); setCoClientLastName(""); setCoClientPhone("");
      setClientInforme(false);
    }
  }

  const [extraDocOpenId, setExtraDocOpenId] = useState(null);
  const [extraDocType, setExtraDocType] = useState("autre");
  const [editingDossierId, setEditingDossierId] = useState(null);
  const [editDossierForm, setEditDossierForm] = useState({});
  function startEditDossier(d) {
    setEditingDossierId(d.id);
    setEditDossierForm({
      clientFirstName: d.clientFirstName || "", clientLastName: d.clientLastName || "", clientPhone: d.clientPhone || "",
      hasCoEmprunteur: !!d.hasCoEmprunteur, coClientLastName: d.coClientLastName || "", coClientFirstName: d.coClientFirstName || "", coClientPhone: d.coClientPhone || "",
    });
  }
  async function saveEditDossier(id) {
    await onUpdateDossierClient(id, editDossierForm);
    setEditingDossierId(null);
  }
  const [extraDocLabel, setExtraDocLabel] = useState("");
  const [extraDocFile, setExtraDocFile] = useState(null);
  async function submitExtraDoc(dossierId) {
    if (!extraDocFile) return;
    const ok = extraDocType === "autre"
      ? await onAddExtraDoc(dossierId, extraDocLabel.trim(), extraDocFile)
      : await onUploadDocToSlot(dossierId, extraDocType, extraDocFile);
    if (ok) { setExtraDocOpenId(null); setExtraDocLabel(""); setExtraDocFile(null); setExtraDocType("autre"); }
  }

  const [factureFile, setFactureFile] = useState(null);
  const [factureMontant, setFactureMontant] = useState("");
  const [factureBusy, setFactureBusy] = useState(false);
  const [factureErreur, setFactureErreur] = useState("");
  async function submitFacture() {
    if (!factureFile) { setFactureErreur("Choisissez d'abord un fichier PDF."); return; }
    setFactureErreur(""); setFactureBusy(true);
    try {
      const ok = await onUploadFacture(partner.id, factureFile, factureMontant);
      if (ok) { setFactureFile(null); setFactureMontant(""); }
    } finally { setFactureBusy(false); }
  }

  const [ribFile, setRibFile] = useState(null);
  const [ribBusy, setRibBusy] = useState(false);
  async function submitRib() {
    if (!ribFile) return;
    setRibBusy(true);
    try {
      const ok = await onUploadRib(partner.id, ribFile);
      if (ok) setRibFile(null);
    } finally { setRibBusy(false); }
  }

  useEffect(() => {
    const unread = dossiers.filter(d => d.partnerMessage && !d.partnerMessageRead);
    if (unread.length === 0) return;
    const t = setTimeout(() => { unread.forEach(d => onMarkMessageRead(d.id)); }, 2500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dossiers.map(d => d.id + ":" + (d.partnerMessage || "")).join(",")]);

  const [editingGoal, setEditingGoal] = useState(false);
  const [goalDraft, setGoalDraft] = useState(partner.monthlyGoal || "");
  async function saveGoal() {
    await onSetGoal(partner.id, goalDraft === "" ? null : Number(goalDraft));
    setEditingGoal(false);
  }

  return (
    <div className="min-h-screen">
      <header className="px-6 py-4 flex items-center justify-between border-b border-gray-100 bg-white">
        <Logo size="text-lg" />
        <div className="flex items-center gap-4">
          <div className="text-right hidden sm:block">
            <div className="text-sm fa-navy flex items-center gap-2 justify-end">
              <span className="font-bold">{up(partner.name)} {partner.firstName}</span>
              {partner.company && (
                <span className="flex items-center gap-1.5 font-medium">
                  - {afficheReseau(partner.company)}
                  {reseauLogoFor(partner.company) && (
                    <img src={reseauLogoFor(partner.company).data} alt="" className="w-8 h-8 rounded object-contain" />
                  )}
                </span>
              )}
            </div>
          </div>
          <button onClick={onLogout} className="text-gray-400 hover:text-red-600"><LogOut size={18} /></button>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8">
        <div className="flex gap-2 mb-6 overflow-x-auto pb-1 -mx-1 px-1 sm:flex-wrap sm:overflow-visible">
          <button onClick={() => setTab("encours")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "encours" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            Dossiers en cours
            {(() => { const n = dossiers.filter(d => !["Souscrit", "Bordereau émis", "Payé", "KO"].includes(d.status)).length;
              return n > 0 && <span className={`text-[10px] font-bold rounded-full w-4 h-4 flex items-center justify-center ${tab === "encours" ? "bg-white/25" : "fa-bg-gold fa-navy"}`}>{n}</span>; })()}
            {dossiers.filter(d => !["Souscrit", "Bordereau émis", "Payé", "KO"].includes(d.status) && d.partnerMessage && !d.partnerMessageRead).length > 0 && (
              <span className="w-2 h-2 rounded-full bg-red-500" title="Message non lu" />
            )}
          </button>
          <button onClick={() => setTab("clotures")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "clotures" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            Dossiers clôturés
            {(() => { const n = dossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé", "KO"].includes(d.status)).length;
              return n > 0 && <span className={`text-[10px] font-bold rounded-full w-4 h-4 flex items-center justify-center ${tab === "clotures" ? "bg-white/25" : "bg-gray-100 text-gray-500"}`}>{n}</span>; })()}
            {dossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé", "KO"].includes(d.status) && d.partnerMessage && !d.partnerMessageRead).length > 0 && (
              <span className="w-2 h-2 rounded-full bg-red-500" title="Message non lu" />
            )}
          </button>
          <button onClick={() => setTab("analytique")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "analytique" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <BarChart3 size={15} /> Ma Production
          </button>
          <button onClick={() => setTab("facturation")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "facturation" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <Download size={15} /> Facturation
            {(partner.factures || []).some(f => f.statut === "À corriger") && (
              <span className="w-2 h-2 rounded-full bg-red-500" title="Une facture est à corriger" />
            )}
          </button>
          <button onClick={() => setTab("contrat")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "contrat" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <FileCheck2 size={15} /> Mon contrat
          </button>
                    <button onClick={() => setTab("parrainage")}
            className={`flex items-center gap-1.5 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "parrainage" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            🤝 Parrainage
          </button>
        </div>

        <BanniereChallenge challenge={challenge} partner={partner} dossiers={dossiers} />

        {(tab === "encours" || tab === "clotures") && (
        <>
        <div className="flex items-center justify-between mb-6">
          <h1 className="font-display text-xl font-semibold fa-navy">{tab === "encours" ? "Dossiers en cours" : "Dossiers clôturés"}</h1>
          {tab === "encours" && (
            <button onClick={() => setShowForm(v => !v)}
              className="flex items-center gap-1.5 fa-bg-gold fa-navy font-medium text-sm px-4 py-2 rounded-full transition">
              <Plus size={16} /> Nouveau dossier
            </button>
          )}
        </div>

        {tab === "clotures" && (() => {
          const closedAll = dossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé", "KO"].includes(d.status));
          if (closedAll.length === 0) return null;
          const compte = (etat) => etat === "tous" ? closedAll.length : closedAll.filter(d => etatPaiement(d) === etat).length;
          const puces = [
            ["tous", "Tous"],
            ["avenir", "Paiement à venir"],
            ["partiel", "Paiement partiel"],
            ["solde", "Soldés"],
            ["ko", "Sans suite"],
          ].filter(([v]) => v === "tous" || compte(v) > 0);
          if (puces.length <= 2) return null;
          return (
            <div className="flex flex-wrap gap-2 mb-5">
              {puces.map(([val, lib]) => (
                <button key={val} onClick={() => setFiltrePaiement(val)}
                  className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full transition ${
                    filtrePaiement === val ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
                  {lib}
                  <span className={`text-[10px] font-bold rounded-full px-1.5 ${filtrePaiement === val ? "bg-white/25" : "bg-gray-100 text-gray-500"}`}>
                    {compte(val)}
                  </span>
                </button>
              ))}
            </div>
          );
        })()}

        {tab === "encours" && showForm && (
          <div className="bg-white border border-gray-200 rounded-2xl p-6 mb-8 shadow-sm">
            <h3 className="font-display font-semibold fa-navy mb-4">Déposer un nouveau dossier</h3>
            <div className="grid sm:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium fa-navy mb-1">Nom du client</label>
                <input value={clientLastName} onChange={e => setClientLastName(e.target.value)}
                  placeholder="Nom" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
              </div>
              <div>
                <label className="block text-sm font-medium fa-navy mb-1">Prénom du client</label>
                <input value={clientFirstName} onChange={e => setClientFirstName(e.target.value)}
                  placeholder="Prénom" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
              </div>
              <div>
                <label className="block text-sm font-medium fa-navy mb-1">N° de téléphone du client</label>
                <input value={clientPhone} onChange={e => setClientPhone(e.target.value)} type="tel"
                  placeholder="06 12 34 56 78" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
              </div>
            </div>
            <label className="flex items-center gap-2 text-sm text-gray-600 mb-4">
              <input type="checkbox" checked={hasCoEmprunteur} onChange={e => setHasCoEmprunteur(e.target.checked)}
                className="rounded border-gray-300" />
              Co-emprunteur
            </label>
            {hasCoEmprunteur && (
              <div className="grid sm:grid-cols-3 gap-4 mb-4 bg-gray-50 rounded-lg p-4">
                <div>
                  <label className="block text-sm font-medium fa-navy mb-1">Nom du co-emprunteur</label>
                  <input value={coClientLastName} onChange={e => setCoClientLastName(e.target.value)}
                    placeholder="Nom" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium fa-navy mb-1">Prénom du co-emprunteur</label>
                  <input value={coClientFirstName} onChange={e => setCoClientFirstName(e.target.value)}
                    placeholder="Prénom" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                </div>
                <div>
                  <label className="block text-sm font-medium fa-navy mb-1">Téléphone du co-emprunteur</label>
                  <input value={coClientPhone} onChange={e => setCoClientPhone(e.target.value)} type="tel"
                    placeholder="06 12 34 56 78" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                </div>
              </div>
            )}
            {clientLastName.trim() && dossiers.some(d => d.clientLastName?.trim().toLowerCase() === clientLastName.trim().toLowerCase() && d.clientFirstName?.trim().toLowerCase() === clientFirstName.trim().toLowerCase()) && (
              <div className="text-xs text-orange-700 bg-orange-50 border border-orange-200 rounded-lg px-3 py-2 mb-4">
                ⚠ Vous avez déjà déposé un dossier pour ce client.
              </div>
            )}
            <div className="grid sm:grid-cols-3 gap-4 mb-5">
              <FileDrop label="Offre de prêt" file={files.offre} onChange={f => setFiles(s => ({ ...s, offre: f }))} />
              <FileDrop label="Tableau d'amortissement" file={files.tableau} onChange={f => setFiles(s => ({ ...s, tableau: f }))} />
              <FileDrop label="Carte d'identité" file={files.cni} onChange={f => setFiles(s => ({ ...s, cni: f }))} />
            </div>
            <label className="flex items-start gap-2.5 text-sm text-gray-600 bg-teal-50 border border-teal-200 rounded-lg px-3 py-2.5 mb-4 cursor-pointer select-none">
              <input type="checkbox" checked={clientInforme} onChange={e => setClientInforme(e.target.checked)}
                className="mt-0.5 accent-teal-600" />
              <span>
                Le client est informé que ses coordonnées et ses pièces sont transmises à Frangola pour
                l'étude de son assurance de prêt, et ne s'y oppose pas.
                <span className="block text-xs text-gray-400 mt-0.5">
                  Obligatoire. Votre déclaration est enregistrée avec la date du dépôt.
                </span>
              </span>
            </label>
            <div className="flex gap-3 items-center">
              <button onClick={submit} disabled={busy || !isFormComplete()}
                title={!clientInforme ? "Cochez la déclaration ci-dessus pour déposer le dossier" : ""}
                className="fa-bg-teal disabled:opacity-50 text-white text-sm font-medium px-5 py-2 rounded-lg transition">
                {busy ? "Envoi…" : "Déposer le dossier"}
              </button>
              <button onClick={() => setShowForm(false)} className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
            </div>
          </div>
        )}

        {(() => {
          const CLOSED = ["Souscrit", "Bordereau émis", "Payé", "KO"];
          // Dans les dossiers clôturés, ce qui compte n'est plus l'avancement
          // mais l'argent : on regroupe par état de paiement, ce qui reste dû
          // en tête.
          const ORDRE_PAIEMENT = { avenir: 0, partiel: 1, solde: 2, encours: 3, ko: 4 };
          let visibleDossiers = dossiers.filter(d => tab === "clotures" ? CLOSED.includes(d.status) : !CLOSED.includes(d.status));
          if (tab === "clotures") {
            if (filtrePaiement !== "tous") visibleDossiers = visibleDossiers.filter(d => etatPaiement(d) === filtrePaiement);
            visibleDossiers = [...visibleDossiers].sort((a, b) =>
              (ORDRE_PAIEMENT[etatPaiement(a)] ?? 9) - (ORDRE_PAIEMENT[etatPaiement(b)] ?? 9)
              || b.createdAt - a.createdAt);
          }
          return (
            <>
              {visibleDossiers.length === 0 && !(tab === "encours" && showForm) && (
                <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">
                  {tab === "clotures" ? "Aucun dossier clôturé pour l'instant." : "Aucun dossier en cours. Cliquez sur \"Nouveau dossier\" pour commencer."}
                </div>
              )}

              <div className="space-y-4">
                {visibleDossiers.sort((a, b) => b.createdAt - a.createdAt).map(d => (
            <div key={d.id} className="bg-white border border-gray-200 rounded-2xl p-3.5 sm:p-5 shadow-sm">
              {editingDossierId === d.id ? (
                <div className="mb-4 space-y-2">
                  <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2">
                    <input value={editDossierForm.clientLastName}
                      onChange={e => setEditDossierForm(f => ({ ...f, clientLastName: e.target.value }))}
                      placeholder="Nom" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-32 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    <input value={editDossierForm.clientFirstName}
                      onChange={e => setEditDossierForm(f => ({ ...f, clientFirstName: e.target.value }))}
                      placeholder="Prénom" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-32 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    <input value={editDossierForm.clientPhone}
                      onChange={e => setEditDossierForm(f => ({ ...f, clientPhone: e.target.value }))}
                      type="tel" placeholder="Téléphone" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  </div>
                  <label className="flex items-center gap-2 text-xs text-gray-600">
                    <input type="checkbox" checked={editDossierForm.hasCoEmprunteur}
                      onChange={e => setEditDossierForm(f => ({ ...f, hasCoEmprunteur: e.target.checked }))}
                      className="rounded border-gray-300" />
                    Co-emprunteur
                  </label>
                  {editDossierForm.hasCoEmprunteur && (
                    <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 bg-violet-50 border border-violet-200 rounded-lg p-2">
                      <input value={editDossierForm.coClientLastName}
                        onChange={e => setEditDossierForm(f => ({ ...f, coClientLastName: e.target.value }))}
                        placeholder="Nom co-emprunteur" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                      <input value={editDossierForm.coClientFirstName}
                        onChange={e => setEditDossierForm(f => ({ ...f, coClientFirstName: e.target.value }))}
                        placeholder="Prénom co-emprunteur" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                      <input value={editDossierForm.coClientPhone}
                        onChange={e => setEditDossierForm(f => ({ ...f, coClientPhone: e.target.value }))}
                        type="tel" placeholder="Téléphone" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    </div>
                  )}
                  <div className="flex gap-2">
                    <button onClick={() => saveEditDossier(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                    <button onClick={() => setEditingDossierId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                  <div>
                    <div className="font-bold fa-navy flex items-center gap-2 flex-wrap">
                      {clientName(d)} <CoEmprunteurBadge d={d} />
{!dossierVerrouille(d) && (
                        <button onClick={() => startEditDossier(d)} className="fa-tap text-xs fa-teal-text hover:underline font-normal">Modifier</button>
                      )}
                    </div>
                    <div className="text-xs text-gray-400">Déposé le {fmtDate(d.createdAt)}{d.clientPhone && ` · ${d.clientPhone}`}</div>
                  </div>
                  <StatusBadge status={d.status} />
                  <PaiementBadge dossier={d} />
                </div>
              )}
              {d.status === "KO" && d.koReason && (
                <div className="mb-4 text-sm bg-red-50 border border-red-200 rounded-lg px-3 py-2.5 text-red-800">
                  <strong>Motif :</strong> {d.koReason === "Autre" ? (d.koReasonDetail || "Autre") : d.koReason}
                </div>
              )}
              {d.partnerMessage && (
                <div className="mb-4 flex items-start justify-between gap-2 text-sm fa-navy bg-teal-50 border border-teal-200 rounded-lg px-3 py-2.5">
                  <div className="flex items-start gap-2">
                    💬 <span>{d.partnerMessage}</span>
                  </div>
                  <span className={`text-xs whitespace-nowrap shrink-0 flex items-center gap-1 ${d.partnerMessageRead ? "text-gray-400" : "text-amber-700 font-semibold"}`}>
                    {d.partnerMessageRead ? <><CheckCircle2 size={12} /> Lu</> : <><span className="fa-bg-gold w-2 h-2 rounded-full" /> Non lu</>}
                  </span>
                </div>
              )}
              <Stepper status={d.status} />
              <div className="flex flex-wrap gap-2 mt-4">
                {Object.keys(DOC_LABELS).map(k => d.docs[k] && (
                  <span key={k} className="text-xs fa-bg-offwhite border border-gray-200 text-gray-600 px-2.5 py-1 rounded-full flex items-center gap-1">
                    <button onClick={() => previewStoredFile(d.docs[k].key)} className="flex items-center gap-1 hover:fa-teal-text transition">
                      <FileText size={12} /> {DOC_LABELS[k]}
                    </button>
                    {!dossierVerrouille(d) && (
                      <button onClick={() => onRemoveDoc(d.id, k)} className="fa-tap text-gray-400 hover:text-red-600 ml-0.5" title="Retirer ce document">
                        <X size={12} />
                      </button>
                    )}
                  </span>
                ))}
                {(d.extraDocs || []).map((ed, i) => (
                  <span key={i} className="text-xs bg-teal-50 border border-teal-200 fa-teal-text px-2.5 py-1 rounded-full flex items-center gap-1">
                    <button onClick={() => previewStoredFile(ed.key)} className="flex items-center gap-1 hover:underline">
                      <FileText size={12} /> {ed.label}
                    </button>
                    {!dossierVerrouille(d) && (
                      <button onClick={() => onRemoveExtraDoc(d.id, i)} className="fa-tap text-teal-500 hover:text-red-600 ml-0.5" title="Retirer ce document">
                        <X size={12} />
                      </button>
                    )}
                  </span>
                ))}
              </div>
              {dossierVerrouille(d) && d.status !== "KO" && (
                <div className="text-xs text-gray-400 mt-2 flex items-start gap-1.5">
                  <Shield size={12} className="mt-0.5 shrink-0" />
                  <span>
                    Le dossier est engagé auprès de l'assureur : le nom du client et les pièces déjà
                    transmises ne sont plus modifiables. Vous pouvez toujours ajouter un document.
                  </span>
                </div>
              )}

              {d.status !== "KO" && (
                extraDocOpenId === d.id ? (
                  <div className="mt-3 fa-bg-offwhite rounded-lg p-3">
                    <div className="flex flex-wrap gap-2 items-center">
                      <select value={extraDocType} onChange={e => setExtraDocType(e.target.value)}
                        className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500">
                        {Object.keys(DOC_LABELS).map(k => (
                          <option key={k} value={k} disabled={!!d.docs?.[k]}>{DOC_LABELS[k]}{d.docs?.[k] ? " (déjà déposée)" : ""}</option>
                        ))}
                        <option value="autre">Autre pièce</option>
                      </select>
                      {extraDocType === "autre" && (
                        <input value={extraDocLabel} onChange={e => setExtraDocLabel(e.target.value)}
                          placeholder="Nom de la pièce (ex. Avenant, Quittance…)"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm flex-1 min-w-[160px] focus:outline-none focus:ring-2 focus:ring-teal-500" />
                      )}
                      <label className="text-sm border border-gray-300 rounded-lg px-3 py-2 cursor-pointer bg-white hover:border-teal-400 transition flex items-center gap-2">
                        {extraDocFile ? extraDocFile.name : "Choisir un fichier"}
                        <input type="file" accept="application/pdf,image/*" className="hidden" onChange={e => setExtraDocFile(e.target.files?.[0] || null)} />
                      </label>
                      {extraDocFile && (
                        <button type="button" onClick={() => setExtraDocFile(null)} className="fa-tap text-gray-400 hover:text-red-600" title="Retirer le fichier">
                          <X size={16} />
                        </button>
                      )}
                    </div>
                    <div className="flex gap-2 mt-2">
                      <button onClick={() => submitExtraDoc(d.id)} disabled={busy || !extraDocFile}
                        className="fa-bg-teal disabled:opacity-50 text-xs font-medium px-4 py-1.5 rounded-lg transition">
                        {busy ? "Envoi…" : "Ajouter la pièce"}
                      </button>
                      <button onClick={() => { setExtraDocOpenId(null); setExtraDocFile(null); setExtraDocLabel(""); setExtraDocType("autre"); }}
                        className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                    </div>
                  </div>
                ) : (
                  <button onClick={() => setExtraDocOpenId(d.id)}
                    className="mt-3 flex items-center gap-1.5 text-xs fa-teal-text hover:underline">
                    <Upload size={13} /> Déposer un document
                  </button>
                )
              )}
              {d.bordereau && (
                <button onClick={() => downloadStoredFile(d.bordereau.key, d.bordereau.name)}
                  className="mt-4 flex items-center gap-2 text-sm font-medium text-violet-700 bg-violet-50 hover:bg-violet-100 px-3 py-2 rounded-lg transition">
                  <Download size={15} /> Télécharger le bordereau de commission
                </button>
              )}
              {d.status !== "KO" && d.commissionAmount != null && (() => {
                // Le montant total et son rythme de versement sont montrés
                // ENSEMBLE. Afficher « 500 € » puis virer 41,67 € est le plus
                // sûr moyen de perdre la confiance d'un apporteur.
                const lignes = echeancesRetrocession([d]);
                const recues = lignes.filter(x => x.recu);
                const aVenir = lignes.filter(x => !x.recu);
                const percu = recues.reduce((sm, x) => sm + x.montant, 0);
                const reste = aVenir.reduce((sm, x) => sm + x.montant, 0);
                const fractionne = lignes.length > 1;
                const prochaine = aVenir.filter(x => x.datePrevue)
                  .sort((a, b) => a.datePrevue.localeCompare(b.datePrevue))[0];
                const dateFr = (iso) => fmtDate(new Date(iso + "T12:00:00").getTime());

                return (
                  <div className={`mt-3 px-3 py-2.5 rounded-lg w-fit max-w-full ${percu > 0.005 ? "fa-bg-gold fa-navy" : "bg-teal-50 border border-teal-200 fa-teal-text"}`}>
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className="text-xs font-medium opacity-70">💶 Votre rémunération</span>
                      <span className="font-display text-2xl font-bold">{fmtEuroPrecis(d.commissionAmount)}</span>
                      {fractionne && (
                        <span className="text-xs opacity-80">versée en {lignes.length} fois de {fmtEuroPrecis(lignes[0].montant)}</span>
                      )}
                    </div>
                    {fractionne && (
                      <div className="text-xs mt-1 opacity-80">
                        {recues.length > 0
                          ? `${recues.length} versement${recues.length > 1 ? "s" : ""} déjà effectué${recues.length > 1 ? "s" : ""} — ${fmtEuroPrecis(percu)} perçus, ${fmtEuroPrecis(reste)} à venir.`
                          : `Aucun versement pour l'instant — ${fmtEuroPrecis(reste)} à venir.`}
                        {prochaine && ` Prochain le ${dateFr(prochaine.datePrevue)}.`}
                      </div>
                    )}
                    {fractionne && (
                      <div className="text-xs mt-1 opacity-70">
                        L'assureur nous reverse ces honoraires au même rythme : nous vous les transmettons dès réception.
                      </div>
                    )}
                    {!fractionne && percu > 0.005 && (
                      <div className="text-xs mt-1 opacity-80">
                        Versée{d.paymentMethod ? ` par ${d.paymentMethod.toLowerCase()}` : ""}{recues[0]?.encaisseLe ? ` le ${dateFr(recues[0].encaisseLe)}` : (d.paymentDate ? ` le ${dateFr(d.paymentDate)}` : "")}.
                      </div>
                    )}
                    {!fractionne && percu < 0.005 && prochaine && (
                      <div className="text-xs mt-1 opacity-80">Versement prévu le {dateFr(prochaine.datePrevue)}.</div>
                    )}
                  </div>
                );
              })()}
              {d.status === "KO" && (
                <div className="mt-4 flex items-center gap-2 text-sm font-medium text-red-700 bg-red-50 px-3 py-2 rounded-lg">
                  <X size={15} /> Dossier clôturé sans suite
                </div>
              )}
            </div>
          ))}
              </div>
            </>
          );
        })()}
        </>
        )}

        {tab === "analytique" && (() => {
          const total = dossiers.length;
          const won = dossiers.filter(d => d.status === "Souscrit" || d.status === "Bordereau émis" || d.status === "Payé");
          const paid = dossiers.filter(d => d.status === "Payé");
          const ko = dossiers.filter(d => d.status === "KO");
          // La rémunération est comptée à l'encaissement, pas à la souscription :
          // un dossier réglé en douze fois ne rapporte qu'un douzième par mois.
          const echRetro = echeancesRetrocession(dossiers);
          const echRecues = echRetro.filter(x => x.recu);
          const echAVenir = echRetro.filter(x => !x.recu);
          const totalRemuneration = echRecues.reduce((s, x) => s + x.montant, 0);
          const totalAVenir = echAVenir.reduce((s, x) => s + x.montant, 0);
          // La moyenne se calcule sur la commission TOTALE des dossiers gagnés,
          // pas sur ce qui est déjà encaissé : un dossier réglé en douze fois
          // rapporte autant qu'un autre, il le rapporte simplement plus tard.
          // Sans ça la moyenne s'effondrerait pour un partenaire récent.
          const remunerationAcquise = won.reduce((sm, d) => sm + (d.commissionAmount || 0), 0);
          const avgRemuneration = won.length ? remunerationAcquise / won.length : (partner.flatFee != null ? partner.flatFee : 150);
          const dateEch = (x) => x.encaisseLe ? new Date(x.encaisseLe + "T12:00:00").getTime()
            : (x.dossier.paymentDate ? new Date(x.dossier.paymentDate).getTime() : (x.dossier.updatedAt || x.dossier.createdAt));
          const bilanPar = bilanParrainage(partner.id);
          const revenuPassif = bilanPar.gainTotal;
          const revenuGlobal = totalRemuneration + revenuPassif;
          const transformDenominator = total - ko.length;
          const transformRate = transformDenominator > 0 ? Math.round((paid.length / transformDenominator) * 100) : 0;

          const now = new Date();
          const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
          const earnedThisMonth = echRecues.filter(x => dateEch(x) >= monthStart).reduce((s, x) => s + x.montant, 0);
          const goalProgress = partner.monthlyGoal ? Math.min(100, Math.round((earnedThisMonth / partner.monthlyGoal) * 100)) : 0;
          const dossiersNeededForGoal = partner.monthlyGoal && avgRemuneration > 0 ? Math.ceil(partner.monthlyGoal / avgRemuneration) : null;
          const monthly = [];
          for (let i = 5; i >= 0; i--) {
            const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
            monthly.push({
              name: start.toLocaleDateString("fr-FR", { month: "short", year: "2-digit" }),
              "Rémunération (€)": echRecues.filter(x => {
                const t = dateEch(x);
                return t >= start.getTime() && t < end.getTime();
              }).reduce((s, x) => s + x.montant, 0),
            });
          }

          return (
            <div className="space-y-6">
              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
                  <div className="font-display font-semibold fa-navy flex items-center gap-2"><Target size={17} className="fa-teal-text" /> Objectif du mois</div>
                  {!editingGoal && (
                    <button onClick={() => { setGoalDraft(partner.monthlyGoal || ""); setEditingGoal(true); }} className="text-xs fa-teal-text hover:underline">
                      {partner.monthlyGoal ? "Modifier" : "Définir un objectif"}
                    </button>
                  )}
                </div>
                {editingGoal ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <input type="number" value={goalDraft} onChange={e => setGoalDraft(e.target.value)}
                      placeholder="Montant visé ce mois (€)" className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-56 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    <button onClick={saveGoal} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                    <button onClick={() => setEditingGoal(false)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                  </div>
                ) : partner.monthlyGoal ? (
                  <>
                    <div className="text-sm text-gray-500 mb-2">{fmtEuro(earnedThisMonth)} / {fmtEuro(partner.monthlyGoal)} perçus ce mois-ci</div>
                    <div className="w-full bg-gray-100 rounded-full h-3 overflow-hidden">
                      <div className="h-full fa-bg-gold transition-all" style={{ width: `${goalProgress}%` }} />
                    </div>
                    {dossiersNeededForGoal && (
                      <div className="text-xs text-gray-400 mt-2">
                        Soit environ {dossiersNeededForGoal} dossier{dossiersNeededForGoal > 1 ? "s" : ""} gagné{dossiersNeededForGoal > 1 ? "s" : ""} à votre moyenne actuelle ({fmtEuroPrecis(avgRemuneration)}/dossier).
                      </div>
                    )}
                    {goalProgress >= 100 && <div className="text-xs text-emerald-600 font-semibold mt-2">🎉 Objectif atteint !</div>}
                  </>
                ) : (
                  <div className="text-sm text-gray-400">Aucun objectif défini pour l'instant.</div>
                )}
              </div>

              <div className={`grid gap-4 ${revenuPassif > 0 ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}>
                <div className="fa-bg-teal rounded-2xl p-6">
                  <div className="text-xs text-white/80 mb-1">Rémunération totale perçue</div>
                  <div className="font-display text-3xl font-bold text-white">{fmtEuroPrecis(totalRemuneration)}</div>
                  {totalAVenir > 0.005 && (
                    <div className="text-xs text-white/80 mt-1">+ {fmtEuroPrecis(totalAVenir)} à venir sur vos dossiers en cours</div>
                  )}
                  {revenuPassif > 0 && (
                    <div className="text-xs text-white/70 mt-1">Avec le parrainage : {fmtEuroPrecis(revenuGlobal)}</div>
                  )}
                </div>
                {revenuPassif > 0 && (
                  <div className="fa-bg-pink rounded-2xl p-6">
                    <div className="text-xs text-teal-900/70 mb-1">Revenus passifs — parrainage</div>
                    <div className="font-display text-3xl font-bold fa-navy">{fmtEuro(revenuPassif)}</div>
                    <div className="text-xs text-teal-900/70 mt-1">
                      générés par {bilanPar.actifs} filleul{bilanPar.actifs > 1 ? "s" : ""} actif{bilanPar.actifs > 1 ? "s" : ""} — sans rien faire de plus
                    </div>
                  </div>
                )}
                <div className="fa-bg-gold rounded-2xl p-6">
                  <div className="text-xs text-teal-900/70 mb-1">Rémunération moyenne / dossier gagné</div>
                  <div className="font-display text-3xl font-bold fa-navy">{fmtEuroPrecis(avgRemuneration)}</div>
                </div>
              </div>

              <div className="grid sm:grid-cols-5 gap-4">
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Dossiers déposés</div>
                  <div className="font-display text-2xl font-bold fa-navy">{total}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Dossiers gagnés</div>
                  <div className="font-display text-2xl font-bold text-emerald-600">{won.length}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Dossiers payés</div>
                  <div className="font-display text-2xl font-bold text-green-600">{paid.length}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Taux de transformation</div>
                  <div className="font-display text-2xl font-bold fa-teal-text">{transformRate}%</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Dossiers KO</div>
                  <div className="font-display text-2xl font-bold text-red-500">{ko.length}</div>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-4">Votre rémunération, mois par mois</div>
                <div style={{ width: "100%", height: 200 }}>
                  <ResponsiveContainer>
                    <BarChart data={monthly}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#eee" />
                      <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                      <YAxis tick={{ fontSize: 11 }} width={40} />
                      <Tooltip formatter={(v) => fmtEuro(v)} />
                      <Bar dataKey="Rémunération (€)" fill="#FCD947" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-4">Historique de mes paiements</div>
                {paid.length === 0 ? (
                  <div className="text-sm text-gray-400">Aucun paiement reçu pour l'instant.</div>
                ) : (
                  <div className="space-y-2">
                    {paid.sort((a, b) => (b.paymentDate ? new Date(b.paymentDate).getTime() : b.updatedAt) - (a.paymentDate ? new Date(a.paymentDate).getTime() : a.updatedAt)).map(d => (
                      <div key={d.id} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
                        <div>
                          <div className="text-sm fa-navy font-bold">{clientName(d)}</div>
                          <div className="text-xs text-gray-400">
                            {d.paymentDate ? fmtDate(new Date(d.paymentDate).getTime()) : "—"}{d.paymentMethod && ` · ${d.paymentMethod}`}
                          </div>
                        </div>
                        <span className="text-sm font-bold fa-bg-gold fa-navy px-2.5 py-1 rounded-full">{fmtEuro(d.commissionAmount)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {(() => {
                const bilan = bilanParrainage(partner.id);
                const monParrain = nomParrain(partner.parrainId);
                if (bilan.filleuls.length === 0 && !monParrain) return null;
                return (
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="font-display font-semibold fa-navy mb-1">🤝 Mon parrainage</div>
                    <p className="text-sm text-gray-500 mb-4">
                      Vous percevez {Math.round(PARRAINAGE_TAUX * 100)} % du chiffre d'affaires généré par les confrères que vous avez présentés.
                    </p>
                    {monParrain && (
                      <div className="text-xs text-gray-400 mb-4">Vous avez été parrainé par {monParrain}.</div>
                    )}
                    {bilan.filleuls.length === 0 ? (
                      <div className="text-sm text-gray-400">Vous n'avez pas encore de filleul.</div>
                    ) : (
                      <>
                        <div className="grid sm:grid-cols-3 gap-3 mb-4">
                          <div className="fa-bg-offwhite rounded-xl p-4">
                            <div className="text-xs text-gray-400">Filleuls</div>
                            <div className="font-display text-xl font-bold fa-navy">{bilan.filleuls.length}</div>
                          </div>
                          <div className="fa-bg-offwhite rounded-xl p-4">
                            <div className="text-xs text-gray-400">Dont actifs</div>
                            <div className="font-display text-xl font-bold text-emerald-600">{bilan.actifs}</div>
                          </div>
                          <div className="fa-bg-gold rounded-xl p-4">
                            <div className="text-xs text-teal-900/70">Vos gains de parrainage</div>
                            <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(bilan.gainTotal)}</div>
                          </div>
                        </div>
                        <div className="space-y-2">
                          {bilan.filleuls.slice().sort((a, b) => b.ca - a.ca).map(f => (
                            <div key={f.partner.id} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
                              <div>
                                <div className="text-sm fa-navy font-bold">
                                  {nomPartenaire(f.partner)}
                                </div>
                                <div className="text-xs text-gray-400">
                                  {f.dossiers} dossier{f.dossiers !== 1 ? "s" : ""} · CA généré {fmtEuro(f.ca)}
                                </div>
                              </div>
                              <span className="text-sm font-bold fa-bg-gold fa-navy px-2.5 py-1 rounded-full">{fmtEuroPrecis(f.gain)}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                  </div>
                );
              })()}

              {avgRemuneration > 0 && (
                <div className="fa-bg-pink rounded-2xl p-5">
                  <div className="font-display font-semibold fa-navy mb-1">📈 À vous de jouer</div>
                  <p className="text-sm text-teal-900/80">
                    En moyenne, chaque dossier gagné vous rapporte <strong>{fmtEuroPrecis(avgRemuneration)}</strong>.
                    Un dossier de plus par mois, c'est environ <strong>{fmtEuroPrecis(avgRemuneration * 12)}</strong> de plus sur l'année.
                  </p>
                </div>
              )}
            </div>
          );
        })()}

                {tab === "parrainage" && (
          <ParrainageCard partner={partner} onDeclarer={onDeclarerParrainage} />
        )}
        {tab === "facturation" && (() => {
          const bordereaux = dossiers
            .filter(d => d.bordereau)
            .sort((a, b) => (b.updatedAt || b.createdAt) - (a.updatedAt || a.createdAt));
          const factures = (partner.factures || []).slice().sort((a, b) => b.at - a.at);
          const totalPaye = factures.filter(f => f.statut === "Payée").reduce((s, f) => s + (f.montant || 0), 0);
          const totalAttente = factures.filter(f => f.statut === "Déposée").reduce((s, f) => s + (f.montant || 0), 0);
          const couleurStatut = (s) => s === "Payée" ? "bg-emerald-50 text-emerald-700"
            : s === "À corriger" ? "bg-red-50 text-red-700" : "bg-amber-50 text-amber-700";
          return (
            <div className="space-y-6">
              <div>
                <h1 className="font-display text-xl font-semibold fa-navy">Facturation</h1>
                <p className="text-sm text-gray-500">Vos bordereaux de commission et les factures que vous nous adressez.</p>
              </div>

              {(() => {
                // Deux mécaniques : au forfait, une ligne par dossier réglée en
                // une fois ; au pourcentage, un calendrier mensuel.
                const auForfait = partner.flatFee != null;
                const forfaits = auForfait ? forfaitsRetrocession(partner, dossiers) : [];
                const cal = auForfait ? { mois: [], sansDate: 0 } : calendrierRetrocession(partner, dossiers);
                const lignesVue = auForfait ? forfaits : cal.mois;
                if (lignesVue.length === 0) return null;
                const totalRecu = lignesVue.filter(x => x.etat === "regle")
                  .reduce((sm, x) => sm + (x.versement?.montant || 0), 0);
                const totalAVenir = lignesVue.filter(x => x.etat !== "regle")
                  .reduce((sm, x) => sm + x.montant, 0);
                if (totalRecu < 0.005 && totalAVenir < 0.005) return null;

                return (
                  <div className="bg-white border border-gray-200 rounded-2xl p-6">
                    <div className="font-display font-semibold fa-navy mb-1">Mes rétrocessions</div>
                    <p className="text-sm text-gray-500 mb-4">
                      {auForfait
                        ? "Votre forfait vous est réglé en une seule fois par dossier, dès que Frangola a encaissé le montant correspondant."
                        : "Vos honoraires vous sont reversés au rythme où Frangola les encaisse. Selon le contrat, l'assureur les collecte en une fois ou les étale jusqu'à douze mois."}
                    </p>
                    <div className="grid sm:grid-cols-2 gap-3 mb-4">
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-500 mb-1">Déjà perçu</div>
                        <div className="font-display text-xl font-bold text-emerald-600">{fmtEuroPrecis(totalRecu)}</div>
                      </div>
                      <div className="fa-bg-gold rounded-xl p-4">
                        <div className="text-xs text-teal-900/70 mb-1">À venir</div>
                        <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(totalAVenir)}</div>
                      </div>
                    </div>

                    {lignesVue.length > 0 && (
                      <div className="space-y-1.5">
                        <div className="text-xs font-semibold fa-navy mb-1">
                          {auForfait ? "Vos forfaits, dossier par dossier" : "Calendrier des versements"}
                        </div>
                        {lignesVue.map(m => (
                          <div key={m.cle}
                            className={`flex items-center justify-between gap-2 flex-wrap rounded-lg px-3 py-2 border ${
                              m.etat === "regle" ? "bg-emerald-50 border-emerald-200"
                              : m.etat === "a_regler" ? "fa-bg-gold border-amber-300"
                              : "fa-bg-offwhite border-transparent"}`}>
                            <span className={`text-sm fa-navy font-medium ${auForfait ? "" : "capitalize"}`}>{m.libelle}</span>
                            <span className="text-xs text-gray-500">
                              {m.etat === "regle"
                                ? <>{m.versement.mode === "Carte cadeau" ? "carte cadeau remise" : "versé"} le {fmtDate(new Date(m.versement.dateVirement + "T12:00:00").getTime())}</>
                                : m.etat === "a_regler"
                                  ? "encaissé par Frangola — règlement en préparation"
                                  : (auForfait
                                      ? `${fmtEuroPrecis(m.encaisse)} encaissés sur ${fmtEuroPrecis(m.montant)}`
                                      : `${m.nb} échéance${m.nb > 1 ? "s" : ""}`)}
                            </span>
                            <span className="flex items-center gap-2">
                              {m.etat === "regle" && m.versement.ordre && (
                                <button onClick={() => downloadStoredFile(m.versement.ordre.key, m.versement.ordre.name)}
                                  className="flex items-center gap-1 text-xs font-medium text-emerald-700 hover:underline">
                                  <Download size={12} /> {m.versement.mode === "Carte cadeau" ? "carte cadeau" : "ordre de virement"}
                                </button>
                              )}
                              <span className={`text-sm font-bold ${m.etat === "regle" ? "text-emerald-700" : "fa-navy"}`}>
                                {fmtEuroPrecis(m.etat === "regle" ? m.versement.montant : m.montant)}
                              </span>
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                    {cal.sansDate > 0 && (
                      <div className="text-xs text-gray-400 mt-2">
                        {cal.sansDate} échéance{cal.sansDate > 1 ? "s" : ""} en attente de date d'effet.
                      </div>
                    )}
                  </div>
                );
              })()}

              <div className="bg-white border border-gray-200 rounded-2xl p-6">
                <div className="font-display font-semibold fa-navy mb-1">Mes bordereaux de commission</div>
                <p className="text-sm text-gray-500 mb-4">Émis par Frangola dès la souscription du dossier. Ils justifient le montant à facturer.</p>
                {bordereaux.length === 0 ? (
                  <div className="text-sm text-gray-400">Aucun bordereau pour l'instant.</div>
                ) : (
                  <div className="space-y-2">
                    {bordereaux.map(d => (
                      <div key={d.id} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
                        <div>
                          <div className="text-sm fa-navy font-bold">{clientName(d)}</div>
                          <div className="text-xs text-gray-400">
                            {d.status}{d.caAmount ? ` · commission ${fmtEuro(d.caAmount / 2)}` : ""}
                          </div>
                        </div>
                        <button onClick={() => downloadStoredFile(d.bordereau.key, d.bordereau.name)}
                          className="flex items-center gap-1.5 text-xs font-medium fa-navy fa-bg-gold px-3 py-1.5 rounded-lg transition">
                          <Download size={14} /> Télécharger
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-6">
                <div className="font-display font-semibold fa-navy mb-1">Déposer une facture</div>
                <p className="text-sm text-gray-500 mb-4">Au format PDF, 3,5 Mo maximum. Indiquez le montant TTC pour faciliter le rapprochement.</p>
                <div className="grid sm:grid-cols-3 gap-3 mb-3">
                  <div className="sm:col-span-2">
                    <FileDrop label="Facture PDF" file={factureFile} onChange={setFactureFile} />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-500 mb-1">Montant TTC (€)</label>
                    <input type="number" value={factureMontant} onChange={e => setFactureMontant(e.target.value)}
                      placeholder="0" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  </div>
                </div>
                {factureErreur && <div className="text-xs text-red-600 mb-2">{factureErreur}</div>}
                <button onClick={submitFacture} disabled={factureBusy || busy}
                  className="fa-bg-teal disabled:opacity-50 text-sm font-medium px-5 py-2.5 rounded-lg transition">
                  {factureBusy ? "Envoi…" : "Envoyer la facture"}
                </button>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-6">
                <div className="font-display font-semibold fa-navy mb-4">Mes factures</div>
                {factures.length === 0 ? (
                  <div className="text-sm text-gray-400">Vous n'avez encore déposé aucune facture.</div>
                ) : (
                  <>
                    <div className="grid sm:grid-cols-2 gap-3 mb-4">
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">En attente de règlement</div>
                        <div className="font-display text-xl font-bold fa-navy">{fmtEuro(totalAttente)}</div>
                      </div>
                      <div className="fa-bg-gold rounded-xl p-4">
                        <div className="text-xs text-teal-900/70">Déjà réglé</div>
                        <div className="font-display text-xl font-bold fa-navy">{fmtEuro(totalPaye)}</div>
                      </div>
                    </div>
                    <div className="space-y-2">
                      {factures.map(f => (
                        <div key={f.id} className="fa-bg-offwhite rounded-lg px-3 py-2.5">
                          <div className="flex items-center justify-between flex-wrap gap-2">
                            <button onClick={() => downloadStoredFile(f.key, f.name)}
                              className="text-sm fa-navy font-bold hover:underline text-left">{f.name}</button>
                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${couleurStatut(f.statut)}`}>{f.statut}</span>
                          </div>
                          <div className="text-xs text-gray-400 mt-0.5">
                            Déposée le {fmtDate(f.at)}{f.montant != null ? ` · ${fmtEuro(f.montant)}` : ""}
                          </div>
                          {f.statut === "À corriger" && f.motif && (
                            <div className="text-xs text-red-700 mt-1.5">{f.motif}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>
          );
        })()}

        {tab === "contrat" && (
          <div className="space-y-6 max-w-xl">
            <div className="bg-white border border-gray-200 rounded-2xl p-6">
              <div className="font-display font-semibold fa-navy mb-1 flex items-center gap-2">
                <FileCheck2 size={18} className="fa-teal-text" /> Contrat d'apporteur d'affaires
              </div>
              <p className="text-sm text-gray-500 mb-4">Votre contrat signé par les deux parties, déposé par Frangola Assure.</p>
              {partner.contractFile ? (
                <div className="flex flex-wrap gap-2">
                  <button onClick={() => previewStoredFile(partner.contractFile.key)}
                    className="flex items-center gap-2 text-sm font-medium fa-navy border border-gray-300 hover:border-teal-400 px-4 py-2.5 rounded-lg transition w-fit">
                    <FileCheck2 size={15} /> Aperçu
                  </button>
                  <button onClick={() => downloadStoredFile(partner.contractFile.key, partner.contractFile.name)}
                    className="flex items-center gap-2 text-sm font-medium fa-navy fa-bg-gold px-4 py-2.5 rounded-lg transition w-fit">
                    <Download size={15} /> Télécharger mon contrat signé
                  </button>
                </div>
              ) : (
                <div className="text-sm text-gray-400 bg-gray-50 rounded-lg px-4 py-3">
                  Votre contrat n'a pas encore été déposé par Frangola Assure.
                </div>
              )}
            </div>

            <div className="bg-white border border-gray-200 rounded-2xl p-6">
              <div className="font-display font-semibold fa-navy mb-1">🏦 RIB pour le versement des commissions</div>
              <p className="text-sm text-gray-500 mb-4">Déposez votre RIB pour que Frangola Assure puisse vous verser vos rétrocessions.</p>

              {partner.ribFile && (
                <div className="flex items-center justify-between flex-wrap gap-2 bg-teal-50 border border-teal-200 rounded-lg px-4 py-3 mb-4">
                  <span className="text-sm fa-navy">✅ RIB fourni le {fmtDate(partner.ribFile.uploadedAt)}</span>
                  <button onClick={() => downloadStoredFile(partner.ribFile.key, partner.ribFile.name)}
                    className="text-xs fa-teal-text hover:underline font-medium">Voir le fichier</button>
                </div>
              )}

              <div className="flex flex-wrap items-center gap-2">
                <label className="text-sm border border-gray-300 rounded-lg px-3 py-2 cursor-pointer bg-white hover:border-teal-400 transition flex items-center gap-2">
                  {ribFile ? ribFile.name : (partner.ribFile ? "Remplacer mon RIB" : "Choisir un fichier (PDF ou image)")}
                  <input type="file" accept="application/pdf,image/*" className="hidden" onChange={e => setRibFile(e.target.files?.[0] || null)} />
                </label>
                {ribFile && (
                  <button type="button" onClick={() => setRibFile(null)} className="fa-tap text-gray-400 hover:text-red-600" title="Retirer le fichier">
                    <X size={16} />
                  </button>
                )}
                {ribFile && (
                  <button onClick={submitRib} disabled={ribBusy}
                    className="fa-bg-teal disabled:opacity-50 text-sm font-medium px-4 py-2 rounded-lg transition">
                    {ribBusy ? "Envoi…" : "Envoyer le RIB"}
                  </button>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

const MANDATAIRE_PALETTE = ["#545454", "#8B5CF6", "#0EA5E9", "#F97316", "#059669", "#DC2626", "#DB2777", "#CA8A04"];
let _colorDataRef = null;
function setColorDataRef(d) { _colorDataRef = d; }
function commercialColor(name) {
  if (!name) return "#999";
  if (_colorDataRef) {
    if (name === "Sébastien" && _colorDataRef.settings?.admin?.color) return _colorDataRef.settings.admin.color;
    const found = _colorDataRef.mandataires?.find(mm => mm.name === name);
    if (found?.color) return found.color;
  }
  if (name === "Sébastien") return "#2F448B";
  if (name === "Nelson") return "#545454";
  let hash = 0;
  for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  return MANDATAIRE_PALETTE[hash % MANDATAIRE_PALETTE.length];
}
const COMMERCIAL_COLORS = new Proxy({}, { get: (_, name) => commercialColor(name) });
function commercialLabel(name) {
  if (!name) return name;
  if (_colorDataRef) {
    if (name === "Sébastien" && _colorDataRef.settings?.admin?.firstName) {
      return _colorDataRef.settings.admin.firstName;
    }
    const found = _colorDataRef.mandataires?.find(m => m.name === name);
    if (found?.firstName) return found.firstName;
  }
  return name;
}
function reseauLogoFor(companyName) {
  // En mode discret, un logo d'agence trahirait le réseau aussi sûrement
  // qu'un nom : on n'en affiche aucun.
  if (MODE_DISCRET) return null;
  if (!companyName || !_colorDataRef?.reseaux) return null;
  const found = _colorDataRef.reseaux.find(r => r.name.trim().toLowerCase() === companyName.trim().toLowerCase());
  return found?.logoData ? { data: found.logoData } : null;
}
async function lookupVilleFromCodePostal(codePostal) {
  if (!/^\d{5}$/.test(codePostal)) return null;
  try {
    const res = await fetch(`https://geo.api.gouv.fr/communes?codePostal=${codePostal}&fields=nom,codeDepartement&format=json`);
    if (!res.ok) return null;
    const arr = await res.json();
    if (!arr || arr.length === 0) return null;
    return { ville: arr.map(c => c.nom).join(" / "), departement: arr[0].codeDepartement || null };
  } catch (e) { return null; }
}

const DEPARTEMENTS = [
  ...Array.from({ length: 95 }, (_, i) => i + 1)
    .filter(n => n !== 20)
    .map(n => String(n).padStart(2, "0")),
  "2A", "2B", "971", "972", "973", "974", "976",
].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

function MandataireDashboard({ mandataire, data, onLogout }) {
  const myPartners = data.partners.filter(p => !p.deleted && p.commercial === mandataire.name);
  const myDossiers = data.dossiers.filter(d => myPartners.some(p => p.id === d.partnerId));
  const paid = myDossiers.filter(d => d.status === "Payé");
  const won = myDossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));
  const ko = myDossiers.filter(d => d.status === "KO");
  const totalCa = paid.reduce((s, d) => s + (d.caAmount || 0), 0);
  const totalCommission = paid.reduce((s, d) => s + (d.commissionAmount || 0), 0);
  const caReel = totalCa - totalCommission;
  const maPart = caReel / 2;
  const transformDenom = myDossiers.length - ko.length;
  const transformRate = transformDenom > 0 ? Math.round((paid.length / transformDenom) * 100) : 0;

  const partnerStats = myPartners.map(p => {
    const pd = data.dossiers.filter(d => d.partnerId === p.id);
    const pPaid = pd.filter(d => d.status === "Payé");
    return {
      partner: p, count: pd.length,
      ca: pPaid.reduce((s, d) => s + (d.caAmount || 0), 0),
    };
  }).sort((a, b) => b.count - a.count);

  return (
    <div className="min-h-screen">
      <header className="px-6 py-4 flex items-center justify-between border-b border-gray-100 bg-white">
        <Logo size="text-lg" />
        <div className="flex items-center gap-3">
          <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[mandataire.name] }}>{commercialLabel(mandataire.name)}</span>
          <button onClick={onLogout} className="text-gray-400 hover:text-red-600"><LogOut size={18} /></button>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-6">
        <div>
          <h1 className="font-display text-xl font-semibold fa-navy">Bonjour {mandataire.firstName || up(mandataire.name)} 👋</h1>
          <p className="text-sm text-gray-500">Voici votre production — visible uniquement par vous et Frangola.</p>
        </div>
                <ChallengeBoard data={data}
          commerciaux={["Sébastien", ...data.mandataires.filter(m => !m.deleted).map(m => m.name)]}
          onSetGoals={() => {}} canEdit={false} />

        <div className="grid sm:grid-cols-2 gap-4">
          <div className="fa-bg-teal rounded-2xl p-6">
            <div className="text-xs text-white/80 mb-1">Votre part (mandataire, 50%)</div>
            <div className="font-display text-3xl font-bold text-white">{fmtEuro(maPart)}</div>
          </div>
          <div className="fa-bg-gold rounded-2xl p-6">
            <div className="text-xs text-teal-900/70 mb-1">CA total généré (payé)</div>
            <div className="font-display text-3xl font-bold fa-navy">{fmtEuro(totalCa)}</div>
          </div>
        </div>

        <div className="grid sm:grid-cols-5 gap-4">
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="text-xs text-gray-400 mb-1">Partenaires</div>
            <div className="font-display text-2xl font-bold fa-navy">{myPartners.length}</div>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="text-xs text-gray-400 mb-1">Dossiers</div>
            <div className="font-display text-2xl font-bold fa-navy">{myDossiers.length}</div>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="text-xs text-gray-400 mb-1">Gagnés</div>
            <div className="font-display text-2xl font-bold text-emerald-600">{won.length}</div>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="text-xs text-gray-400 mb-1">Transformation</div>
            <div className="font-display text-2xl font-bold fa-teal-text">{transformRate}%</div>
          </div>
          <div className="bg-white border border-gray-200 rounded-2xl p-5">
            <div className="text-xs text-gray-400 mb-1">KO</div>
            <div className="font-display text-2xl font-bold text-red-500">{ko.length}</div>
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="font-display font-semibold fa-navy mb-4">Vos partenaires</div>
          {partnerStats.length === 0 ? (
            <div className="text-sm text-gray-400">Aucun partenaire ne vous est encore rattaché.</div>
          ) : (
            <div className="space-y-2">
              {partnerStats.map(ps => (
                <div key={ps.partner.id} className="flex items-center justify-between text-sm fa-bg-offwhite rounded-lg px-3 py-2.5">
                  <span className="fa-navy font-bold">{nomPartenaire(ps.partner)}</span>
                  <span className="text-gray-500 text-xs">{ps.count} dossier{ps.count !== 1 ? "s" : ""} · CA {fmtEuro(ps.ca)}</span>
                </div>
              ))}
            </div>
          )}
        </div>

      </main>
    </div>
  );
}

function RegistreParrainages({ data, onTraiter }) {
  const [refusId, setRefusId] = useState(null);
  const [motif, setMotif] = useState(MOTIFS_REFUS[0]);
  const [motifLibre, setMotifLibre] = useState("");
  const decls = (data.parrainages || []).slice().sort((a, b) => b.at - a.at);
  const attente = decls.filter(d => d.statut === "en_attente");
  const traitees = decls.filter(d => d.statut !== "en_attente").slice(0, 10);

  const nomParrainDe = (id) => {
    const p = data.partners.find(x => x.id === id);
    return p ? (nomPartenaire(p)) : "—";
  };

  function confirmerRefus(id) {
    const texte = motif === "Autre" ? motifLibre.trim() : motif;
    onTraiter(id, "refuse", texte || "Déclaration non retenue.");
    setRefusId(null); setMotif(MOTIFS_REFUS[0]); setMotifLibre("");
  }

  if (decls.length === 0) return null;

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-4">
      <div className="font-display font-semibold fa-navy mb-1">
        🤝 Déclarations de parrainage
        {attente.length > 0 && <span className="ml-2 fa-bg-gold fa-navy text-xs font-bold px-2 py-0.5 rounded-full">{attente.length} en attente</span>}
      </div>
      <p className="text-sm text-gray-500 mb-4">Vérifiez les alertes puis validez ou refusez. Rien n'est rattaché sans votre accord.</p>

      {attente.length === 0 && <div className="text-sm text-gray-400 mb-3">Aucune déclaration en attente.</div>}

      <div className="space-y-3">
        {attente.map(d => {
          const alerte = detecterDoublon(d);
          return (
            <div key={d.id} className={`rounded-xl p-3.5 border ${
              alerte.niveau === "rouge" ? "border-red-200 bg-red-50"
              : alerte.niveau === "orange" ? "border-amber-200 bg-amber-50"
              : "border-gray-200 fa-bg-offwhite"}`}>
              <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
                <span className="text-sm fa-navy font-bold">{d.prenom} {(d.nom || "").toUpperCase()}</span>
                <span className="text-xs text-gray-500">présenté par <strong className="fa-navy">{nomParrainDe(d.parrainId)}</strong> le {fmtDate(d.at)}</span>
              </div>
              <div className="text-xs text-gray-500 mb-2">
                {d.telephone} {d.reseau && `· ${d.reseau}`} · SIRET {d.siret}
              </div>

              {alerte.messages.length > 0 && (
                <div className={`text-xs mb-2.5 space-y-0.5 ${alerte.niveau === "rouge" ? "text-red-800" : "text-amber-800"}`}>
                  {alerte.messages.map((m, i) => <div key={i}>⚠ {m}</div>)}
                </div>
              )}

              {refusId === d.id ? (
                <div className="space-y-2">
                  <select value={motif} onChange={e => setMotif(e.target.value)}
                    className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-teal-500">
                    {MOTIFS_REFUS.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                  {motif === "Autre" && (
                    <input value={motifLibre} onChange={e => setMotifLibre(e.target.value)}
                      placeholder="Motif communiqué au parrain"
                      className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  )}
                  <div className="flex gap-2">
                    <button onClick={() => confirmerRefus(d.id)}
                      className="text-xs font-semibold bg-red-600 hover:bg-red-700 text-white px-3 py-1.5 rounded-lg transition">Confirmer le refus</button>
                    <button onClick={() => setRefusId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                  </div>
                </div>
              ) : (
                <div className="flex gap-2">
                  <button onClick={() => onTraiter(d.id, "valide", "")}
                    title="Crée aussitôt la fiche partenaire du filleul, rattachée à son parrain"
                    className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded-lg transition">Valider et créer la fiche</button>
                  <button onClick={() => setRefusId(d.id)}
                    className="text-xs font-semibold bg-white border border-gray-300 hover:border-red-300 text-gray-600 px-3 py-1.5 rounded-lg transition">Refuser</button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {traitees.length > 0 && (
        <div className="mt-4 pt-3 border-t border-gray-100 space-y-1">
          <div className="text-xs font-semibold fa-navy mb-1">Traitées récemment</div>
          {traitees.map(d => (
            <div key={d.id} className="flex items-center justify-between flex-wrap gap-2 text-xs py-1">
              <span className="fa-navy">{d.prenom} {(d.nom || "").toUpperCase()} · {nomParrainDe(d.parrainId)}</span>
              <span className="flex items-center gap-2">
                <span className={d.statut === "valide" ? "text-emerald-700 font-semibold" : "text-red-700"}>
                  {d.statut === "valide" ? "Validée" : `Refusée — ${d.motif}`}
                </span>
                {d.statut === "valide" && !d.partnerId && (
                  <button onClick={() => onTraiter(d.id, "valide", "")}
                    title="Aucune fiche partenaire n'a été créée pour ce filleul — la créer maintenant"
                    className="text-xs font-semibold fa-navy fa-bg-gold px-2.5 py-1 rounded-lg transition">
                    Créer la fiche
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
function ChallengeBoard({ data, commerciaux, onSetGoals, canEdit }) {
  const [editGoals, setEditGoals] = useState(false);
  const [draft, setDraft] = useState({});
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
  const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1).getTime();
  const goals = data.settings?.challenge || { partenaires: 40, dossiers: 30, ca: 22500 };

  const commercialOf = (d) => data.partners.find(p => p.id === d.partnerId)?.commercial || null;
  const paidAt = (d) => d.paymentDate ? new Date(d.paymentDate).getTime() : (d.updatedAt || d.createdAt);

  function statsFor(c, start, end) {
    const parts = data.partners.filter(p => !p.deleted && p.commercial === c && p.createdAt >= start && p.createdAt < end);
    const doss = data.dossiers.filter(d => commercialOf(d) === c && d.createdAt >= start && d.createdAt < end);
    const ca = data.dossiers
      .filter(d => commercialOf(d) === c && d.status === "Payé" && paidAt(d) >= start && paidAt(d) < end)
      .reduce((s, d) => s + (d.caAmount || 0), 0);
    return { partenaires: parts.length, dossiers: doss.length, ca };
  }

  const classement = commerciaux
    .map(c => ({ nom: c, ...statsFor(c, monthStart, monthEnd) }))
    .sort((a, b) => (b.dossiers - a.dossiers) || (b.ca - a.ca) || (b.partenaires - a.partenaires));
  const leader = classement[0];
  const second = classement[1];
  const ecart = second ? leader.dossiers - second.dossiers : 0;
  const totaux = classement.reduce((s, x) => ({
    partenaires: s.partenaires + x.partenaires,
    dossiers: s.dossiers + x.dossiers,
    ca: s.ca + x.ca,
  }), { partenaires: 0, dossiers: 0, ca: 0 });

  const joursRestants = Math.max(0, Math.ceil((monthEnd - Date.now()) / 86400000));
  const moisCourant = now.toLocaleDateString("fr-FR", { month: "long", year: "numeric" });

  const histo = [1, 2, 3].map(i => {
    const s = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const e = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
    const cl = commerciaux.map(c => ({ nom: c, ...statsFor(c, s.getTime(), e.getTime()) }))
      .sort((a, b) => b.dossiers - a.dossiers);
    return {
      label: s.toLocaleDateString("fr-FR", { month: "long", year: "numeric" }),
      gagnant: cl[0],
      total: cl.reduce((t, x) => t + x.dossiers, 0),
    };
  }).filter(h => h.total > 0);

  let bandeau;
  if (totaux.dossiers === 0) bandeau = "Le mois démarre — tout reste à jouer";
  else if (ecart === 0) bandeau = "Égalité parfaite — ça se joue maintenant";
  else bandeau = `${commercialLabel(leader.nom)} mène de ${ecart} dossier${ecart > 1 ? "s" : ""}`;

  function barre(valeur, cible, couleur) {
    const pct = cible > 0 ? Math.min(100, Math.round((valeur / cible) * 100)) : 0;
    return (
      <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className="h-full transition-all" style={{ width: `${pct}%`, background: couleur }} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between flex-wrap gap-2">
        <h2 className="font-display text-lg font-semibold fa-navy capitalize">{moisCourant}</h2>
        <span className="text-sm text-gray-400">{joursRestants} jour{joursRestants > 1 ? "s" : ""} restant{joursRestants > 1 ? "s" : ""}</span>
      </div>

      <div className="fa-bg-gold rounded-2xl px-5 py-3.5 flex items-center gap-2.5">
        <span className="text-lg">🏆</span>
        <span className="font-display font-semibold fa-navy">{bandeau}</span>
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        {classement.map((c, i) => (
          <div key={c.nom}
            className={`bg-white rounded-2xl p-5 ${i === 0 && ecart > 0 ? "border-2" : "border border-gray-200"}`}
            style={i === 0 && ecart > 0 ? { borderColor: COMMERCIAL_COLORS[c.nom] } : {}}>
            <div className="flex items-center gap-2 mb-3.5">
              <span className="w-7 h-7 rounded-full text-white flex items-center justify-center text-xs font-bold"
                style={{ backgroundColor: COMMERCIAL_COLORS[c.nom] }}>
                {(commercialLabel(c.nom) || "?").charAt(0).toUpperCase()}
              </span>
              <span className="font-display font-semibold fa-navy">{commercialLabel(c.nom)}</span>
              {i === 0 && ecart > 0 && <span className="ml-auto text-base">👑</span>}
            </div>
            <div className="flex items-baseline justify-between py-1">
              <span className="text-xs text-gray-500">Partenaires recrutés</span>
              <span className="font-display text-xl font-bold fa-navy">{c.partenaires}</span>
            </div>
            <div className="flex items-baseline justify-between py-1">
              <span className="text-xs text-gray-500">Dossiers déposés</span>
              <span className="font-display text-xl font-bold fa-navy">{c.dossiers}</span>
            </div>
            <div className="flex items-baseline justify-between py-1">
              <span className="text-xs text-gray-500">CA encaissé</span>
              <span className="font-display text-xl font-bold fa-navy">{fmtEuro(c.ca)}</span>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-white border border-gray-200 rounded-2xl p-5">
        <div className="flex items-center justify-between mb-3.5 flex-wrap gap-2">
          <span className="font-display font-semibold fa-navy">Objectifs du mois — équipe</span>
          {canEdit && !editGoals && (
            <button onClick={() => { setDraft({ partenaires: goals.partenaires, dossiers: goals.dossiers, ca: goals.ca }); setEditGoals(true); }}
              className="text-xs fa-teal-text hover:underline">Modifier</button>
          )}
        </div>

        {editGoals ? (
          <div className="space-y-2">
            <div className="grid sm:grid-cols-3 gap-2">
              <input type="number" value={draft.partenaires} onChange={e => setDraft(d => ({ ...d, partenaires: e.target.value }))}
                placeholder="Partenaires" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
              <input type="number" value={draft.dossiers} onChange={e => setDraft(d => ({ ...d, dossiers: e.target.value }))}
                placeholder="Dossiers" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
              <input type="number" value={draft.ca} onChange={e => setDraft(d => ({ ...d, ca: e.target.value }))}
                placeholder="CA (€)" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
            </div>
            <div className="flex gap-2">
              <button onClick={async () => {
                await onSetGoals({
                  partenaires: Number(draft.partenaires) || 0,
                  dossiers: Number(draft.dossiers) || 0,
                  ca: Number(draft.ca) || 0,
                });
                setEditGoals(false);
              }} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
              <button onClick={() => setEditGoals(false)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-gray-500">Nouveaux partenaires</span>
                <span className="fa-navy font-medium">{totaux.partenaires} / {goals.partenaires}</span>
              </div>
              {barre(totaux.partenaires, goals.partenaires, "#008BA8")}
            </div>
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-gray-500">Dossiers déposés</span>
                <span className="fa-navy font-medium">{totaux.dossiers} / {goals.dossiers}</span>
              </div>
              {barre(totaux.dossiers, goals.dossiers, "#008BA8")}
            </div>
            <div>
              <div className="flex justify-between text-xs mb-1.5">
                <span className="text-gray-500">CA encaissé</span>
                <span className="fa-navy font-medium">{fmtEuro(totaux.ca)} / {fmtEuro(goals.ca)}</span>
              </div>
              {barre(totaux.ca, goals.ca, "#FCD947")}
            </div>
          </div>
        )}
      </div>

      {histo.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="font-display font-semibold fa-navy mb-3">Mois précédents</div>
          <div className="space-y-1">
            {histo.map(h => (
              <div key={h.label} className="flex items-center justify-between text-sm py-1.5 border-b border-gray-100 last:border-0">
                <span className="text-gray-500 capitalize">{h.label}</span>
                <span className="fa-navy">
                  <span className="font-bold">{commercialLabel(h.gagnant.nom)}</span> · {h.gagnant.dossiers} dossier{h.gagnant.dossiers > 1 ? "s" : ""}
                </span>
                <span>🏆</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
function VersementsParrainage({ data, onAddVersement }) {
  const [ouvertId, setOuvertId] = useState(null);
  const [montant, setMontant] = useState("");
  const [note, setNote] = useState("");
  const [detailId, setDetailId] = useState(null);

  // Le cumul historique (ancien champ) reste pris en compte pour ne pas
  // repartir de zéro sur ce qui a déjà été réglé avant l'historique daté.
  const verseTotal = (p) => (p.parrainageVerse || 0)
    + (p.parrainageVersements || []).reduce((s, v) => s + (v.montant || 0), 0);

  const parrains = data.partners
    .filter(p => !p.deleted && filleulsDe(p.id).length > 0)
    .map(p => ({ p, ...bilanParrainage(p.id), verse: verseTotal(p) }))
    .map(x => ({ ...x, reste: x.gainTotal - x.verse }))
    .sort((a, b) => b.reste - a.reste);

  if (parrains.length === 0) return null;

  const totalDu = parrains.reduce((s, x) => s + x.gainTotal, 0);
  const totalVerse = parrains.reduce((s, x) => s + x.verse, 0);
  const aRegler = parrains.filter(x => x.reste > 0.5);
  const nomDe = (p) => nomPartenaire(p);

  async function enregistrer(partnerId) {
    const ok = await onAddVersement(partnerId, montant, note);
    if (ok !== false) { setOuvertId(null); setMontant(""); setNote(""); }
  }

  // Dossiers payés d'un filleul : c'est ce qui justifie la prime.
  const dossiersJustificatifs = (partnerId) => filleulsDe(partnerId).flatMap(f =>
    data.dossiers
      .filter(d => d.partnerId === f.id && d.status === "Payé")
      .map(d => ({ d, filleul: f }))
  ).sort((a, b) => (b.d.paymentDate ? new Date(b.d.paymentDate).getTime() : b.d.updatedAt)
                 - (a.d.paymentDate ? new Date(a.d.paymentDate).getTime() : a.d.updatedAt));

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="font-display font-semibold fa-navy mb-1">
        Parrainage — combien verser
        {aRegler.length > 0 && (
          <span className="ml-2 fa-bg-gold fa-navy text-xs font-bold px-2 py-0.5 rounded-full">
            {aRegler.length} parrain{aRegler.length > 1 ? "s" : ""} à régler
          </span>
        )}
      </div>
      <p className="text-sm text-gray-500 mb-4">
        La prime est due sur les dossiers de vos filleuls déjà <strong>payés</strong> : {Math.round(PARRAINAGE_TAUX * 100)} % du chiffre d'affaires encaissé.
      </p>

      <div className="grid sm:grid-cols-3 gap-3 mb-4">
        <div className="fa-bg-offwhite rounded-xl p-4">
          <div className="text-xs text-gray-400">Dû depuis le début</div>
          <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(totalDu)}</div>
        </div>
        <div className="fa-bg-offwhite rounded-xl p-4">
          <div className="text-xs text-gray-400">Déjà versé</div>
          <div className="font-display text-xl font-bold text-emerald-600">{fmtEuroPrecis(totalVerse)}</div>
        </div>
        <div className="fa-bg-gold rounded-xl p-4">
          <div className="text-xs text-teal-900/70">Reste à payer</div>
          <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(Math.max(0, totalDu - totalVerse))}</div>
        </div>
      </div>

      <div className="space-y-2">
        {parrains.map(x => {
          const justificatifs = detailId === x.p.id ? dossiersJustificatifs(x.p.id) : [];
          const versements = (x.p.parrainageVersements || []).slice().sort((a, b) => b.at - a.at);
          return (
            <div key={x.p.id} className="fa-bg-offwhite rounded-lg px-3 py-2.5">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="min-w-[160px]">
                  <div className="text-sm fa-navy font-bold">{nomDe(x.p)}</div>
                  <div className="text-xs text-gray-400">
                    {x.filleuls.length} filleul{x.filleuls.length > 1 ? "s" : ""} · {x.actifs} actif{x.actifs > 1 ? "s" : ""} · CA encaissé {fmtEuro(x.caTotal)}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-gray-500">Dû {fmtEuroPrecis(x.gainTotal)} · versé {fmtEuroPrecis(x.verse)}</span>
                  <span className={`text-sm font-bold px-2.5 py-1 rounded-full ${x.reste > 0.5 ? "fa-bg-gold fa-navy" : "bg-emerald-50 text-emerald-700"}`}>
                    {x.reste > 0.5 ? `à verser ${fmtEuroPrecis(x.reste)}` : "à jour"}
                  </span>
                </div>
              </div>

              <div className="flex gap-2 mt-2 flex-wrap">
                {ouvertId !== x.p.id && (
                  <button onClick={() => { setOuvertId(x.p.id); setMontant(x.reste > 0.5 ? String(Math.round(x.reste * 100) / 100) : ""); setNote(""); }}
                    className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded-lg transition">
                    Enregistrer un versement
                  </button>
                )}
                <button onClick={() => setDetailId(detailId === x.p.id ? null : x.p.id)}
                  className="text-xs font-semibold bg-white border border-gray-300 text-gray-600 px-3 py-1.5 rounded-lg transition">
                  {detailId === x.p.id ? "Masquer le détail" : "Voir le détail"}
                </button>
              </div>

              {ouvertId === x.p.id && (
                <div className="flex gap-2 mt-2 flex-wrap items-center">
                  <input type="number" value={montant} onChange={e => setMontant(e.target.value)} placeholder="Montant €"
                    className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs w-28 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <input value={note} onChange={e => setNote(e.target.value)} placeholder="Référence du virement (facultatif)"
                    className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs flex-1 min-w-[180px] focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <button onClick={() => enregistrer(x.p.id)}
                    className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Valider</button>
                  <button onClick={() => setOuvertId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                </div>
              )}

              {detailId === x.p.id && (
                <div className="mt-3 pt-2 border-t border-gray-200 space-y-2">
                  <div>
                    <div className="text-xs font-semibold fa-navy mb-1">Dossiers payés qui ouvrent droit à la prime</div>
                    {justificatifs.length === 0 ? (
                      <div className="text-xs text-gray-400">Aucun dossier payé pour l'instant — rien n'est encore dû.</div>
                    ) : justificatifs.map(({ d, filleul }) => (
                      <div key={d.id} className="flex items-center justify-between flex-wrap gap-2 text-xs py-0.5">
                        <span className="text-gray-600">
                          {clientName(d)} <span className="text-gray-400">— via {nomPartenaire(filleul)}</span>
                        </span>
                        <span className="fa-navy">
                          CA {fmtEuroPrecis(d.caAmount || 0)} → prime {fmtEuroPrecis((d.caAmount || 0) * PARRAINAGE_TAUX)}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div>
                    <div className="text-xs font-semibold fa-navy mb-1">Versements effectués</div>
                    {versements.length === 0 && !x.p.parrainageVerse ? (
                      <div className="text-xs text-gray-400">Aucun versement enregistré.</div>
                    ) : (
                      <>
                        {x.p.parrainageVerse > 0 && (
                          <div className="text-xs text-gray-500 py-0.5">Report antérieur : {fmtEuro(x.p.parrainageVerse)}</div>
                        )}
                        {versements.map(v => (
                          <div key={v.id} className="flex items-center justify-between flex-wrap gap-2 text-xs py-0.5">
                            <span className="text-gray-600">{fmtDate(v.at)}{v.note ? ` — ${v.note}` : ""}</span>
                            <span className="text-emerald-700 font-semibold">{fmtEuro(v.montant)}</span>
                          </div>
                        ))}
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// =============================================================================
// FACTURATION — vue d'ensemble des paiements, côté Frangola
//
// Répond à deux questions et à elles seules : qui dois-je payer, et qui ai-je
// payé et quand. Les montants sont au centime : ce sont des sommes dues à
// quelqu'un, pas des indicateurs de tableau de bord.
// =============================================================================
// =============================================================================
// ÉCHÉANCIER D'UN DOSSIER — côté administration
//
// Trois réglages déterminent quand l'argent rentre : le mode de règlement, la
// date d'effet du contrat, et le nombre d'échéances quand c'est l'assureur qui
// collecte. Le reste se calcule. On coche ce qui est reçu au fur et à mesure.
// =============================================================================
// =============================================================================
// RÉCURRENCE ASSUREUR — réservé à l'administration
//
// Le partenaire n'a pas connaissance de cette rémunération : elle n'est pas
// rétrocédée et n'apparaît nulle part dans son espace.
// =============================================================================
function RecurrenceDossier({ dossier, onUpdate, assureurs }) {
  const [ouvert, setOuvert] = useState(false);
  const mensuelle = recurrenceMensuelle(dossier);
  const mois = mensualitesEcoulees(dossier);
  const cumul = recurrenceCumulee(dossier);
  const court = contratEnCours(dossier);
  const petitChamp = "text-xs border border-gray-300 rounded-lg px-2 py-1 w-24 focus:outline-none focus:ring-2 focus:ring-teal-500";

  return (
    <div className="mt-2">
      <button onClick={() => setOuvert(v => !v)}
        className="flex items-center gap-1.5 text-xs font-semibold fa-navy hover:fa-teal-text transition">
        <RefreshCw size={13} />
        Récurrence assureur
        {mensuelle > 0 ? (
          <span className="font-normal text-gray-500">
            — {fmtEuroPrecis(mensuelle)}/mois
            {court ? <> · {mois} versée{mois > 1 ? "s" : ""} · {fmtEuroPrecis(cumul)} perçus</> : (dossier.resilieLe ? " · résilié" : " · en attente de date d'effet")}
          </span>
        ) : (
          <span className="font-normal text-amber-700">— à renseigner</span>
        )}
        <ChevronDown size={13} className={ouvert ? "rotate-180 transition" : "transition"} />
      </button>

      {ouvert && (
        <div className="mt-2 bg-violet-50 border border-violet-200 rounded-lg p-3 space-y-2">
          <div className="text-[11px] text-violet-800 font-semibold">
            Non rétrocédé — invisible pour le partenaire.
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="text-xs text-gray-600 flex items-center gap-1.5">
              Assureur
              <select value={dossier.assureur || ""}
                onChange={e => onUpdate(dossier.id, { assureur: e.target.value || null })}
                className="text-xs border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500">
                <option value="">à choisir…</option>
                {(assureurs || []).map(a => <option key={a.id || a.nom} value={a.nom}>{a.nom}</option>)}
              </select>
              {dossier.assureur && (() => {
                const a = (assureurs || []).find(x => x.nom === dossier.assureur);
                const src = a?.logoData || a?.logo;
                return src
                  ? <img src={src} alt={a.nom} className="h-5 max-w-[70px] object-contain" />
                  : <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: a?.couleur || "#999" }} />;
              })()}
            </label>
            <label className="text-xs text-gray-600 flex items-center gap-1.5">
              Cotisation du client
              <input type="number" min="0" step="0.01" value={dossier.cotisationMensuelle ?? ""}
                onChange={e => onUpdate(dossier.id, { cotisationMensuelle: e.target.value === "" ? null : Number(e.target.value) })}
                placeholder="€ / mois" className={petitChamp} />
              € / mois
            </label>
            <label className="text-xs text-gray-600 flex items-center gap-1.5">
              Commission 1<sup>re</sup> année
              <input type="number" min="0" max="100" step="1" value={dossier.tauxCommissionAssureur ?? ""}
                onChange={e => onUpdate(dossier.id, { tauxCommissionAssureur: e.target.value === "" ? null : Number(e.target.value) })}
                placeholder="%" className="text-xs border border-gray-300 rounded-lg px-2 py-1 w-16 text-center focus:outline-none focus:ring-2 focus:ring-teal-500" />
              % HT
            </label>
            <label className="text-xs text-gray-600 flex items-center gap-1.5">
              puis années suivantes
              <input type="number" min="0" max="100" step="1" value={dossier.tauxCommissionSuivantes ?? ""}
                onChange={e => onUpdate(dossier.id, { tauxCommissionSuivantes: e.target.value === "" ? null : Number(e.target.value) })}
                placeholder="idem" className="text-xs border border-gray-300 rounded-lg px-2 py-1 w-16 text-center focus:outline-none focus:ring-2 focus:ring-teal-500" />
              % HT
              {tauxAnnee1(dossier) > 0 && (
                <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${baremeDegressif(dossier) ? "bg-amber-100 text-amber-800" : "bg-emerald-100 text-emerald-800"}`}>
                  {libelleBareme(dossier)}
                </span>
              )}
            </label>
          </div>

          {mensuelle > 0 && (
            <div className="text-xs text-gray-600">
              Soit <strong className="fa-navy">{fmtEuroPrecis(mensuelle)} par mois</strong>
              {baremeDegressif(dossier) && (
                <span className="text-amber-800">
                  {" "}la première année, puis <strong>{fmtEuroPrecis(recurrenceCroisiere(dossier))}</strong> ensuite
                </span>
              )}
              <span className="text-gray-500"> — dont {fmtEuroPrecis(mensuelle * PART_MANDATAIRE)} pour le mandataire
              et {fmtEuroPrecis(mensuelle * (1 - PART_MANDATAIRE))} pour Frangola</span>
              {dossier.dateEffet
                ? <> à partir du {fmtDate(new Date(dossier.dateEffet + "T12:00:00").getTime())} —
                    <strong className="fa-navy"> {fmtEuroPrecis(cumul)}</strong> perçus à ce jour sur {mois} mensualité{mois > 1 ? "s" : ""},
                    et <strong className="fa-navy">{fmtEuroPrecis(tauxAnnee1(dossier) * (Number(dossier.cotisationMensuelle) || 0) / 100 * 12)}</strong> sur la première année
                    {baremeDegressif(dossier)
                      ? <>, puis <strong className="fa-navy">{fmtEuroPrecis(recurrenceCroisiere(dossier) * 12)}</strong> par an ensuite.</>
                      : <> et autant les suivantes.</>}</>
                : <span className="text-amber-700"> — renseignez la date d'effet dans l'échéancier pour lancer le compteur.</span>}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-violet-200">
            {dossier.resilieLe ? (
              <>
                <span className="text-xs text-red-700 font-medium">
                  Contrat résilié le {fmtDate(new Date(dossier.resilieLe + "T12:00:00").getTime())} — la récurrence s'arrête à cette date.
                </span>
                <button onClick={() => onUpdate(dossier.id, { resilieLe: null })}
                  className="text-xs text-gray-400 hover:fa-teal-text">annuler</button>
              </>
            ) : (
              <label className="text-xs text-gray-500 flex items-center gap-1.5">
                Résilié le
                <input type="date" value=""
                  onChange={e => e.target.value && onUpdate(dossier.id, { resilieLe: e.target.value })}
                  className="text-xs border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <span className="text-gray-400">(laisser vide tant que le contrat court)</span>
              </label>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function EcheancierDossier({ dossier, onUpdate }) {
  const [ouvert, setOuvert] = useState(false);
  const mode = dossier.modeReglement || "";
  const echeances = Array.isArray(dossier.echeances) && dossier.echeances.length > 0
    ? dossier.echeances : null;

  const encaisse = partEncaissee(dossier, dossier.caAmount || 0);
  const aVenir = partAVenir(dossier, dossier.caAmount || 0);
  const nbRecues = echeances ? echeances.filter(e => e.encaisseLe).length : 0;

  function majParametres(champs) {
    const projete = { ...dossier, ...champs };
    onUpdate(dossier.id, { ...champs, echeances: genererEcheancier(projete) });
  }
  function majEcheance(i, champs) {
    const base = dossier.echeances || genererEcheancier(dossier);
    onUpdate(dossier.id, { echeances: base.map((e, k) => k === i ? { ...e, ...champs } : e) });
  }

  const aujourdhui = () => new Date().toISOString().slice(0, 10);
  const partsHono = repartir(dossier.caAmount || 0, echeances ? echeances.length : 1);
  const partsPart = repartir(dossier.commissionAmount || 0, echeances ? echeances.length : 1);

  const petitChamp = "text-xs border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500";

  return (
    <div className="mt-3 pt-3 border-t border-gray-100">
      <button onClick={() => setOuvert(v => !v)}
        className="flex items-center gap-1.5 text-xs font-semibold fa-navy hover:fa-teal-text transition">
        <Wallet size={13} />
        Échéancier
        {!mode && <span className="font-normal text-amber-700">— mode de règlement à définir</span>}
        {mode && echeances && (
          <span className="font-normal text-gray-500">
            — {nbRecues}/{echeances.length} encaissée{nbRecues > 1 ? "s" : ""} · reçu {fmtEuroPrecis(encaisse)} · à venir {fmtEuroPrecis(aVenir)}
          </span>
        )}
        <ChevronDown size={13} className={ouvert ? "rotate-180 transition" : "transition"} />
      </button>

      {ouvert && (
        <div className="mt-2 fa-bg-offwhite rounded-lg p-3 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <select value={mode} onChange={e => majParametres({ modeReglement: e.target.value })} className={petitChamp}>
              <option value="">Mode de règlement…</option>
              {MODES_REGLEMENT.map(m => <option key={m.valeur} value={m.valeur}>{m.libelle}</option>)}
            </select>

            <label className="text-xs text-gray-500 flex items-center gap-1.5">
              Date d'effet
              <input type="date" value={dossier.dateEffet || ""}
                onChange={e => majParametres({ dateEffet: e.target.value })} className={petitChamp} />
            </label>

            {mode === "assureur" && (
              <label className="text-xs text-gray-500 flex items-center gap-1.5">
                Échéances
                <select value={dossier.nombreEcheances || 1}
                  onChange={e => majParametres({ nombreEcheances: Number(e.target.value) })} className={petitChamp}>
                  {Array.from({ length: 12 }, (_, i) => i + 1).map(n => (
                    <option key={n} value={n}>{n === 1 ? "1 fois" : `${n} fois`}</option>
                  ))}
                </select>
              </label>
            )}
          </div>

          {!mode ? (
            <div className="text-xs text-gray-500">
              Choisissez le mode de règlement : en direct, les honoraires rentrent sous 48 h ;
              par l'assureur, ils sont reversés à partir d'un mois après la date d'effet.
            </div>
          ) : !dossier.dateEffet ? (
            <div className="text-xs text-amber-700">
              Renseignez la date d'effet du contrat pour calculer les dates d'encaissement.
            </div>
          ) : !echeances ? null : (
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-[11px] text-gray-400 px-1">
                <span className="w-6 shrink-0">N°</span>
                <span className="w-32 shrink-0">Date prévue</span>
                <span className="w-24 shrink-0 text-right">Honoraires</span>
                <span className="w-24 shrink-0 text-right">Partenaire</span>
                <span className="flex-1" />
              </div>
              {echeances.map((e, i) => (
                <div key={e.numero} className={`flex items-center gap-2 flex-wrap rounded-lg px-1 py-1 ${e.encaisseLe ? "bg-emerald-50" : ""}`}>
                  <span className="w-6 shrink-0 text-xs text-gray-500">{e.numero}</span>
                  <input type="date" value={e.datePrevue || ""}
                    onChange={ev => majEcheance(i, { datePrevue: ev.target.value, dateForcee: true })}
                    className="w-32 shrink-0 text-xs border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <span className="w-24 shrink-0 text-right text-xs fa-navy font-medium">{fmtEuroPrecis(partsHono[i])}</span>
                  <span className="w-24 shrink-0 text-right text-xs text-gray-500">{fmtEuroPrecis(partsPart[i])}</span>
                  {e.encaisseLe ? (
                    <span className="flex items-center gap-1.5 text-xs text-emerald-700 font-medium">
                      <CheckCircle2 size={13} /> encaissé le {fmtDate(new Date(e.encaisseLe + "T12:00:00").getTime())}
                      <button onClick={() => majEcheance(i, { encaisseLe: null })}
                        className="text-gray-400 hover:text-red-600 ml-1" title="Annuler l'encaissement">✕</button>
                    </span>
                  ) : (
                    <button onClick={() => majEcheance(i, { encaisseLe: aujourdhui() })}
                      className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white px-2.5 py-1 rounded-lg transition">
                      Marquer encaissée
                    </button>
                  )}
                </div>
              ))}
              <div className="pt-2 text-xs text-gray-500">
                Reçu <strong className="fa-navy">{fmtEuroPrecis(encaisse)}</strong> sur {fmtEuroPrecis(dossier.caAmount || 0)}
                {aVenir > 0.005 && <> · reste à percevoir <strong className="fa-navy">{fmtEuroPrecis(aVenir)}</strong></>}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// =============================================================================
// VISION 360 DE LA TRÉSORERIE
//
// Ce qui est rentré, ce qui va rentrer et quand, ce qui est engagé envers le
// réseau, et ce qui reste réellement à Frangola. Le fond de roulement se joue
// dans l'écart entre l'encaissé et les engagements : une partie de ce qui est
// en banque est déjà due à quelqu'un.
// =============================================================================
// =============================================================================
// PROJECTION DE CHIFFRE D'AFFAIRES
//
// Extrapole la production au rythme observé. Une projection n'est pas une
// prévision : elle dit « si rien ne change », ce qui n'arrive jamais. D'où
// deux partis pris — on montre toujours sur quoi le calcul repose, et on
// refuse de projeter quand l'échantillon est trop mince.
// =============================================================================
// =============================================================================
// OBJECTIFS — le calcul à l'envers
//
// La projection part de la production pour arriver à un chiffre. Ici on part
// du chiffre voulu et on remonte à ce qu'il faut : combien de dossiers,
// combien de partenaires actifs, combien à recruter.
//
// Les quatre hypothèses sont préremplies par l'observation puis modifiables :
// c'est un outil de pilotage, il doit fonctionner avant même d'avoir des
// données, sur les chiffres que Sébastien estime justes.
// =============================================================================
// =============================================================================
// REVENU RÉCURRENT
//
// Au-delà des honoraires, l'assureur verse chaque mois un pourcentage de la
// cotisation du client, pour toute la vie du contrat. Cette part n'est pas
// rétrocédée : elle revient entièrement à Frangola et au mandataire. Elle est
// donc strictement réservée à l'administration — le partenaire ne la voit pas.
//
// Le compteur démarre à la date d'effet et s'arrête à la résiliation.
// =============================================================================
const STATUTS_CONTRAT_VIVANT = ["Souscrit", "Bordereau émis", "Payé"];

// Le mandataire touche la moitié de la récurrence, comme sur les honoraires.
// Le partenaire, lui, n'en touche rien : elle ne lui est jamais montrée.
const PART_MANDATAIRE = 0.5;

// Compagnies partenaires. La liste vit dans les données pour que Frangola
// puisse l'étoffer sans toucher au code. Les couleurs ne sont que des valeurs
// de départ, modifiables.
// Compagnies partenaires. La liste vit dans les réglages et s'enrichit depuis
// l'onglet Mandataires ; celle-ci ne sert que de point de départ. Les couleurs
// sont approchées d'après les identités visuelles — à ajuster avec les logos.
const ASSUREURS_PAR_DEFAUT = [
  {
    id: "cardif", nom: "CARDIF", couleur: "#00915A",
    logo: "data:image/png;base64,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",
  },
  {
    id: "april", nom: "APRIL", couleur: "#3D7F27",
    logo: "data:image/png;base64,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",
  },
  {
    id: "apivia", nom: "APIVIA", couleur: "#1B3A8B",
    logo: "data:image/png;base64,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",
  },
];
function listeAssureurs(data) {
  const l = data?.settings?.assureurs;
  return Array.isArray(l) && l.length > 0 ? l : ASSUREURS_PAR_DEFAUT;
}
function assureurLogo(data, nom) {
  const a = assureurParNom(data, nom);
  // Deux origines possibles : les logos livrés avec l'application (`logo`) et
  // ceux déposés depuis l'écran de gestion (`logoData`).
  return a?.logoData || a?.logo || null;
}
function assureurParNom(data, nom) {
  if (!nom) return null;
  return listeAssureurs(data).find(a => a.nom === nom) || null;
}

// Deux barèmes existent chez les compagnies :
//   — linéaire : le même taux toute la vie du contrat (30/30) ;
//   — dégressif : un taux gonflé la première année, plus bas ensuite (50/10).
// Confondre les deux surestime les revenus dès la treizième mensualité, et
// d'autant plus que le portefeuille vieillit. Le second taux vaut le premier
// par défaut, ce qui rend les anciens dossiers linéaires sans rien casser.
const DUREE_TAUX_INITIAL = 12; // mensualités au taux de première année

function tauxAnnee1(dossier) {
  return Number(dossier?.tauxCommissionAssureur) || 0;
}
function tauxAnneesSuivantes(dossier) {
  const t = dossier?.tauxCommissionSuivantes;
  return (t === null || t === undefined || t === "") ? tauxAnnee1(dossier) : (Number(t) || 0);
}
function baremeDegressif(dossier) {
  return tauxAnneesSuivantes(dossier) !== tauxAnnee1(dossier);
}
function libelleBareme(dossier) {
  const a = tauxAnnee1(dossier), b = tauxAnneesSuivantes(dossier);
  if (!a) return "";
  return `${a}/${b}`;
}

// Montant d'une mensualité donnée, la première portant le numéro 1.
function montantMensualite(dossier, numero) {
  const cotisation = Number(dossier?.cotisationMensuelle) || 0;
  if (cotisation <= 0) return 0;
  const taux = numero <= DUREE_TAUX_INITIAL ? tauxAnnee1(dossier) : tauxAnneesSuivantes(dossier);
  return (cotisation * taux) / 100;
}

// Ce que rapporte le contrat CE MOIS-CI, au taux qui s'applique aujourd'hui.
function recurrenceMensuelle(dossier) {
  const n = mensualitesEcoulees(dossier);
  return montantMensualite(dossier, Math.max(1, n + (n === 0 ? 1 : 0)));
}

// Ce qu'il rapportera une fois la première année passée — le régime de
// croisière. C'est lui qu'il faut regarder pour se projeter.
function recurrenceCroisiere(dossier) {
  const cotisation = Number(dossier?.cotisationMensuelle) || 0;
  return (cotisation * tauxAnneesSuivantes(dossier)) / 100;
}

// Le contrat produit-il encore aujourd'hui ?
function contratEnCours(dossier) {
  if (!STATUTS_CONTRAT_VIVANT.includes(dossier?.status)) return false;
  if (dossier.resilieLe) return false;
  if (!dossier.dateEffet) return false;
  return new Date(dossier.dateEffet + "T12:00:00").getTime() <= Date.now();
}

// Nombre de mensualités déjà versées : une à la date d'effet, puis une par
// mois, jusqu'à aujourd'hui ou jusqu'à la résiliation.
function mensualitesEcoulees(dossier) {
  if (!dossier?.dateEffet) return 0;
  const debut = new Date(dossier.dateEffet + "T12:00:00");
  if (isNaN(debut.getTime())) return 0;
  const borne = dossier.resilieLe ? new Date(dossier.resilieLe + "T12:00:00") : new Date();
  if (borne < debut) return 0;
  let n = (borne.getFullYear() - debut.getFullYear()) * 12 + (borne.getMonth() - debut.getMonth());
  if (borne.getDate() >= debut.getDate()) n += 1;
  return Math.max(0, n);
}

function recurrenceCumulee(dossier) {
  if (!STATUTS_CONTRAT_VIVANT.includes(dossier?.status)) return 0;
  const n = mensualitesEcoulees(dossier);
  if (n <= 0) return 0;
  const cotisation = Number(dossier?.cotisationMensuelle) || 0;
  if (cotisation <= 0) return 0;
  const an1 = Math.min(n, DUREE_TAUX_INITIAL);
  const apres = Math.max(0, n - DUREE_TAUX_INITIAL);
  return (cotisation * tauxAnnee1(dossier) / 100) * an1
       + (cotisation * tauxAnneesSuivantes(dossier) / 100) * apres;
}

// Revenu récurrent du portefeuille à une échéance future donnée, en tenant
// compte du passage au taux réduit de chaque contrat à sa date anniversaire.
function mrrDansNMois(dossiers, n) {
  return (dossiers || []).filter(contratEnCours).reduce((s, d) => {
    const numero = mensualitesEcoulees(d) + n;
    return s + montantMensualite(d, Math.max(1, numero));
  }, 0);
}

// Décomposition de ce qui a DÉJÀ été encaissé, par régime de taux. Répond à
// « où j'en suis » : ce que la première année de chaque contrat a rapporté,
// et ce que les années suivantes ont rapporté à leur taux propre.
function recurrencePercueDetaillee(dossiers) {
  let an1 = 0, apres = 0, moisAn1 = 0, moisApres = 0;
  let contratsEnAn1 = 0, contratsAuDela = 0;
  for (const d of dossiers || []) {
    if (!STATUTS_CONTRAT_VIVANT.includes(d.status)) continue;
    const n = mensualitesEcoulees(d);
    const cot = Number(d.cotisationMensuelle) || 0;
    if (n <= 0 || cot <= 0) continue;
    const a = Math.min(n, DUREE_TAUX_INITIAL);
    const b = Math.max(0, n - DUREE_TAUX_INITIAL);
    an1 += (cot * tauxAnnee1(d) / 100) * a;
    apres += (cot * tauxAnneesSuivantes(d) / 100) * b;
    moisAn1 += a; moisApres += b;
    if (b > 0) contratsAuDela += 1; else contratsEnAn1 += 1;
  }
  return { an1, apres, moisAn1, moisApres, contratsEnAn1, contratsAuDela, total: an1 + apres };
}

// Rythme observé de signature de contrats porteurs de récurrence, et montants
// moyens. Sert à projeter l'empilement : chaque année de production s'ajoute
// aux précédentes, c'est ce qui fait grossir la cagnotte.
function rythmeRecurrence(dossiers, fenetreJours = 90) {
  const depuis = Date.now() - fenetreJours * 86400000;
  const avecRec = (dossiers || []).filter(d =>
    STATUTS_CONTRAT_VIVANT.includes(d.status) && (Number(d.cotisationMensuelle) || 0) > 0 && tauxAnnee1(d) > 0);
  const recents = avecRec.filter(d => {
    if (!d.dateEffet) return false;
    const t = new Date(d.dateEffet + "T12:00:00").getTime();
    return !isNaN(t) && t >= depuis;
  });
  const parMois = recents.length / (fenetreJours / 30.44);
  const moy = (f) => avecRec.length ? avecRec.reduce((s, d) => s + f(d), 0) / avecRec.length : 0;
  return {
    parMois,
    an1: moy(d => (Number(d.cotisationMensuelle) || 0) * tauxAnnee1(d) / 100),
    apres: moy(d => recurrenceCroisiere(d)),
    echantillon: avecRec.length,
  };
}

// Projection sur cinq ans, dans les deux lectures :
//   — « acquis » : le portefeuille actuel vieillit, sans rien de nouveau ;
//   — « maintenu » : on continue de signer au rythme observé.
function projectionRecurrence(dossiers, nouveauxParMois, r1, r2, annees = 5) {
  const lignes = [];
  let cumulAcquis = 0, cumulMaintenu = 0;
  for (let a = 1; a <= annees; a++) {
    let acquis = 0, maintenu = 0;
    for (let k = 1; k <= 12; k++) {
      const m = (a - 1) * 12 + k;
      const base = mrrDansNMois(dossiers, m);
      acquis += base;
      // Chaque cohorte mensuelle passée contribue, au taux correspondant à
      // son propre âge.
      let apport = 0;
      for (let c = 1; c <= m; c++) {
        const age = m - c + 1;
        apport += nouveauxParMois * (age <= DUREE_TAUX_INITIAL ? r1 : r2);
      }
      maintenu += base + apport;
    }
    cumulAcquis += acquis;
    cumulMaintenu += maintenu;
    lignes.push({ annee: a, acquis, maintenu, cumulAcquis, cumulMaintenu });
  }
  return lignes;
}

// Ce que rapportera le portefeuille actuel sur une année donnée, sans un
// dossier de plus : année 1 = les douze prochains mois.
function recurrenceAnnee(dossiers, annee) {
  let total = 0;
  for (let m = 1; m <= 12; m++) total += mrrDansNMois(dossiers, (annee - 1) * 12 + m);
  return total;
}

// Revenu récurrent mensuel du cabinet : la somme des contrats qui courent.
// C'est le chiffre qui dit ce qui tombe tous les mois sans rien faire.
function recurrenceMensuelleTotale(dossiers) {
  return (dossiers || []).filter(contratEnCours).reduce((s, d) => s + recurrenceMensuelle(d), 0);
}

function recurrenceCumuleeTotale(dossiers) {
  return (dossiers || []).reduce((s, d) => s + recurrenceCumulee(d), 0);
}

// Date à laquelle un dossier a été gagné, lue dans l'historique des statuts
// plutôt que devinée d'après la date de dépôt : un dossier déposé en février
// et souscrit en mars appartient à mars.
function dateGain(dossier) {
  const h = dossier.history || [];
  const gagnants = ["Souscrit", "Bordereau émis", "Payé"];
  const trouve = h.find(e => gagnants.includes(e.status));
  if (trouve) return trouve.at;
  return gagnants.includes(dossier.status) ? (dossier.updatedAt || dossier.createdAt) : null;
}

// =============================================================================
// PRODUCTION DU MOIS
//
// Répond à une seule question : suis-je dans les temps. D'où le repère de
// rythme — être à 18 sur 30 le 5 du mois et le 28 n'a rien à voir — et les
// écarts exprimés en dossiers plutôt qu'en pourcentages : « il en manque 4 »
// se traite, « 88 % du rythme » ne se traite pas.
//
// La barre est segmentée par commercial : le total et la répartition se lisent
// dans le même geste.
// =============================================================================
// Compte les dossiers souscrits d'un partenaire sur une période. La date
// retenue est celle de la souscription, pas du dépôt : un dossier déposé le 28
// et souscrit le 3 compte pour le mois suivant.
function souscritsSurPeriode(dossiers, partnerId, debut, fin) {
  return (dossiers || []).filter(d => {
    if (d.partnerId !== partnerId) return false;
    const t = dateGain(d);
    return t !== null && t >= debut && t <= fin;
  }).length;
}

function bornesChallenge(ch) {
  const d = ch?.debut ? new Date(ch.debut + "T00:00:00").getTime() : null;
  const f = ch?.fin ? new Date(ch.fin + "T23:59:59").getTime() : null;
  return { debut: d, fin: f, valide: d !== null && f !== null && f > d };
}

// =============================================================================
// CHALLENGE PARTENAIRES — pilotage côté Frangola
// =============================================================================
// Fiche du gérant. Il est administrateur, mais il est aussi commercial : sa
// couleur apparaît sur chaque dossier et chaque jauge, il doit pouvoir la
// changer sans passer par moi.
// Gestion des compagnies partenaires : nom, couleur, logo. La couleur sert
// dans les analyses, le logo les rend lisibles d'un coup d'œil.
// =============================================================================
// PRODUCTION PAR ASSUREUR
//
// Où produit-on, et combien chaque compagnie rapporte. Deux lectures : le
// volume de contrats, et le revenu — honoraires d'un côté, récurrence
// mensuelle de l'autre, puisqu'elles ne se comportent pas pareil.
// =============================================================================
function ProductionParAssureur({ data, dossiers }) {
  const gagnes = (dossiers || []).filter(d => STATUTS_CONTRAT_VIVANT.includes(d.status));
  if (gagnes.length === 0) return null;

  const groupes = new Map();
  for (const d of gagnes) {
    const nom = (d.assureur || "").trim() || "Non renseigné";
    if (!groupes.has(nom)) groupes.set(nom, { nom, contrats: 0, honoraires: 0, recMensuelle: 0, recCumulee: 0 });
    const g = groupes.get(nom);
    g.contrats += 1;
    g.honoraires += d.caAmount || 0;
    if (contratEnCours(d)) g.recMensuelle += recurrenceMensuelle(d);
    g.recCumulee += recurrenceCumulee(d);
  }
  const lignes = [...groupes.values()].sort((a, b) => b.contrats - a.contrats);
  const totalContrats = lignes.reduce((s, x) => s + x.contrats, 0);
  const totalHono = lignes.reduce((s, x) => s + x.honoraires, 0);
  const totalRec = lignes.reduce((s, x) => s + x.recMensuelle, 0);
  const manquants = groupes.get("Non renseigné")?.contrats || 0;

  const couleurDe = (nom) => nom === "Non renseigné"
    ? "#c4c4c4"
    : (assureurParNom(data, nom)?.couleur || "#6b7280");

  return (
    <div>
      <h2 className="font-display text-lg font-semibold fa-navy mb-3">Production par assureur</h2>

      <div className="bg-white border border-gray-200 rounded-2xl p-5">
        {/* Une barre unique : la répartition se lit d'un seul regard. */}
        <div className="flex h-4 rounded-full overflow-hidden mb-4 bg-gray-100">
          {lignes.map(l => (
            <div key={l.nom} title={`${l.nom} — ${l.contrats} contrat${l.contrats > 1 ? "s" : ""}`}
              style={{ width: `${(l.contrats / totalContrats) * 100}%`, backgroundColor: couleurDe(l.nom) }} />
          ))}
        </div>

        <div className="space-y-2">
          {lignes.map(l => {
            const part = Math.round((l.contrats / totalContrats) * 100);
            return (
              <div key={l.nom} className="flex items-center gap-3 flex-wrap text-sm">
                <span className="flex items-center gap-2 w-44 shrink-0">
                  {assureurLogo(data, l.nom)
                    ? <img src={assureurLogo(data, l.nom)} alt={l.nom} className="h-5 max-w-[80px] object-contain shrink-0" />
                    : <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: couleurDe(l.nom) }} />}
                  <span className={`font-semibold ${l.nom === "Non renseigné" ? "text-gray-400" : "fa-navy"}`}>{l.nom}</span>
                </span>
                <span className="text-xs text-gray-500 w-28 shrink-0">
                  {l.contrats} contrat{l.contrats > 1 ? "s" : ""} · {part} %
                </span>
                <span className="text-xs fa-navy w-32 shrink-0 text-right">{fmtEuro(l.honoraires)} d'honoraires</span>
                <span className="text-xs text-violet-700 ml-auto text-right">
                  {fmtEuroPrecis(l.recMensuelle)}/mois · {fmtEuro(l.recCumulee)} perçus
                </span>
              </div>
            );
          })}
        </div>

        <div className="flex flex-wrap items-baseline justify-between gap-2 mt-4 pt-3 border-t border-gray-100 text-sm">
          <span className="fa-navy font-semibold">{totalContrats} contrat{totalContrats > 1 ? "s" : ""} au total</span>
          <span className="text-gray-500">
            {fmtEuro(totalHono)} d'honoraires · <span className="text-violet-700">{fmtEuroPrecis(totalRec)}/mois de récurrence</span>
          </span>
        </div>

        {manquants > 0 && (
          <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mt-3">
            {manquants} contrat{manquants > 1 ? "s" : ""} sans assureur renseigné. Renseignez-le dans l'encadré
            « Récurrence assureur » du dossier : sans lui, vous ne saurez pas avec quelle compagnie négocier.
          </div>
        )}
      </div>
    </div>
  );
}

function AssureursPanel({ data, onSet, canEdit, busy }) {
  const liste = listeAssureurs(data);
  const [nouveau, setNouveau] = useState("");
  const champs = useRef({});

  function maj(id, fields) {
    onSet(liste.map(a => (a.id || a.nom) === id ? { ...a, ...fields } : a));
  }
  function ajouter() {
    const nom = nouveau.trim().toUpperCase();
    if (!nom || liste.some(a => a.nom.toUpperCase() === nom)) return;
    onSet([...liste, { id: nom.toLowerCase().replace(/\s+/g, "-"), nom, couleur: "#6b7280" }]);
    setNouveau("");
  }
  function retirer(id) {
    onSet(liste.filter(a => (a.id || a.nom) !== id));
  }
  async function logo(id, file) {
    if (!file) return;
    try {
      const dataUrl = await reduireImage(file, 200);
      maj(id, { logoData: dataUrl });
    } catch (e) { /* on garde l'assureur sans logo */ }
  }

  const compte = (nom) => data.dossiers.filter(d => d.assureur === nom).length;

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-6">
      <div className="font-display font-semibold fa-navy mb-1">Compagnies partenaires</div>
      <p className="text-sm text-gray-500 mb-4">
        Renseignées sur chaque dossier, elles alimentent l'analyse « où produit-on le plus ».
        La couleur et le logo servent dans les statistiques.
      </p>

      <div className="space-y-2">
        {liste.map(a => {
          const id = a.id || a.nom;
          return (
            <div key={id} className="flex items-center gap-3 flex-wrap fa-bg-offwhite rounded-lg px-3 py-2">
              {(a.logoData || a.logo)
                ? <img src={a.logoData || a.logo} alt={a.nom} className="h-6 w-auto max-w-[80px] object-contain" />
                : <span className="w-4 h-4 rounded-full shrink-0" style={{ backgroundColor: a.couleur || "#999" }} />}
              <span className="text-sm fa-navy font-semibold">{a.nom}</span>
              <span className="text-xs text-gray-400">{compte(a.nom)} dossier{compte(a.nom) > 1 ? "s" : ""}</span>
              {canEdit && (
                <span className="ml-auto flex items-center gap-2">
                  <input type="color" value={a.couleur || "#999999"}
                    onChange={e => maj(id, { couleur: e.target.value })}
                    title="Couleur dans les statistiques"
                    className="w-8 h-7 rounded cursor-pointer border border-gray-300" />
                  <button onClick={() => champs.current[id]?.click()} disabled={busy}
                    className="text-xs font-medium bg-white border border-gray-300 text-gray-600 px-2.5 py-1 rounded-lg transition">
                    {a.logoData ? "Changer le logo" : "Logo"}
                  </button>
                  <input type="file" accept="image/*" className="hidden" ref={el => champs.current[id] = el}
                    onChange={e => logo(id, e.target.files?.[0])} />
                  {compte(a.nom) === 0 && (
                    <button onClick={() => retirer(id)} title="Retirer — aucun dossier ne l'utilise"
                      className="text-xs text-gray-400 hover:text-red-600">✕</button>
                  )}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {canEdit && (
        <div className="flex items-center gap-2 mt-3">
          <input value={nouveau} onChange={e => setNouveau(e.target.value)}
            onKeyDown={e => e.key === "Enter" && ajouter()}
            placeholder="Ajouter une compagnie"
            className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-teal-500" />
          <button onClick={ajouter} disabled={!nouveau.trim()}
            className="fa-bg-teal disabled:opacity-50 text-xs font-medium px-3 py-1.5 rounded-lg transition">Ajouter</button>
        </div>
      )}
    </div>
  );
}

function FicheAdmin({ admin, onUpdate }) {
  const [edition, setEdition] = useState(false);
  const [b, setB] = useState({});

  function ouvrir() {
    setB({
      color: admin?.color || "#2F448B",
      telephone: admin?.telephone || "",
      firstName: admin?.firstName || "",
    });
    setEdition(true);
  }
  function enregistrer() {
    onUpdate({ color: b.color, telephone: (b.telephone || "").trim(), firstName: (b.firstName || "").trim() });
    setEdition(false);
  }

  const champ = "text-sm border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500";

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-6">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full"
            style={{ backgroundColor: admin?.color || "#2F448B" }}>
            {admin?.firstName || "Sébastien"}
          </span>
          <div>
            <div className="font-display font-semibold fa-navy">Ma fiche</div>
            <div className="text-xs text-gray-400">
              {admin?.email}
              {admin?.telephone && <> · {admin.telephone}</>}
              {" "}· gérant et commercial
            </div>
          </div>
        </div>
        {!edition && (
          <button onClick={ouvrir} className="text-sm fa-teal-text hover:underline">Modifier</button>
        )}
      </div>

      {edition && (
        <div className="mt-4 pt-4 border-t border-gray-100 space-y-3">
          <div className="flex flex-wrap items-center gap-4">
            <label className="text-xs text-gray-500 flex items-center gap-2">
              Ma couleur
              <input type="color" value={b.color} onChange={e => setB(x => ({ ...x, color: e.target.value }))}
                className="w-10 h-8 rounded cursor-pointer border border-gray-300" />
              <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: b.color }}>
                {b.firstName || "Sébastien"}
              </span>
            </label>
            <label className="text-xs text-gray-500 flex items-center gap-2">
              Prénom affiché
              <input value={b.firstName} onChange={e => setB(x => ({ ...x, firstName: e.target.value }))}
                placeholder="Sébastien" className={champ + " w-32"} />
            </label>
            <label className="text-xs text-gray-500 flex items-center gap-2">
              Téléphone
              <input type="tel" value={b.telephone} onChange={e => setB(x => ({ ...x, telephone: e.target.value }))}
                placeholder="06 12 34 56 78" className={champ + " w-40"} />
            </label>
          </div>
          <p className="text-xs text-gray-400">
            Votre adresse de connexion ne se change pas ici : elle est détenue par Supabase, qui garde vos
            mots de passe. La couleur s'applique partout — dossiers, jauges, classements — y compris
            rétroactivement.
          </p>
          <div className="flex gap-2">
            <button onClick={enregistrer} className="fa-bg-teal text-sm font-medium px-4 py-1.5 rounded-lg transition">Enregistrer</button>
            <button onClick={() => setEdition(false)} className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
          </div>
        </div>
      )}
    </div>
  );
}

function ChallengePartenaires({ data, onSet, canEdit }) {
  const ch = data.settings?.challengePartenaires || null;
  const [edition, setEdition] = useState(false);
  const [b, setB] = useState({});

  const now = new Date();
  const defautDebut = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
  const defautFin = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);

  function ouvrir() {
    setB({
      titre: ch?.titre || `Challenge ${now.toLocaleDateString("fr-FR", { month: "long" })}`,
      objectif: ch?.objectif ?? 3,
      recompense: ch?.recompense || "",
      debut: ch?.debut || defautDebut,
      fin: ch?.fin || defautFin,
    });
    setEdition(true);
  }
  function enregistrer() {
    onSet({
      titre: (b.titre || "").trim(),
      objectif: Math.max(1, Number(b.objectif) || 1),
      recompense: (b.recompense || "").trim(),
      debut: b.debut, fin: b.fin, actif: true,
    });
    setEdition(false);
  }

  const bornes = bornesChallenge(ch);
  const actif = ch?.actif && bornes.valide;
  const enCours = actif && Date.now() >= bornes.debut && Date.now() <= bornes.fin;
  const joursRestants = actif ? Math.max(0, Math.ceil((bornes.fin - Date.now()) / 86400000)) : 0;

  const classement = actif
    ? data.partners.filter(p => !p.deleted)
        .map(p => ({ p, n: souscritsSurPeriode(data.dossiers, p.id, bornes.debut, bornes.fin) }))
        .filter(x => x.n > 0)
        .sort((a, b2) => b2.n - a.n)
    : [];
  const gagnants = classement.filter(x => x.n >= (ch?.objectif || 0));

  const champ = "text-sm border border-gray-300 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-teal-500";

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
        <div className="font-display font-semibold fa-navy">Challenge partenaires</div>
        {canEdit && !edition && (
          <div className="flex items-center gap-3">
            {actif && (
              <button onClick={() => onSet({ actif: false })} className="text-xs text-gray-400 hover:text-red-600">
                Arrêter
              </button>
            )}
            <button onClick={ouvrir} className="text-xs fa-teal-text hover:underline">
              {ch?.titre ? "Modifier" : "Créer un challenge"}
            </button>
          </div>
        )}
      </div>

      {edition ? (
        <div className="space-y-2 my-3">
          <div className="flex flex-wrap items-center gap-2">
            <input value={b.titre} onChange={e => setB(x => ({ ...x, titre: e.target.value }))}
              placeholder="Intitulé" className={champ + " flex-1 min-w-[180px]"} />
            <label className="text-xs text-gray-500 flex items-center gap-1.5">
              Objectif
              <input type="number" min="1" value={b.objectif} onChange={e => setB(x => ({ ...x, objectif: e.target.value }))}
                className={champ + " w-16 text-center"} />
              dossiers souscrits
            </label>
          </div>
          <input value={b.recompense} onChange={e => setB(x => ({ ...x, recompense: e.target.value }))}
            placeholder="Récompense — ex. une paire d'AirPods" className={champ + " w-full"} />
          <div className="flex flex-wrap items-center gap-2">
            <label className="text-xs text-gray-500 flex items-center gap-1.5">
              Du <input type="date" value={b.debut} onChange={e => setB(x => ({ ...x, debut: e.target.value }))} className={champ} />
            </label>
            <label className="text-xs text-gray-500 flex items-center gap-1.5">
              au <input type="date" value={b.fin} onChange={e => setB(x => ({ ...x, fin: e.target.value }))} className={champ} />
            </label>
            <button onClick={enregistrer} disabled={!b.recompense?.trim() || !b.debut || !b.fin}
              className="fa-bg-teal disabled:opacity-50 text-xs font-medium px-3 py-1.5 rounded-lg transition">
              Lancer
            </button>
            <button onClick={() => setEdition(false)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
          </div>
          <p className="text-xs text-gray-400">
            Les dossiers sont comptés à leur <strong>souscription</strong>, pas à leur dépôt. Un dossier déposé
            le 28 et souscrit le 3 comptera pour la période suivante — annoncez-le à vos partenaires.
          </p>
        </div>
      ) : !actif ? (
        <p className="text-sm text-gray-500">
          Aucun challenge en cours. Un objectif et une récompense suffisent à déclencher les premiers dossiers
          de partenaires qui n'en ont jamais déposé — c'est là que l'argent travaille le mieux.
        </p>
      ) : (
        <>
          <p className="text-sm text-gray-500 mb-3">
            <strong className="fa-navy">{ch.titre}</strong> — {ch.objectif} dossier{ch.objectif > 1 ? "s" : ""} souscrit{ch.objectif > 1 ? "s" : ""} pour gagner
            {" "}<strong className="fa-navy">{ch.recompense}</strong>.
            {enCours
              ? <> Il reste {joursRestants} jour{joursRestants > 1 ? "s" : ""}.</>
              : <> Période terminée ou pas encore commencée.</>}
          </p>

          {gagnants.length > 0 && (
            <div className="fa-bg-gold rounded-lg px-3 py-2.5 mb-3">
              <div className="text-sm fa-navy font-semibold mb-1">
                🏆 {gagnants.length} partenaire{gagnants.length > 1 ? "s ont" : " a"} atteint l'objectif
              </div>
              <div className="text-xs text-teal-900/80">
                {gagnants.map(x => `${x.p.firstName || ""} ${up(x.p.name)} (${x.n})`).join(" · ")}
              </div>
            </div>
          )}

          {classement.length === 0 ? (
            <div className="text-sm text-gray-400">Aucun dossier souscrit sur la période pour l'instant.</div>
          ) : (
            <div className="space-y-1.5">
              {classement.map(x => {
                const pct = Math.min(100, Math.round((x.n / (ch.objectif || 1)) * 100));
                const atteint = x.n >= ch.objectif;
                return (
                  <div key={x.p.id} className="flex items-center gap-3 flex-wrap">
                    <span className="text-sm fa-navy font-medium w-44 shrink-0 truncate">
                      {nomPartenaire(x.p)}
                    </span>
                    <div className="flex-1 min-w-[120px] h-3 bg-gray-100 rounded-full overflow-hidden">
                      <div className={`h-full ${atteint ? "bg-emerald-500" : "fa-bg-teal"}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className={`text-xs font-semibold shrink-0 ${atteint ? "text-emerald-700" : "text-gray-500"}`}>
                      {x.n} / {ch.objectif}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ProductionDuMois({ data, commerciaux, onSetGoals, canEdit }) {
  const [edition, setEdition] = useState(false);
  const [brouillon, setBrouillon] = useState({});

  const objectifs = data.settings?.challenge || { partenaires: 40, dossiers: 30, ca: 22500 };
  const now = new Date();
  const debut = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
  const fin = new Date(now.getFullYear(), now.getMonth() + 1, 1).getTime();
  const avancement = Math.min(1, Math.max(0, (Date.now() - debut) / (fin - debut)));
  const joursRestants = Math.max(0, Math.ceil((fin - Date.now()) / 86400000));

  const commercialDuDossier = (d) => data.partners.find(p => p.id === d.partnerId)?.commercial || null;

  // --- Réalisé, ventilé par commercial
  const parCommercial = (extracteur) => {
    const m = new Map(commerciaux.map(c => [c, 0]));
    extracteur((c, v) => { if (m.has(c)) m.set(c, m.get(c) + v); });
    return commerciaux.map(c => ({ nom: c, valeur: m.get(c) || 0 })).filter(x => x.valeur > 0);
  };

  const partenaires = parCommercial(ajoute => {
    for (const p of data.partners) {
      if (p.deleted || p.createdAt < debut || p.createdAt >= fin) continue;
      ajoute(p.commercial, 1);
    }
  });

  const dossiers = parCommercial(ajoute => {
    for (const d of data.dossiers) {
      const t = dateGain(d);
      if (t === null || t < debut || t >= fin) continue;
      ajoute(commercialDuDossier(d), 1);
    }
  });

  // Récurrence AJOUTÉE ce mois : la commission mensuelle des contrats dont la
  // date d'effet tombe dans le mois. C'est du revenu nouveau, qui continuera
  // de tomber les mois suivants — à ne pas confondre avec le cumul encaissé.
  const recurrence = parCommercial(ajoute => {
    for (const d of data.dossiers) {
      if (!STATUTS_CONTRAT_VIVANT.includes(d.status) || !d.dateEffet) continue;
      const t = new Date(d.dateEffet + "T12:00:00").getTime();
      if (isNaN(t) || t < debut || t >= fin) continue;
      ajoute(commercialDuDossier(d), recurrenceMensuelle(d));
    }
  });
  const recurrenceTotale = recurrenceMensuelleTotale(data.dossiers);

  const ca = parCommercial(ajoute => {
    for (const d of data.dossiers) {
      if (d.status === "KO") continue;
      const ech = echeancesDe(d);
      const parts = repartir(d.caAmount || 0, ech.length);
      ech.forEach((e, i) => {
        const quand = e.encaisseLe ? new Date(e.encaisseLe + "T12:00:00").getTime()
          : (e.payeSansDate ? (d.paymentDate ? new Date(d.paymentDate).getTime() : d.updatedAt) : null);
        if (quand !== null && quand >= debut && quand < fin) ajoute(commercialDuDossier(d), parts[i]);
      });
    }
  });

  function enregistrer() {
    const champs = {};
    for (const k of ["partenaires", "dossiers", "ca", "recurrence"]) {
      const v = Number(brouillon[k]);
      if (!isNaN(v) && v >= 0) champs[k] = v;
    }
    onSetGoals(champs);
    setEdition(false);
  }

  const Jauge = ({ titre, segments, objectif, format }) => {
    const realise = segments.reduce((s, x) => s + x.valeur, 0);
    const attendu = objectif * avancement;
    const ecart = realise - attendu;
    const finDeMois = avancement > 0.02 ? realise / avancement : null;
    const ratio = objectif > 0 ? realise / objectif : 0;
    const enRetard = ecart < 0;
    const grosRetard = objectif > 0 && ecart < -objectif * 0.2;
    const couleurTexte = grosRetard ? "text-red-700" : enRetard ? "text-amber-700" : "text-emerald-700";
    const f = format || ((n) => Math.round(n));

    return (
      <div>
        <div className="flex items-baseline justify-between gap-2 mb-1.5">
          <span className="text-sm font-semibold fa-navy">{titre}</span>
          <span className="text-sm fa-navy">
            <strong className="font-display text-lg">{f(realise)}</strong>
            <span className="text-gray-400"> / {f(objectif)}</span>
          </span>
        </div>

        <div className="relative h-4 bg-gray-100 rounded-full overflow-hidden">
          <div className="flex h-full">
            {segments.map(seg => (
              <div key={seg.nom}
                title={`${commercialLabel(seg.nom)} — ${f(seg.valeur)}`}
                style={{
                  width: `${objectif > 0 ? Math.min(100, (seg.valeur / objectif) * 100) : 0}%`,
                  backgroundColor: COMMERCIAL_COLORS[seg.nom] || "#999",
                }} />
            ))}
          </div>
          {/* Repère : là où il faudrait en être aujourd'hui. */}
          <div className="absolute top-0 bottom-0 w-0.5 bg-gray-800/70"
            style={{ left: `${avancement * 100}%` }} title="Rythme attendu à date" />
        </div>

        <div className={`text-xs mt-1 ${couleurTexte}`}>
          {objectif <= 0 ? "Aucun objectif fixé." : enRetard
            ? `Il manque ${f(Math.abs(ecart))} pour être dans les temps.`
            : `${f(ecart)} d'avance sur le rythme.`}
          {finDeMois !== null && objectif > 0 && (
            <span className="text-gray-400"> · à ce rythme, fin de mois à {f(finDeMois)}</span>
          )}
          {ratio >= 1 && <span className="text-emerald-700 font-semibold"> · objectif atteint</span>}
        </div>
      </div>
    );
  };

  const euros = (n) => fmtEuro(n);

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
        <div className="font-display font-semibold fa-navy">Production du mois</div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">
            {joursRestants} jour{joursRestants > 1 ? "s" : ""} restant{joursRestants > 1 ? "s" : ""} · {Math.round(avancement * 100)} % du mois écoulé
          </span>
          {canEdit && !edition && (
            <button onClick={() => { setBrouillon({ partenaires: objectifs.partenaires, dossiers: objectifs.dossiers, ca: objectifs.ca, recurrence: objectifs.recurrence ?? "" }); setEdition(true); }}
              className="text-xs fa-teal-text hover:underline">Modifier les objectifs</button>
          )}
        </div>
      </div>

      {edition ? (
        <div className="flex flex-wrap items-center gap-2 my-3">
          {[["partenaires", "Partenaires"], ["dossiers", "Dossiers"], ["ca", "Honoraires (€)"], ["recurrence", "Récurrence ajoutée (€/mois)"]].map(([k, lib]) => (
            <label key={k} className="text-xs text-gray-500 flex items-center gap-1.5">
              {lib}
              <input type="number" min="0" value={brouillon[k] ?? ""}
                onChange={e => setBrouillon(b => ({ ...b, [k]: e.target.value }))}
                className="w-24 text-sm border border-gray-300 rounded-lg px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-teal-500" />
            </label>
          ))}
          <button onClick={enregistrer} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
          <button onClick={() => setEdition(false)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
        </div>
      ) : (
        <p className="text-sm text-gray-500 mb-4">
          Le trait sombre marque où vous devriez en être aujourd'hui. Chaque couleur est un commercial.
        </p>
      )}

      <div className="space-y-4">
        <Jauge titre="Nouveaux partenaires" segments={partenaires} objectif={objectifs.partenaires || 0} />
        <Jauge titre="Dossiers gagnés" segments={dossiers} objectif={objectifs.dossiers || 0} />
        <Jauge titre="C.A. encaissé — honoraires" segments={ca} objectif={objectifs.ca || 0} format={euros} />
        <Jauge titre="Récurrence ajoutée ce mois" segments={recurrence} objectif={objectifs.recurrence || 0} format={euros} />
      </div>

      <div className="text-xs text-gray-500 mt-3">
        Revenu récurrent total du cabinet : <strong className="text-violet-700">{fmtEuroPrecis(recurrenceTotale)} par mois</strong>,
        soit {fmtEuro(recurrenceTotale * 12)} par an tant que les contrats vivent.
        <span className="block text-gray-400 mt-0.5">
          La jauge ci-dessus ne compte que ce que le mois a créé de nouveau, pas le cumul.
        </span>
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-4 pt-3 border-t border-gray-100">
        {commerciaux.map(c => {
          const pa = partenaires.find(x => x.nom === c)?.valeur || 0;
          const dos = dossiers.find(x => x.nom === c)?.valeur || 0;
          const mt = ca.find(x => x.nom === c)?.valeur || 0;
          return (
            <div key={c} className="flex items-center gap-1.5 text-xs">
              <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: COMMERCIAL_COLORS[c] || "#999" }} />
              <span className="fa-navy font-medium">{commercialLabel(c)}</span>
              <span className="text-gray-400">
                {pa} part. · {dos} doss. · {fmtEuro(mt)}
                {(recurrence.find(x => x.nom === c)?.valeur || 0) > 0 && (
                  <span className="text-violet-700"> · +{fmtEuroPrecis(recurrence.find(x => x.nom === c).valeur)}/mois</span>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ObjectifsCA({ data }) {
  const vivants = data.partners.filter(p => !p.deleted);
  const tous = data.dossiers;
  const gagnes = tous.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));
  const ko = tous.filter(d => d.status === "KO");
  const actifs = vivants.filter(p => tous.some(d => d.partnerId === p.id));

  const avecMontant = gagnes.filter(d => (d.caAmount || 0) > 0);
  const caMoyenObserve = avecMontant.length > 0
    ? Math.round(avecMontant.reduce((s, d) => s + (d.caAmount || 0), 0) / avecMontant.length)
    : 500;
  const arbitres = gagnes.length + ko.length;
  const transfoObservee = arbitres > 0 ? Math.round((gagnes.length / arbitres) * 100) : 60;
  const activationObservee = vivants.length > 0 ? Math.round((actifs.length / vivants.length) * 100) : 40;

  const [caMoyen, setCaMoyen] = useState(null);
  const [transfo, setTransfo] = useState(null);
  const [prod, setProd] = useState(1);          // 12 dossiers par an et par partenaire
  const [activation, setActivation] = useState(null);
  const [objectifLibre, setObjectifLibre] = useState("");

  const vCa = caMoyen === null ? caMoyenObserve : (Number(caMoyen) || 0);
  const vTransfo = transfo === null ? transfoObservee : (Number(transfo) || 0);
  const vProd = Number(prod) || 0;
  const vActivation = activation === null ? activationObservee : (Number(activation) || 0);

  const calculable = vCa > 0 && vTransfo > 0 && vProd > 0 && vActivation > 0;

  const objectifs = [100000, 200000, 300000, 500000, 1000000];
  const libre = Number(String(objectifLibre).replace(/\s/g, "")) || 0;
  const liste = libre > 0 ? [...objectifs, libre].sort((a, b) => a - b) : objectifs;

  function besoinsPour(cible) {
    const dossiersGagnes = cible / vCa;
    const dossiersDeposes = dossiersGagnes / (vTransfo / 100);
    const parMois = dossiersDeposes / 12;
    const partenairesActifs = parMois / vProd;
    const partenairesTotal = partenairesActifs / (vActivation / 100);
    return { dossiersGagnes, dossiersDeposes, parMois, partenairesActifs, partenairesTotal };
  }

  const champ = "w-20 text-sm border border-gray-300 rounded-lg px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-teal-500";
  const arrondi = (n) => Math.ceil(n - 0.0001);

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="font-display font-semibold fa-navy mb-1">Combien pour atteindre mon objectif</div>
      <p className="text-sm text-gray-500 mb-4">
        Le calcul à l'envers : vous fixez le chiffre d'affaires visé sur douze mois, l'outil remonte au nombre
        de dossiers et de partenaires nécessaires.
      </p>

      <div className="fa-bg-offwhite rounded-lg px-3 py-3 mb-4">
        <div className="text-xs font-semibold fa-navy mb-2">Hypothèses</div>
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-gray-600">
          <label className="flex items-center gap-2">
            <input type="number" min="0" step="10" value={vCa} onChange={e => setCaMoyen(e.target.value)} className={champ} />
            € de C.A. par dossier gagné
            <span className="text-xs text-gray-400">
              ({avecMontant.length > 0 ? `observé : ${caMoyenObserve} €` : "aucune donnée, valeur à fixer"})
            </span>
          </label>
          <label className="flex items-center gap-2">
            <input type="number" min="1" max="100" step="1" value={vTransfo} onChange={e => setTransfo(e.target.value)} className={champ} />
            % de dossiers qui aboutissent
            <span className="text-xs text-gray-400">
              ({arbitres > 0 ? `observé : ${transfoObservee} %` : "aucune donnée"})
            </span>
          </label>
          <label className="flex items-center gap-2">
            <input type="number" min="0" step="0.1" value={vProd} onChange={e => setProd(e.target.value)} className={champ} />
            dossiers/mois par partenaire actif
            <span className="text-xs text-gray-400">(1,00 = 12 par an)</span>
          </label>
          <label className="flex items-center gap-2">
            <input type="number" min="1" max="100" step="1" value={vActivation} onChange={e => setActivation(e.target.value)} className={champ} />
            % de partenaires qui produisent
            <span className="text-xs text-gray-400">
              ({vivants.length > 0 ? `observé : ${activationObservee} %` : "aucune donnée"})
            </span>
          </label>
          <label className="flex items-center gap-2">
            <input type="number" min="0" step="10000" value={objectifLibre} onChange={e => setObjectifLibre(e.target.value)}
              placeholder="250000" className="w-28 text-sm border border-gray-300 rounded-lg px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-teal-500" />
            objectif personnalisé (€)
          </label>
        </div>
      </div>

      {!calculable ? (
        <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-3">
          Renseignez les quatre hypothèses pour obtenir le tableau.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 text-left border-b border-gray-200">
                  <th className="font-medium py-2">C.A. visé</th>
                  <th className="font-medium py-2 text-right">Dossiers gagnés</th>
                  <th className="font-medium py-2 text-right">Dossiers déposés</th>
                  <th className="font-medium py-2 text-right">Par mois</th>
                  <th className="font-medium py-2 text-right">Partenaires actifs</th>
                  <th className="font-medium py-2 text-right">Partenaires à avoir</th>
                </tr>
              </thead>
              <tbody>
                {liste.map((cible, i) => {
                  const b = besoinsPour(cible);
                  const manquants = Math.max(0, arrondi(b.partenairesTotal) - vivants.length);
                  return (
                    <tr key={cible} className={i % 2 ? "fa-bg-offwhite" : ""}>
                      <td className="py-2 font-bold fa-navy">{fmtEuro(cible)}</td>
                      <td className="py-2 text-right text-gray-600">{arrondi(b.dossiersGagnes)}</td>
                      <td className="py-2 text-right text-gray-600">{arrondi(b.dossiersDeposes)}</td>
                      <td className="py-2 text-right text-gray-600">{b.parMois.toFixed(1)}</td>
                      <td className="py-2 text-right fa-navy font-medium">{arrondi(b.partenairesActifs)}</td>
                      <td className="py-2 text-right">
                        <span className="fa-navy font-bold">{arrondi(b.partenairesTotal)}</span>
                        {manquants > 0 && <span className="text-xs text-amber-700 block">+{manquants} à recruter</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="text-xs text-gray-500 mt-3 space-y-1">
            <div>
              <strong className="fa-navy">Comment lire :</strong> pour {fmtEuro(liste[1] || liste[0])}, il faut
              {" "}{arrondi(besoinsPour(liste[1] || liste[0]).dossiersGagnes)} dossiers gagnés, donc
              {" "}{arrondi(besoinsPour(liste[1] || liste[0]).dossiersDeposes)} déposés puisque
              {" "}{100 - vTransfo} % n'aboutissent pas — soit {besoinsPour(liste[1] || liste[0]).parMois.toFixed(1)} par mois,
              ce qui demande {arrondi(besoinsPour(liste[1] || liste[0]).partenairesActifs)} partenaires qui produisent,
              et donc {arrondi(besoinsPour(liste[1] || liste[0]).partenairesTotal)} partenaires au total
              puisque {100 - vActivation} % ne déposeront jamais.
            </div>
            <div className="text-gray-400">
              Vous avez aujourd'hui {vivants.length} partenaire{vivants.length > 1 ? "s" : ""} dont {actifs.length} actif{actifs.length > 1 ? "s" : ""}.
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function ProjectionCA({ data }) {
  const [fenetre, setFenetre] = useState(90);
  const [scenario, setScenario] = useState(false);
  const JOUR = 86400000;
  const depuis = Date.now() - fenetre * JOUR;

  const tous = data.dossiers;
  const vivants = data.partners.filter(p => !p.deleted);
  const gagnes = tous.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));
  const ko = tous.filter(d => d.status === "KO");

  // Le rythme se mesure sur les DÉPÔTS : c'est la seule date indiscutable.
  const deposesPeriode = tous.filter(d => d.createdAt >= depuis).length;
  const moisFenetre = fenetre / 30.44;
  const rythmeMensuel = deposesPeriode / moisFenetre;

  // Transformation et panier moyen se mesurent sur tout l'historique : sur une
  // fenêtre courte, les dossiers encore en cours fausseraient le taux.
  const arbitres = gagnes.length + ko.length;
  const tauxTransfo = arbitres > 0 ? gagnes.length / arbitres : null;
  const avecMontant = gagnes.filter(d => (d.caAmount || 0) > 0);
  const caMoyen = avecMontant.length > 0
    ? avecMontant.reduce((s2, d) => s2 + (d.caAmount || 0), 0) / avecMontant.length
    : null;

  const assezDeDonnees = deposesPeriode >= 3 && avecMontant.length >= 3 && tauxTransfo !== null;

  // --- Réseau : recrutement observé, activation observée
  const actifs = vivants.filter(p => tous.some(d => d.partnerId === p.id));
  const recrutesPeriode = vivants.filter(p => p.createdAt >= depuis).length;
  const recrutementObserve = Math.round((recrutesPeriode / moisFenetre) * 10) / 10;
  const activationObservee = vivants.length > 0 ? Math.round((actifs.length / vivants.length) * 100) : 30;

  // Hypothèses du scénario, préremplies par l'observation puis modifiables.
  const [recrutement, setRecrutement] = useState(null);
  const [activation, setActivation] = useState(null);
  const [delai, setDelai] = useState(1);
  const [prodSaisie, setProdSaisie] = useState(null);
  const recrutementUtilise = recrutement === null ? recrutementObserve : Number(recrutement) || 0;
  const activationUtilisee = activation === null ? activationObservee : Number(activation) || 0;

  // Production par partenaire actif : le socle observé rapporté à ceux qui
  // produisent réellement. C'est ce qu'apportera chaque nouvel actif.
  const productiviteObservee = actifs.length > 0 ? rythmeMensuel / actifs.length : 0;
  const productivite = prodSaisie === null ? productiviteObservee : (Number(prodSaisie) || 0);

  const now = new Date();
  const debutAnnee = new Date(now.getFullYear(), 0, 1).getTime();
  const caAcquisAnnee = gagnes.filter(d => d.createdAt >= debutAnnee).reduce((s2, d) => s2 + (d.caAmount || 0), 0);
  const caParDossier = assezDeDonnees ? tauxTransfo * caMoyen : 0;
  const caMensuelActuel = assezDeDonnees ? rythmeMensuel * caParDossier : null;

  // Trajectoire : la production du mois en cours est un PLANCHER. Chaque mois
  // on y ajoute ce qu'apportent les partenaires activés depuis, avec un délai
  // de démarrage — un apporteur recruté en mars ne produit pas en mars.
  // Récurrence : chaque contrat souscrit ajoute sa commission mensuelle, qui
  // court ensuite tous les mois. C'est ce qui fait qu'un mois de production
  // continue de rapporter longtemps après.
  const mrrActuel = recurrenceMensuelleTotale(data.dossiers);
  const avecRecurrence = gagnes.filter(d => recurrenceMensuelle(d) > 0);
  // Pour les contrats à venir, c'est le taux de première année qui s'applique :
  // sur un horizon de douze mois, aucun n'atteint son anniversaire.
  const recMoyenne = avecRecurrence.length > 0
    ? avecRecurrence.reduce((s2, d) => s2 + (Number(d.cotisationMensuelle) || 0) * tauxAnnee1(d) / 100, 0) / avecRecurrence.length
    : 0;

  const trajectoire = [];
  if (assezDeDonnees) {
    let cumul = 0, cumulRec = 0, apportNouveaux = 0;
    for (let m = 1; m <= 12; m++) {
      const vaguesActives = Math.max(0, m - delai);
      const nouveauxActifs = vaguesActives * recrutementUtilise * (activationUtilisee / 100);
      const dossiersMois = rythmeMensuel + nouveauxActifs * productivite;
      const caMois = dossiersMois * caParDossier;
      // Le portefeuille existant vieillit — certains contrats passent à leur
      // taux réduit en cours de route — pendant que les nouveaux s'ajoutent.
      apportNouveaux += dossiersMois * (tauxTransfo || 0) * recMoyenne;
      const mrr = mrrDansNMois(data.dossiers, m) + apportNouveaux;
      cumul += caMois;
      cumulRec += mrr;
      const d = new Date(now.getFullYear(), now.getMonth() + m, 1);
      trajectoire.push({
        mois: d.toLocaleDateString("fr-FR", { month: "short", year: "2-digit" }),
        actifs: Math.round(actifs.length + nouveauxActifs),
        dossiers: dossiersMois,
        ca: caMois,
        rec: mrr,
        cumul,
        cumulTotal: cumul + cumulRec,
      });
    }
  }
  const total12Recurrence = trajectoire.length ? trajectoire[11].cumulTotal - trajectoire[11].cumul : null;

  const total12Gele = assezDeDonnees ? caMensuelActuel * 12 : null;
  const total12Scenario = trajectoire.length ? trajectoire[11].cumul : null;

  const moisRestants = 11 - now.getMonth();
  const finAnneeGele = assezDeDonnees ? caAcquisAnnee + caMensuelActuel * moisRestants : null;
  const finAnneeScenario = assezDeDonnees && moisRestants > 0
    ? caAcquisAnnee + trajectoire.slice(0, moisRestants).reduce((s2, x) => s2 + x.ca, 0)
    : caAcquisAnnee;

  const bouton = (v, libelle) => (
    <button key={v} onClick={() => setFenetre(v)}
      className={`text-xs font-medium px-3 py-1 rounded-full transition ${fenetre === v ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
      {libelle}
    </button>
  );
  const champHypo = "w-16 text-sm border border-gray-300 rounded-lg px-2 py-1 text-center focus:outline-none focus:ring-2 focus:ring-teal-500";

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
        <div className="font-display font-semibold fa-navy">Projection de chiffre d'affaires</div>
        <div className="flex gap-1.5">
          {bouton(30, "30 jours")}{bouton(90, "90 jours")}{bouton(180, "6 mois")}
        </div>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        Mesurée sur les {fenetre} derniers jours.
      </p>

      {!assezDeDonnees ? (
        <div className="text-sm text-gray-500 bg-amber-50 border border-amber-200 rounded-lg px-3 py-3">
          <strong className="fa-navy">Pas assez de données pour projeter.</strong>
          <div className="text-xs mt-1">
            Il faut au moins trois dossiers déposés sur la période et trois dossiers gagnés avec un montant renseigné.
            Aujourd'hui : {deposesPeriode} dépôt{deposesPeriode > 1 ? "s" : ""} sur {fenetre} jours, {avecMontant.length} dossier{avecMontant.length > 1 ? "s" : ""} gagné{avecMontant.length > 1 ? "s" : ""} valorisé{avecMontant.length > 1 ? "s" : ""}.
            Toute projection à ce stade serait du bruit.
          </div>
        </div>
      ) : (
        <>
          <div className="grid sm:grid-cols-2 gap-3 mb-4">
            <div className="fa-bg-offwhite rounded-xl p-4">
              <div className="text-xs text-gray-500 mb-1">Au rythme actuel — réseau figé</div>
              <div className="font-display text-2xl font-bold fa-navy">{fmtEuro(total12Gele)}</div>
              <div className="text-[11px] text-gray-400 mt-0.5">
                sur 12 mois · {rythmeMensuel.toFixed(1)} dossiers/mois · fin {now.getFullYear()} : {fmtEuro(finAnneeGele)}
              </div>
            </div>
            <div className="fa-bg-gold rounded-xl p-4">
              <div className="text-xs text-teal-900/70 mb-1">Avec la croissance du réseau</div>
              <div className="font-display text-2xl font-bold fa-navy">{fmtEuro(total12Scenario)}</div>
              <div className="text-[11px] text-teal-900/60 mt-0.5">
                sur 12 mois · {trajectoire[11].actifs} partenaires actifs en fin de période · fin {now.getFullYear()} : {fmtEuro(finAnneeScenario)}
              </div>
            </div>
          </div>

          {total12Recurrence > 0 && (
            <div className="grid sm:grid-cols-3 gap-3 mb-4">
              <div className="bg-white border border-gray-200 rounded-xl p-4">
                <div className="text-xs text-gray-500 mb-1">Honoraires</div>
                <div className="font-display text-lg font-bold fa-navy">{fmtEuro(total12Scenario)}</div>
              </div>
              <div className="bg-violet-50 border border-violet-200 rounded-xl p-4">
                <div className="text-xs text-gray-500 mb-1">Récurrence assureur</div>
                <div className="font-display text-lg font-bold text-violet-700">{fmtEuro(total12Recurrence)}</div>
                <div className="text-[11px] text-gray-400">
                  {fmtEuroPrecis(mrrActuel)}/mois aujourd'hui → {fmtEuroPrecis(trajectoire[11].rec)}/mois dans un an
                </div>
              </div>
              <div className="fa-bg-teal rounded-xl p-4">
                <div className="text-xs text-white/80 mb-1">Total sur 12 mois</div>
                <div className="font-display text-lg font-bold text-white">{fmtEuro(total12Scenario + total12Recurrence)}</div>
              </div>
            </div>
          )}

          <div className="fa-bg-offwhite rounded-lg px-3 py-3 mb-3">
            <div className="text-xs font-semibold fa-navy mb-2">Hypothèses du scénario</div>
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-gray-600">
              <label className="flex items-center gap-2">
                <input type="number" min="0" step="1" value={recrutementUtilise}
                  onChange={e => setRecrutement(e.target.value)} className={champHypo} />
                partenaires recrutés par mois
                <span className="text-xs text-gray-400">(observé : {recrutementObserve})</span>
              </label>
              <label className="flex items-center gap-2">
                <input type="number" min="0" max="100" step="1" value={activationUtilisee}
                  onChange={e => setActivation(e.target.value)} className={champHypo} />
                % qui déposent au moins un dossier
                <span className="text-xs text-gray-400">(observé : {activationObservee} %)</span>
              </label>
              <label className="flex items-center gap-2">
                <input type="number" min="0" max="6" step="1" value={delai}
                  onChange={e => setDelai(Math.max(0, Number(e.target.value) || 0))} className={champHypo} />
                mois avant le premier dossier
              </label>
              <label className="flex items-center gap-2">
                <input type="number" min="0" step="0.1" value={productivite.toFixed(2)}
                  onChange={e => setProdSaisie(e.target.value)} className={champHypo} />
                dossiers/mois par partenaire actif
                <span className="text-xs text-gray-400">(observé : {productiviteObservee.toFixed(2)} · 12/an = 1,00)</span>
              </label>
              {(recrutement !== null || activation !== null || delai !== 1 || prodSaisie !== null) && (
                <button onClick={() => { setRecrutement(null); setActivation(null); setDelai(1); setProdSaisie(null); }}
                  className="text-xs fa-teal-text hover:underline">réinitialiser</button>
              )}
            </div>
            <div className="text-xs text-gray-400 mt-2">
              C'est la productivité par partenaire qui porte le résultat : mesurée sur {actifs.length} partenaire{actifs.length > 1 ? "s" : ""},
              elle est la plus fragile des quatre. Votre propre hypothèse de 12 dossiers par an correspond à 1,00.
            </div>
          </div>

          <button onClick={() => setScenario(v => !v)} className="text-xs fa-teal-text hover:underline mb-2">
            {scenario ? "Masquer la trajectoire" : "Voir la trajectoire mois par mois"}
          </button>

          {scenario && (
            <div className="overflow-x-auto mb-3">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-400 text-left">
                    <th className="font-medium py-1">Mois</th>
                    <th className="font-medium py-1 text-right">Partenaires actifs</th>
                    <th className="font-medium py-1 text-right">Dossiers</th>
                    <th className="font-medium py-1 text-right">Honoraires</th>
                    <th className="font-medium py-1 text-right">Récurrence</th>
                    <th className="font-medium py-1 text-right">Cumul total</th>
                  </tr>
                </thead>
                <tbody>
                  {trajectoire.map((t, i2) => (
                    <tr key={t.mois} className={i2 % 2 ? "fa-bg-offwhite" : ""}>
                      <td className="py-1 fa-navy capitalize">{t.mois}</td>
                      <td className="py-1 text-right text-gray-500">{t.actifs}</td>
                      <td className="py-1 text-right text-gray-500">{t.dossiers.toFixed(1)}</td>
                      <td className="py-1 text-right fa-navy font-medium">{fmtEuro(t.ca)}</td>
                      <td className="py-1 text-right text-violet-700">{fmtEuro(t.rec)}</td>
                      <td className="py-1 text-right fa-navy font-bold">{fmtEuro(t.cumulTotal)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="text-xs text-gray-500 fa-bg-offwhite rounded-lg px-3 py-2.5 space-y-1">
            <div className="font-semibold fa-navy">Sur quoi repose ce calcul</div>
            <div>
              {deposesPeriode} dossier{deposesPeriode > 1 ? "s" : ""} déposé{deposesPeriode > 1 ? "s" : ""} en {fenetre} jours,
              soit <strong className="fa-navy">{rythmeMensuel.toFixed(1)} par mois</strong> — ce rythme sert de plancher, il n'est jamais revu à la baisse.
            </div>
            <div>
              Taux de transformation : <strong className="fa-navy">{Math.round(tauxTransfo * 100)} %</strong>
              <span className="text-gray-400"> ({gagnes.length} gagné{gagnes.length > 1 ? "s" : ""} sur {arbitres} arbitré{arbitres > 1 ? "s" : ""})</span>.
            </div>
            <div>
              C.A. moyen par dossier gagné : <strong className="fa-navy">{fmtEuroPrecis(caMoyen)}</strong>
              <span className="text-gray-400"> (sur {avecMontant.length} dossier{avecMontant.length > 1 ? "s" : ""} valorisé{avecMontant.length > 1 ? "s" : ""})</span>.
            </div>
            <div>
              Réseau : <strong className="fa-navy">{actifs.length}</strong> partenaire{actifs.length > 1 ? "s" : ""} actif{actifs.length > 1 ? "s" : ""} sur {vivants.length}.
            </div>
          </div>

          <p className="text-xs text-gray-400 mt-3">
            Ce n'est pas une prévision mais une arithmétique conditionnelle : elle suppose que le rythme
            tient, que les nouveaux partenaires s'activent au taux indiqué, et ignore la saisonnalité du
            marché immobilier. Regardez surtout laquelle des trois hypothèses fait bouger le résultat —
            c'est le levier sur lequel agir.
          </p>
        </>
      )}
    </div>
  );
}

function Vision360({ data }) {
  const [detail, setDetail] = useState(false);
  const [vueRec, setVueRec] = useState("maintenu");
  const vivants = data.dossiers.filter(d => d.status !== "KO");
  const gagnes = vivants.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));

  // --- Entrées
  const encaisse = gagnes.reduce((s, d) => s + partEncaissee(d, d.caAmount || 0), 0);
  const aPercevoir = gagnes.reduce((s, d) => s + partAVenir(d, d.caAmount || 0), 0);

  // Dossiers gagnés dont l'échéancier n'est pas encore paramétré : le montant
  // est acquis, mais aucune date ne peut être annoncée.
  const sansCalendrier = gagnes.filter(d => {
    const e = echeancesDe(d);
    return e.some(x => !x.encaisseLe && !x.datePrevue);
  });

  // --- Engagements envers le réseau
  const retroAcquise = gagnes.reduce((s, d) => s + partEncaissee(d, d.commissionAmount || 0), 0);
  const retroAVenir = gagnes.reduce((s, d) => s + partAVenir(d, d.commissionAmount || 0), 0);

  const parrainDe = (partnerId) => {
    const p = data.partners.find(x => x.id === partnerId);
    return p && p.parrainId ? p.parrainId : null;
  };
  const primeAcquise = gagnes.reduce((s, d) => s + (parrainDe(d.partnerId) ? partEncaissee(d, d.caAmount || 0) * PARRAINAGE_TAUX : 0), 0);
  const primeAVenir = gagnes.reduce((s, d) => s + (parrainDe(d.partnerId) ? partAVenir(d, d.caAmount || 0) * PARRAINAGE_TAUX : 0), 0);

  // --- Déjà sorti de la caisse
  const facturesReglees = data.partners.filter(p => !p.deleted)
    .reduce((s, p) => s + (p.factures || []).filter(f => f.statut === "Payée").reduce((s2, f) => s2 + (f.montant || 0), 0), 0);
  const versementsParrains = data.partners.filter(p => !p.deleted)
    .reduce((s, p) => s + (p.parrainageVerse || 0) + (p.parrainageVersements || []).reduce((s2, v) => s2 + (v.montant || 0), 0), 0);
  const dejaRegle = facturesReglees + versementsParrains;

  const engage = Math.max(0, retroAcquise + primeAcquise - dejaRegle);
  const libre = encaisse - retroAcquise - primeAcquise;
  const margeAVenir = aPercevoir - retroAVenir - primeAVenir;

  const Ligne = ({ libelle, montant, ton = "", note }) => (
    <div className="flex items-baseline justify-between gap-3 py-1.5 border-b border-gray-100 last:border-0">
      <span className="text-sm text-gray-600">{libelle}{note && <span className="block text-xs text-gray-400">{note}</span>}</span>
      <span className={`text-sm font-bold shrink-0 ${ton}`}>{fmtEuroPrecis(montant)}</span>
    </div>
  );

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
        <div className="font-display font-semibold fa-navy">Trésorerie — vue d'ensemble</div>
        <button onClick={() => setDetail(v => !v)} className="text-xs fa-teal-text hover:underline">
          {detail ? "Masquer le détail" : "Voir le détail"}
        </button>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        Une partie de ce qui est encaissé est déjà due au réseau. Le fond de roulement, c'est ce qui reste après.
      </p>

      <div className="grid sm:grid-cols-4 gap-3 mb-4">
        <div className="fa-bg-offwhite rounded-xl p-4">
          <div className="text-xs text-gray-500 mb-1">Encaissé à ce jour</div>
          <div className="font-display text-xl font-bold text-emerald-600">{fmtEuroPrecis(encaisse)}</div>
        </div>
        <div className="fa-bg-gold rounded-xl p-4">
          <div className="text-xs text-teal-900/70 mb-1">À percevoir</div>
          <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(aPercevoir)}</div>
          <div className="text-[11px] text-teal-900/60 mt-0.5">acquis, pas encore reçu</div>
        </div>
        <div className="fa-bg-offwhite rounded-xl p-4">
          <div className="text-xs text-gray-500 mb-1">Engagé envers le réseau</div>
          <div className="font-display text-xl font-bold text-violet-700">{fmtEuroPrecis(engage)}</div>
          <div className="text-[11px] text-gray-400 mt-0.5">dû et pas encore versé</div>
        </div>
        <div className={`rounded-xl p-4 border ${libre < 0 ? "bg-red-50 border-red-200" : "bg-white border-gray-200"}`}>
          <div className="text-xs text-gray-500 mb-1">Marge sur l'encaissé</div>
          <div className={`font-display text-xl font-bold ${libre < 0 ? "text-red-700" : "fa-navy"}`}>{fmtEuroPrecis(libre)}</div>
          <div className="text-[11px] text-gray-400 mt-0.5">après rétrocessions et primes</div>
        </div>
      </div>

      {(() => {
        const mrr = recurrenceMensuelleTotale(data.dossiers);
        const cumul = recurrenceCumuleeTotale(data.dossiers);
        const contrats = data.dossiers.filter(contratEnCours);
        const sansRecurrence = gagnes.filter(d => recurrenceMensuelle(d) <= 0).length;
        // Affiché même à zéro : une récurrence invisible est une récurrence
        // qu'on oublie de renseigner, et donc du chiffre d'affaires perdu.
        return (
          <div className="bg-violet-50 border border-violet-200 rounded-xl p-4 mb-4">
            <div className="flex items-baseline justify-between flex-wrap gap-2 mb-2">
              <span className="font-display font-semibold fa-navy">Revenu récurrent</span>
              <span className="text-xs text-violet-800">
                commissions versées par l'assureur — non rétrocédées
              </span>
            </div>
            {(() => {
              // Le portefeuille vieillit : chaque contrat passe à son taux
              // réduit à sa date anniversaire. Projeter en multipliant le
              // mensuel actuel par douze surestimerait donc les années à venir.
              const croisiere = contrats.reduce((s2, d) => s2 + recurrenceCroisiere(d), 0);
              const degressifs = contrats.filter(baremeDegressif).length;
              const annees = [1, 2, 3, 4, 5].map(a => ({ a, montant: recurrenceAnnee(data.dossiers, a) }));
              let cumulGlissant = cumul;
              const lignes = annees.map(x => { cumulGlissant += x.montant; return { ...x, cumul: cumulGlissant }; });
              return (
                <>
                  <div className="grid sm:grid-cols-4 gap-3">
                    <div>
                      <div className="text-xs text-gray-500 mb-0.5">Ce mois-ci</div>
                      <div className="font-display text-xl font-bold text-violet-700">{fmtEuroPrecis(mrr)}</div>
                      <div className="text-[11px] text-gray-400">sur {contrats.length} contrat{contrats.length > 1 ? "s" : ""} en cours</div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 mb-0.5">En régime de croisière</div>
                      <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(croisiere)}</div>
                      <div className="text-[11px] text-gray-400">
                        {degressifs > 0 ? `après la 1re année des ${degressifs} contrat${degressifs > 1 ? "s" : ""} dégressif${degressifs > 1 ? "s" : ""}` : "barèmes linéaires"}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 mb-0.5">Déjà perçu</div>
                      <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(cumul)}</div>
                      <div className="text-[11px] text-gray-400">depuis la première date d'effet</div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 mb-0.5">12 prochains mois</div>
                      <div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(lignes[0].montant)}</div>
                      <div className="text-[11px] text-gray-400">portefeuille actuel, sans nouveau dossier</div>
                    </div>
                  </div>

                  {(() => {
                    // Où en est-on réellement : le réalisé, ventilé par régime.
                    const r = recurrencePercueDetaillee(data.dossiers);
                    if (r.total < 0.005) return null;
                    return (
                      <div className="mt-3 pt-3 border-t border-violet-200 text-xs text-gray-600">
                        <span className="font-semibold fa-navy">Où en est-on : </span>
                        sur les <strong className="fa-navy">{fmtEuroPrecis(r.total)}</strong> déjà encaissés,
                        {" "}<strong className="text-violet-700">{fmtEuroPrecis(r.an1)}</strong> proviennent du taux de première année
                        {" "}({r.moisAn1} mensualité{r.moisAn1 > 1 ? "s" : ""})
                        {r.apres > 0.005
                          ? <>, et <strong className="text-violet-700">{fmtEuroPrecis(r.apres)}</strong> du taux des années suivantes ({r.moisApres} mensualité{r.moisApres > 1 ? "s" : ""}).</>
                          : <>. Aucun contrat n'a encore dépassé sa première année.</>}
                        <span className="block text-gray-400 mt-0.5">
                          {r.contratsEnAn1} contrat{r.contratsEnAn1 > 1 ? "s" : ""} encore en première année
                          {r.contratsAuDela > 0 && <> · {r.contratsAuDela} passé{r.contratsAuDela > 1 ? "s" : ""} au taux des années suivantes</>}
                        </span>
                      </div>
                    );
                  })()}

                  {mrr > 0 && (() => {
                    const ry = rythmeRecurrence(data.dossiers);
                    const proj = projectionRecurrence(data.dossiers, vueRec === "maintenu" ? ry.parMois : 0, ry.an1, ry.apres);
                    const maintenu = vueRec === "maintenu";
                    return (
                      <div className="mt-4 pt-3 border-t border-violet-200">
                        <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
                          <span className="text-xs font-semibold fa-navy">La cagnotte, année après année</span>
                          <div className="flex gap-1.5">
                            <button onClick={() => setVueRec("maintenu")}
                              className={`text-[11px] font-medium px-2.5 py-1 rounded-full transition ${maintenu ? "bg-violet-600 text-white" : "bg-white border border-violet-200 text-gray-600"}`}>
                              Si je continue à produire
                            </button>
                            <button onClick={() => setVueRec("acquis")}
                              className={`text-[11px] font-medium px-2.5 py-1 rounded-full transition ${!maintenu ? "bg-violet-600 text-white" : "bg-white border border-violet-200 text-gray-600"}`}>
                              Si j'arrête demain
                            </button>
                          </div>
                        </div>

                        <div className="overflow-x-auto">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="text-gray-400 text-left">
                                <th className="font-medium py-1">Année</th>
                                <th className="font-medium py-1 text-right">Récurrence de l'année</th>
                                <th className="font-medium py-1 text-right">Dont mandataires</th>
                                <th className="font-medium py-1 text-right">Dont Frangola</th>
                                <th className="font-medium py-1 text-right">Cagnotte cumulée</th>
                                <th className="font-medium py-1 text-right">Soit par mois</th>
                              </tr>
                            </thead>
                            <tbody>
                              {proj.map(l => {
                                const montant = maintenu ? l.maintenu : l.acquis;
                                const cumul2 = maintenu ? l.cumulMaintenu : l.cumulAcquis;
                                return (
                                  <tr key={l.annee} className={l.annee % 2 === 0 ? "bg-white/50" : ""}>
                                    <td className="py-1 fa-navy">Année {l.annee}</td>
                                    <td className="py-1 text-right text-violet-700 font-medium">{fmtEuroPrecis(montant)}</td>
                                    <td className="py-1 text-right text-gray-500">{fmtEuroPrecis(montant * PART_MANDATAIRE)}</td>
                                    <td className="py-1 text-right text-gray-500">{fmtEuroPrecis(montant * (1 - PART_MANDATAIRE))}</td>
                                    <td className="py-1 text-right fa-navy font-bold">{fmtEuroPrecis(cumul + cumul2)}</td>
                                    {/* Le revenu mensuel moyen de l'année : le chiffre
                                        qu'on a en tête quand on pense « ça me rapporte
                                        tant par mois ». */}
                                    <td className="py-1 text-right text-violet-700 font-semibold">{fmtEuroPrecis(montant / 12)}</td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>

                        <p className="text-[11px] text-gray-400 mt-2">
                          {maintenu
                            ? <>Au rythme observé de <strong className="text-violet-700">{ry.parMois.toFixed(1)} contrat{ry.parMois >= 2 ? "s" : ""} par mois</strong>,
                                à {fmtEuroPrecis(ry.an1)} la première année puis {fmtEuroPrecis(ry.apres)} ensuite (moyennes sur {ry.echantillon} contrat{ry.echantillon > 1 ? "s" : ""}).
                                Chaque année de production s'ajoute aux précédentes : c'est ce qui fait grossir la cagnotte.</>
                            : <>Aucun dossier nouveau n'est supposé : c'est ce que vous toucherez si vous arrêtez de produire demain.
                                La baisse entre l'année 1 et l'année 2 vient des barèmes dégressifs.</>}
                          {" "}La cagnotte cumulée inclut les {fmtEuroPrecis(cumul)} déjà perçus.
                        </p>
                      </div>
                    );
                  })()}
                </>
              );
            })()}
            <div className="text-xs text-gray-600 mt-3 pt-3 border-t border-violet-200">
              Répartition mensuelle : <strong className="fa-navy">{fmtEuroPrecis(mrr * PART_MANDATAIRE)}</strong> pour les
              mandataires, <strong className="fa-navy">{fmtEuroPrecis(mrr * (1 - PART_MANDATAIRE))}</strong> pour Frangola.
              Rien pour les apporteurs : la récurrence n'est pas rétrocédée.
            </div>
            {sansRecurrence > 0 && (
              <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mt-3">
                {sansRecurrence} dossier{sansRecurrence > 1 ? "s" : ""} gagné{sansRecurrence > 1 ? "s" : ""} sans cotisation ni taux renseignés :
                leur récurrence n'est comptée nulle part. C'est autant de chiffre d'affaires invisible.
              </div>
            )}
          </div>
        );
      })()}

      {sansCalendrier.length > 0 && (
        <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
          {sansCalendrier.length} dossier{sansCalendrier.length > 1 ? "s" : ""} gagné{sansCalendrier.length > 1 ? "s" : ""} sans date d'effet :
          leur montant est acquis, mais aucune date d'encaissement ne peut être annoncée tant que l'échéancier n'est pas renseigné.
        </div>
      )}

      {detail && (
        <div className="grid sm:grid-cols-2 gap-5">
          <div>
            <div className="text-xs font-semibold fa-navy mb-1 uppercase tracking-wide">Ce qui rentre</div>
            <Ligne libelle="Honoraires encaissés" montant={encaisse} ton="text-emerald-700" />
            <Ligne libelle="Honoraires à percevoir" montant={aPercevoir} ton="fa-navy" note="échéances datées, non encore reçues" />
            <Ligne libelle="Total acquis" montant={encaisse + aPercevoir} ton="fa-navy" />
          </div>
          <div>
            <div className="text-xs font-semibold fa-navy mb-1 uppercase tracking-wide">Ce qui sort</div>
            <Ligne libelle="Rétrocessions acquises aux partenaires" montant={retroAcquise} ton="text-violet-700" note="sur les honoraires déjà encaissés" />
            <Ligne libelle="Primes de parrainage acquises" montant={primeAcquise} ton="text-violet-700" />
            <Ligne libelle="Déjà réglé" montant={dejaRegle} ton="text-emerald-700" note="factures payées et versements aux parrains" />
            <Ligne libelle="Reste à régler" montant={engage} ton="text-violet-700" />
          </div>
          <div>
            <div className="text-xs font-semibold fa-navy mb-1 uppercase tracking-wide">Engagements futurs</div>
            <Ligne libelle="Rétrocessions à venir" montant={retroAVenir} ton="text-gray-600" note="dues quand les échéances rentreront" />
            <Ligne libelle="Primes de parrainage à venir" montant={primeAVenir} ton="text-gray-600" />
          </div>
          <div>
            <div className="text-xs font-semibold fa-navy mb-1 uppercase tracking-wide">Ce qui reste à Frangola</div>
            <Ligne libelle="Marge sur l'encaissé" montant={libre} ton={libre < 0 ? "text-red-700" : "fa-navy"} />
            <Ligne libelle="Marge à venir" montant={margeAVenir} ton="fa-navy" note="sur les échéances pas encore reçues" />
            <Ligne libelle="Marge totale attendue" montant={libre + margeAVenir} ton="fa-navy" />
          </div>
        </div>
      )}
    </div>
  );
}

// =============================================================================
// VERSEMENTS AUX PARTENAIRES
//
// Mois par mois, ce qui est dû à chaque partenaire une fois que Frangola a
// encaissé. On dépose l'ordre de virement avec la date : la ligne passe au
// vert, et le partenaire télécharge lui-même son justificatif.
// =============================================================================
function VersementsPartenaires({ data, onVirement, onAnnuler, busy }) {
  const [ouvertId, setOuvertId] = useState(null);      // "partnerId|mois"
  const [date, setDate] = useState("");
  const [fichier, setFichier] = useState(null);
  const [mode, setMode] = useState("Virement");
  const [historique, setHistorique] = useState(false);
  const champ = useRef(null);

  const aujourdhui = () => new Date().toISOString().slice(0, 10);
  const nomDe = (p) => nomPartenaire(p);

  // Deux mécaniques distinctes : les apporteurs immobiliers sont réglés mois
  // par mois au rythme des encaissements ; les hors immobilier reçoivent leur
  // forfait en une fois, dès qu'il est couvert.
  const lignes = [];
  const reglees = [];
  for (const p of data.partners.filter(x => !x.deleted)) {
    const siens = data.dossiers.filter(d => d.partnerId === p.id);
    if (siens.length === 0) continue;
    const forfait = p.flatFee != null;
    const items = forfait
      ? forfaitsRetrocession(p, siens).map(f => ({
          cle: f.cle, libelle: f.libelle, montant: f.montant, etat: f.etat, versement: f.versement,
          detail: f.etat === "a_venir" ? `${fmtEuroPrecis(f.encaisse)} encaissés sur ${fmtEuroPrecis(f.montant)}` : null,
        }))
      : calendrierRetrocession(p, siens).mois.map(m => ({
          cle: m.cle, libelle: m.libelle, montant: m.montant, etat: m.etat, versement: m.versement, detail: null,
        }));
    for (const it of items) {
      if (it.etat === "a_regler") lignes.push({ p, m: it, forfait });
      else if (it.etat === "regle") reglees.push({ p, m: it, forfait });
    }
  }
  lignes.sort((a, b) => a.m.cle.localeCompare(b.m.cle));
  reglees.sort((a, b) => (b.m.versement?.at || 0) - (a.m.versement?.at || 0));

  const total = lignes.reduce((s, x) => s + x.m.montant, 0);

  async function valider(p, m) {
    const ok = await onVirement(p.id, m.cle, m.libelle, m.montant, date || aujourdhui(), fichier, mode);
    if (ok !== false) { setOuvertId(null); setDate(""); setFichier(null); }
  }
  // Les apporteurs hors immobilier sont rémunérés au forfait, et réglés en
  // carte cadeau le plus souvent : on prérègle le mode sur le leur.
  const modeParDefaut = (p) => (p.flatFee != null ? "Carte cadeau" : "Virement");

  if (lignes.length === 0 && reglees.length === 0) return null;

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="font-display font-semibold fa-navy mb-1">Versements aux partenaires</div>
      <p className="text-sm text-gray-500 mb-4">
        Uniquement ce que Frangola a déjà encaissé — on ne verse pas d'argent qu'on n'a pas reçu.
        {lignes.length > 0 && <> Total à régler : <strong className="fa-navy">{fmtEuroPrecis(total)}</strong>.</>}
      </p>

      {lignes.length === 0 ? (
        <div className="text-sm text-gray-400 mb-3">Rien à régler pour l'instant.</div>
      ) : (
        <div className="space-y-1.5">
          {lignes.map(({ p, m }) => {
            const cle = p.id + "|" + m.cle;
            const ouvert = ouvertId === cle;
            return (
              <div key={cle} className="fa-bg-gold rounded-lg px-3 py-2.5">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-sm fa-navy font-bold">{nomDe(p)}</span>
                  {p.flatFee != null && (
                    <span className="text-[11px] font-semibold bg-violet-100 text-violet-800 px-2 py-0.5 rounded-full">Hors immo</span>
                  )}
                  <span className="text-xs text-teal-900/70 capitalize">{m.libelle}</span>
                  <span className="text-sm font-bold fa-navy ml-auto">{fmtEuroPrecis(m.montant)}</span>
                  {!ouvert && (
                    <button onClick={() => { setOuvertId(cle); setDate(aujourdhui()); setFichier(null); setMode(modeParDefaut(p)); }}
                      className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded-lg transition">
                      Enregistrer le virement
                    </button>
                  )}
                </div>
                {ouvert && (
                  <div className="flex items-center gap-2 flex-wrap mt-2">
                    <label className="text-xs text-teal-900/80 flex items-center gap-1.5">
                      Date du virement
                      <input type="date" value={date} onChange={e => setDate(e.target.value)}
                        className="text-xs border border-amber-300 rounded-lg px-2 py-1 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500" />
                    </label>
                    <select value={mode} onChange={e => setMode(e.target.value)}
                      className="text-xs border border-amber-300 rounded-lg px-2 py-1 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500">
                      {PAYMENT_METHODS.map(x => <option key={x} value={x}>{x}</option>)}
                    </select>
                    <button onClick={() => champ.current?.click()}
                      className="text-xs font-medium bg-white border border-amber-300 text-teal-900 px-3 py-1.5 rounded-lg transition">
                      {fichier ? fichier.name : (mode === "Carte cadeau" ? "Joindre la carte cadeau" : "Joindre l'ordre de virement")}
                    </button>
                    <input type="file" accept="application/pdf,image/*" className="hidden" ref={champ}
                      onChange={e => setFichier(e.target.files?.[0] || null)} />
                    <button onClick={() => valider(p, m)} disabled={busy || !date}
                      className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg transition">
                      {busy ? "Enregistrement…" : "Valider"}
                    </button>
                    <button onClick={() => { setOuvertId(null); setFichier(null); }}
                      className="text-xs text-teal-900/60 hover:text-teal-900 px-2">Annuler</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {reglees.length > 0 && (
        <>
          <button onClick={() => setHistorique(v => !v)} className="text-xs fa-teal-text hover:underline mt-3">
            {historique ? "Masquer les versements effectués" : `Voir les ${reglees.length} versement${reglees.length > 1 ? "s" : ""} effectué${reglees.length > 1 ? "s" : ""}`}
          </button>
          {historique && (
            <div className="space-y-1.5 mt-2">
              {reglees.map(({ p, m }) => (
                <div key={p.id + "|" + m.cle} className="flex items-center justify-between gap-2 flex-wrap bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2">
                  <span className="text-sm fa-navy font-medium">{nomDe(p)}</span>
                  <span className="text-xs text-gray-500 capitalize">{m.libelle}</span>
                  <span className="text-xs text-emerald-700">
                    {m.versement.mode === "Carte cadeau" ? "carte cadeau remise" : "versé"} le {fmtDate(new Date(m.versement.dateVirement + "T12:00:00").getTime())}
                  </span>
                  {m.versement.ordre && (
                    <button onClick={() => downloadStoredFile(m.versement.ordre.key, m.versement.ordre.name)}
                      className="flex items-center gap-1 text-xs font-medium text-emerald-700 hover:underline">
                      <Download size={12} /> {m.versement.mode === "Carte cadeau" ? "carte cadeau" : "ordre de virement"}
                    </button>
                  )}
                  <span className="text-sm font-bold text-emerald-700 ml-auto">{fmtEuroPrecis(m.versement.montant)}</span>
                  <button onClick={() => onAnnuler(p.id, m.versement.id)}
                    title="Annuler ce versement — à n'utiliser qu'en cas d'erreur de saisie"
                    className="text-xs text-gray-400 hover:text-red-600">✕</button>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function FacturationAdmin({ data, onSetStatut, onAddVersement, onVirementPartenaire, onAnnulerVirement, busy }) {
  const [toutHistorique, setToutHistorique] = useState(false);

  const nomDe = (p) => p ? (nomPartenaire(p)) : "—";
  const vivants = data.partners.filter(p => !p.deleted);

  // --- Encaissements : ce que nous avons réellement reçu, échéance par
  //     échéance. Un dossier réglé en douze fois n'est pas un encaissement,
  //     c'est douze.
  const dossiersVivants = data.dossiers.filter(d => d.status !== "KO");
  const encaisse = dossiersVivants.reduce((s, d) => s + partEncaissee(d, d.caAmount || 0), 0);

  // --- À percevoir, réparti par mois : c'est la trésorerie qui arrive.
  const aPercevoir = [];
  for (const d of dossiersVivants) {
    const ech = echeancesDe(d);
    if (ech[0] && ech[0].implicite) continue; // dossier antérieur à l'échéancier
    const parts = repartir(d.caAmount || 0, ech.length);
    ech.forEach((e, i) => {
      if (e.encaisseLe || parts[i] < 0.005) return;
      aPercevoir.push({ montant: parts[i], datePrevue: e.datePrevue });
    });
  }
  const totalAPercevoir = aPercevoir.reduce((s, x) => s + x.montant, 0);
  const previsionnel = [];
  for (const x of aPercevoir) {
    const cle = x.datePrevue ? x.datePrevue.slice(0, 7) : "sans-date";
    let ligne = previsionnel.find(m => m.cle === cle);
    if (!ligne) {
      ligne = { cle, montant: 0, nb: 0,
        libelle: x.datePrevue
          ? new Date(x.datePrevue + "T12:00:00").toLocaleDateString("fr-FR", { month: "long", year: "numeric" })
          : "Date d'effet non renseignée" };
      previsionnel.push(ligne);
    }
    ligne.montant += x.montant; ligne.nb += 1;
  }
  previsionnel.sort((a, b) => a.cle.localeCompare(b.cle));

  // --- À payer
  const facturesDues = vivants.flatMap(p =>
    (p.factures || []).filter(f => f.statut === "Déposée")
      .map(f => ({ genre: "facture", cle: "f" + f.id, qui: nomDe(p), partner: p, facture: f, montant: f.montant || 0, depuis: f.at })));

  const retrocessionsDues = vivants
    .filter(p => filleulsDe(p.id).length > 0)
    .map(p => {
      const du = bilanParrainage(p.id).gainTotal;
      const verse = (p.parrainageVerse || 0) + (p.parrainageVersements || []).reduce((sm, v) => sm + (v.montant || 0), 0);
      return { genre: "parrainage", cle: "r" + p.id, qui: nomDe(p), partner: p, montant: du - verse, depuis: p.createdAt };
    })
    .filter(x => x.montant > 0.5);

  const aPayer = [...facturesDues, ...retrocessionsDues].sort((a, b) => (a.depuis || 0) - (b.depuis || 0));
  const totalAPayer = aPayer.reduce((s, x) => s + x.montant, 0);

  // --- Déjà payé, daté
  const historique = [
    ...vivants.flatMap(p => (p.factures || []).filter(f => f.statut === "Payée")
      .map(f => ({ cle: "hf" + f.id, quand: f.traiteAt || f.at, qui: nomDe(p), montant: f.montant || 0,
                   objet: "Facture partenaire", couleur: "bg-violet-100 text-violet-800", note: f.nom || "" }))),
    ...vivants.flatMap(p => (p.parrainageVersements || [])
      .map(v => ({ cle: "hv" + v.id, quand: v.at, qui: nomDe(p), montant: v.montant || 0,
                   objet: "Rétrocession parrainage", couleur: "bg-amber-100 text-amber-800", note: v.note || "" }))),
  ].sort((a, b) => (b.quand || 0) - (a.quand || 0));

  const totalVerse = historique.reduce((s, x) => s + x.montant, 0);
  const visibles = toutHistorique ? historique : historique.slice(0, 15);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-xl font-semibold fa-navy">Facturation</h1>
        <p className="text-sm text-gray-500">Qui reste à payer, et qui a été payé — factures partenaires et rétrocessions de parrainage.</p>
      </div>

      <div className="grid sm:grid-cols-3 gap-4">
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="text-xs text-gray-400 mb-1">Encaissé (dossiers payés)</div>
          <div className="font-display text-2xl font-bold text-emerald-600">{fmtEuroPrecis(encaisse)}</div>
        </div>
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="text-xs text-gray-400 mb-1">Déjà reversé</div>
          <div className="font-display text-2xl font-bold fa-navy">{fmtEuroPrecis(totalVerse)}</div>
        </div>
        <div className={`rounded-2xl p-5 border ${totalAPayer > 0.5 ? "fa-bg-gold border-amber-300" : "bg-white border-gray-200"}`}>
          <div className="text-xs text-gray-500 mb-1">Reste à payer</div>
          <div className="font-display text-2xl font-bold fa-navy">{fmtEuroPrecis(totalAPayer)}</div>
        </div>
      </div>

      {previsionnel.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-2xl p-5">
          <div className="font-display font-semibold fa-navy mb-1">À percevoir</div>
          <p className="text-sm text-gray-500 mb-4">
            Honoraires acquis mais pas encore reçus — total <strong className="fa-navy">{fmtEuroPrecis(totalAPercevoir)}</strong>.
            Ils conditionnent ce que tu pourras reverser aux partenaires et aux parrains.
          </p>
          <div className="space-y-1.5">
            {previsionnel.map(m => (
              <div key={m.cle} className={`flex items-center justify-between rounded-lg px-3 py-2 ${m.cle === "sans-date" ? "bg-amber-50 border border-amber-200" : "fa-bg-offwhite"}`}>
                <span className="text-sm fa-navy capitalize">{m.libelle}</span>
                <span className="text-xs text-gray-400">{m.nb} échéance{m.nb > 1 ? "s" : ""}</span>
                <span className="text-sm font-bold fa-navy">{fmtEuroPrecis(m.montant)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-2xl p-5">
        <div className="font-display font-semibold fa-navy mb-1">À payer</div>
        <p className="text-sm text-gray-500 mb-4">La plus ancienne dette en premier.</p>
        {aPayer.length === 0 ? (
          <div className="text-sm text-gray-400">Rien en attente — tout le monde est à jour.</div>
        ) : (
          <div className="space-y-1.5">
            {aPayer.map(x => (
              <div key={x.cle} className="flex items-center gap-2 flex-wrap fa-bg-offwhite rounded-lg px-3 py-2.5">
                <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full shrink-0 ${x.genre === "facture" ? "bg-violet-100 text-violet-800" : "bg-amber-100 text-amber-800"}`}>
                  {x.genre === "facture" ? "Facture" : "Parrainage"}
                </span>
                <span className="text-sm fa-navy font-bold">{x.qui}</span>
                <span className="text-xs text-gray-400">{joursDepuis(x.depuis)}</span>
                <span className="ml-auto text-sm font-bold fa-navy">{fmtEuroPrecis(x.montant)}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-white border border-gray-200 rounded-2xl p-5">
        <div className="font-display font-semibold fa-navy mb-1">Historique des paiements</div>
        <p className="text-sm text-gray-500 mb-4">Du plus récent au plus ancien.</p>
        {historique.length === 0 ? (
          <div className="text-sm text-gray-400">Aucun paiement enregistré pour l'instant.</div>
        ) : (
          <>
            <div className="space-y-1.5">
              {visibles.map(h => (
                <div key={h.cle} className="flex items-center gap-2 flex-wrap fa-bg-offwhite rounded-lg px-3 py-2">
                  <span className="text-xs text-gray-500 w-24 shrink-0">{fmtDate(h.quand)}</span>
                  <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full shrink-0 ${h.couleur}`}>{h.objet}</span>
                  <span className="text-sm fa-navy font-medium">{h.qui}</span>
                  {h.note && <span className="text-xs text-gray-400">{h.note}</span>}
                  <span className="ml-auto text-sm font-bold text-emerald-700">{fmtEuroPrecis(h.montant)}</span>
                </div>
              ))}
            </div>
            {historique.length > 15 && (
              <button onClick={() => setToutHistorique(v => !v)} className="text-xs fa-teal-text hover:underline mt-3">
                {toutHistorique ? "Réduire" : `Voir les ${historique.length - 15} paiements plus anciens →`}
              </button>
            )}
          </>
        )}
      </div>

      <VersementsPartenaires data={data} onVirement={onVirementPartenaire} onAnnuler={onAnnulerVirement} busy={busy} />
      <FacturesPartenaires data={data} onSetStatut={onSetStatut} />
      <VersementsParrainage data={data} onAddVersement={onAddVersement} />
    </div>
  );
}

function FacturesPartenaires({ data, onSetStatut }) {
  const [corrigeId, setCorrigeId] = useState(null);
  const [motif, setMotif] = useState("");

  const lignes = [];
  for (const p of data.partners) {
    for (const f of (p.factures || [])) lignes.push({ p, f });
  }
  if (lignes.length === 0) return null;

  const attente = lignes.filter(x => x.f.statut === "Déposée").sort((a, b) => a.f.at - b.f.at);
  const traitees = lignes.filter(x => x.f.statut !== "Déposée").sort((a, b) => b.f.at - a.f.at).slice(0, 8);
  const totalDu = attente.reduce((s, x) => s + (x.f.montant || 0), 0);
  const nomDe = (p) => nomPartenaire(p);

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-4">
      <div className="font-display font-semibold fa-navy mb-1">
        Factures partenaires
        {attente.length > 0 && (
          <span className="ml-2 fa-bg-gold fa-navy text-xs font-bold px-2 py-0.5 rounded-full">
            {attente.length} à régler · {fmtEuroPrecis(totalDu)}
          </span>
        )}
      </div>
      <p className="text-sm text-gray-500 mb-4">Factures de commission déposées par vos apporteurs.</p>

      {attente.length === 0 && <div className="text-sm text-gray-400 mb-3">Aucune facture en attente.</div>}

      <div className="space-y-2">
        {attente.map(({ p, f }) => (
          <div key={f.id} className="fa-bg-offwhite rounded-lg px-3 py-2.5">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
              <div>
                <div className="text-sm fa-navy font-bold">{nomDe(p)}</div>
                <div className="text-xs text-gray-400">
                  Déposée le {fmtDate(f.at)}{f.montant != null ? ` · ${fmtEuro(f.montant)}` : " · montant non précisé"}
                </div>
              </div>
              <button onClick={() => downloadStoredFile(f.key, f.name)}
                className="flex items-center gap-1.5 text-xs font-medium fa-navy fa-bg-gold px-3 py-1.5 rounded-lg transition">
                <Download size={14} /> {f.name}
              </button>
            </div>
            {corrigeId === f.id ? (
              <div className="space-y-2 mt-2">
                <input value={motif} onChange={e => setMotif(e.target.value)}
                  placeholder="Ce qui doit être corrigé — visible par le partenaire"
                  className="w-full border border-gray-300 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <div className="flex gap-2">
                  <button onClick={() => { onSetStatut(p.id, f.id, "À corriger", motif.trim()); setCorrigeId(null); setMotif(""); }}
                    className="text-xs font-semibold bg-red-600 hover:bg-red-700 text-white px-3 py-1.5 rounded-lg transition">Confirmer</button>
                  <button onClick={() => { setCorrigeId(null); setMotif(""); }}
                    className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                </div>
              </div>
            ) : (
              <div className="flex gap-2 mt-2">
                <button onClick={() => onSetStatut(p.id, f.id, "Payée", "")}
                  className="text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded-lg transition">Marquer payée</button>
                <button onClick={() => setCorrigeId(f.id)}
                  className="text-xs font-semibold bg-white border border-gray-300 hover:border-red-300 text-gray-600 px-3 py-1.5 rounded-lg transition">À corriger</button>
              </div>
            )}
          </div>
        ))}
      </div>

      {traitees.length > 0 && (
        <div className="mt-4 pt-3 border-t border-gray-100 space-y-1">
          <div className="text-xs font-semibold fa-navy mb-1">Traitées récemment</div>
          {traitees.map(({ p, f }) => (
            <div key={f.id} className="flex items-center justify-between flex-wrap gap-2 text-xs py-1">
              <span className="fa-navy">{nomDe(p)} · {fmtDate(f.at)}{f.montant != null ? ` · ${fmtEuro(f.montant)}` : ""}</span>
              <span className={f.statut === "Payée" ? "text-emerald-700 font-semibold" : "text-red-700"}>
                {f.statut === "Payée" ? "Payée" : `À corriger — ${f.motif}`}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SauvegardesPanel() {
  const [liste, setListe] = useState(null);
  const [busy, setBusy] = useState(false);

  async function charger() {
    setBusy(true);
    try {
      const res = await storage.list("adp:backup:", true);
      const cles = (res?.keys || []).sort().reverse();
      const details = [];
      for (const cle of cles) {
        try {
          const item = await storage.get(cle, true);
          const parsed = JSON.parse(item.value);
          details.push({ cle, jour: cle.replace("adp:backup:", ""), at: parsed.at, partenaires: parsed.partenaires, dossiers: parsed.dossiers });
        } catch (e) { /* ignore */ }
      }
      setListe(details);
    } catch (e) {
      setListe([]);
    } finally { setBusy(false); }
  }

  async function telecharger(cle, jour) {
    try {
      const item = await storage.get(cle, true);
      const parsed = JSON.parse(item.value);
      downloadJson(`frangola-adp-sauvegarde-${jour}.json`, parsed.data);
    } catch (e) { /* ignore */ }
  }

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
        <div className="font-display font-semibold fa-navy">Sauvegardes automatiques</div>
        <button onClick={charger} disabled={busy}
          className="text-xs fa-teal-text hover:underline disabled:opacity-50">
          {busy ? "Chargement…" : (liste ? "Rafraîchir" : "Afficher")}
        </button>
      </div>
      <p className="text-sm text-gray-500 mb-4">
        Une copie est déposée à chaque première connexion de la journée. Les 7 dernières sont conservées.
      </p>
      {liste === null && <div className="text-sm text-gray-400">Cliquez sur « Afficher » pour voir les sauvegardes disponibles.</div>}
      {liste !== null && liste.length === 0 && <div className="text-sm text-gray-400">Aucune sauvegarde pour l'instant — la première sera créée à votre prochaine connexion.</div>}
      {liste !== null && liste.length > 0 && (
        <div className="space-y-2">
          {liste.map(s => (
            <div key={s.cle} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
              <div>
                <div className="text-sm fa-navy font-bold">{fmtDate(s.at)}</div>
                <div className="text-xs text-gray-400">{s.partenaires} partenaire{s.partenaires !== 1 ? "s" : ""} · {s.dossiers} dossier{s.dossiers !== 1 ? "s" : ""}</div>
              </div>
              <button onClick={() => telecharger(s.cle, s.jour)}
                className="text-xs font-medium fa-navy fa-bg-gold px-3 py-1.5 rounded-lg transition">
                Télécharger
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AdminDashboard({ data, currentAdmin, isFullAdmin, viewerLabel, viewerTelephone, onSetViewerTelephone, onUpdateAdmin, onSetAssureurs, onUploadContratType, onVirementPartenaire, onAnnulerVirement, onSetChallengePartenaires, onLogout, onAddPartner, onUpdatePartner, onUploadPartnerContract, onDeletePartner, onRestorePartner, onUpdateStatus, onUpdateDossierClient, onDeleteDossier, onUpdateDossierNotes, onUpdateDossierSimulation, onAnalyzeDossierIA, onUpdateDossierPartnerMessage, onUploadBordereau, onAdminUploadDoc, onRemoveDoc, onSwapDocs, onAddExtraDoc, onRemoveExtraDoc, onAddMandataire, onUpdateMandataire, onDeleteMandataire, onResetMandataireTotp, onSetChallengeGoals, onTraiterParrainage, onSetFactureStatut, onAddVersementParrainage, onApercuPartner, onRestoreMandataire, onUploadReseauLogo, onRemoveReseauLogo, busy }) {
  const COMMERCIAUX = ["Sébastien", ...data.mandataires.filter(m => !m.deleted).map(m => m.name)];
  const parrainagesEnAttente = (data.parrainages || []).filter(x => x.statut === "en_attente").length;
  const facturesEnAttente = data.partners.reduce((s, p) => s + (p.factures || []).filter(f => f.statut === "Déposée").length, 0);
  const actionsPartenaires = parrainagesEnAttente + facturesEnAttente;
  const livePartnerIds = new Set(data.partners.filter(p => !p.deleted).map(p => p.id));
  const liveDossiers = data.dossiers.filter(d => livePartnerIds.has(d.partnerId));
  const [tab, setTabRaw] = useState(() => getStoredTab("adp:adminTab", "accueil"));
  const setTab = (t) => { setTabRaw(t); setStoredTab("adp:adminTab", t); };
  useEffect(() => { if (tab === "mandataires" && !isFullAdmin) setTab("accueil"); }, []);
  // Ordre personnalisé des onglets et mode discret : deux réglages de confort,
  // propres à cet ordinateur, qui n'ont pas à voyager dans les données.
  const [ordreOnglets, setOrdreOnglets] = useState(lireOrdreOnglets);
  const [reorganiser, setReorganiser] = useState(false);
  // initModeDiscret positionne le drapeau global AVANT le premier rendu :
  // au rechargement d'une page en pleine visio, aucun chiffre n'apparaît.
  const [discret, setDiscretState] = useState(initModeDiscret);
  function basculerDiscret() {
    const v = !discret;
    setModeDiscret(v);
    setDiscretState(v);
  }
  const [newPartnerName, setNewPartnerName] = useState("");
  const [newPartnerFirstName, setNewPartnerFirstName] = useState("");
  const [newPartnerCompany, setNewPartnerCompany] = useState("");
  const [newPartnerFlatFee, setNewPartnerFlatFee] = useState("");
  const [newPartnerPostalCode, setNewPartnerPostalCode] = useState("");
  const [newPartnerVille, setNewPartnerVille] = useState("");
  const [newPartnerDepartement, setNewPartnerDepartement] = useState("");
  useEffect(() => {
    let active = true;
    lookupVilleFromCodePostal(newPartnerPostalCode).then(res => {
      if (active && res) { setNewPartnerVille(res.ville); setNewPartnerDepartement(res.departement || ""); }
    });
    return () => { active = false; };
  }, [newPartnerPostalCode]);
  const [newPartnerEmail, setNewPartnerEmail] = useState("");
  const [newPartnerTelephone, setNewPartnerTelephone] = useState("");
  const [newPartnerSiret, setNewPartnerSiret] = useState("");
  const [newPartnerCommercial, setNewPartnerCommercial] = useState(COMMERCIAUX[0]);
  const [createdPartner, setCreatedPartner] = useState(null);
  const [copiedId, setCopiedId] = useState(null);
  const [editingId, setEditingId] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [editingDossierId, setEditingDossierId] = useState(null);
  const [editDossierForm, setEditDossierForm] = useState({});
  const [statsPeriod, setStatsPeriod] = useState("jour");
  const [showAddPartnerForm, setShowAddPartnerForm] = useState(false);
  const [corbeilleSearch, setCorbeilleSearch] = useState("");
    const [partnerSearch, setPartnerSearch] = useState("");
  const [corbeilleMandataireSearch, setCorbeilleMandataireSearch] = useState("");
  const [confirmDeleteMandataireId, setConfirmDeleteMandataireId] = useState(null);
  async function confirmDeleteMandataire(id) {
    await onDeleteMandataire(id);
    setConfirmDeleteMandataireId(null);
  }
  const [showAddMandataireForm, setShowAddMandataireForm] = useState(false);
  const [editingMandataireId, setEditingMandataireId] = useState(null);
  const [editMandataireForm, setEditMandataireForm] = useState({});
  const [viewingMandataireId, setViewingMandataireId] = useState(null);
  function startEditMandataire(m) {
    setEditingMandataireId(m.id);
    setEditMandataireForm({ name: m.name || "", firstName: m.firstName || "", email: m.email || "", color: m.color || commercialColor(m.name), role: m.role || "standard" });
  }
  async function saveEditMandataire(id) {
    await onUpdateMandataire(id, editMandataireForm);
    setEditingMandataireId(null);
  }
  const [newMandataireName, setNewMandataireName] = useState("");
  const [newMandataireFirstName, setNewMandataireFirstName] = useState("");
  const [newMandataireEmail, setNewMandataireEmail] = useState("");
  const [newMandataireColor, setNewMandataireColor] = useState("#545454");
  const [newMandataireRole, setNewMandataireRole] = useState("standard");
  const [createdMandataire, setCreatedMandataire] = useState(null);
  const [dossierSearch, setDossierSearch] = useState("");
  const [dossierFilter, setDossierFilter] = useState("tous");
  const [commercialFilter, setCommercialFilter] = useState("tous");
  const [statsDepartementFilter, setStatsDepartementFilter] = useState("tous");
  const [statsReseauFilter, setStatsReseauFilter] = useState("tous");
  const [notesOpenId, setNotesOpenId] = useState(null);
  const [simOpenId, setSimOpenId] = useState(null);
  const [simDraft, setSimDraft] = useState({});
  const [simAnalyzing, setSimAnalyzing] = useState(null);
  const [simAnalysisResult, setSimAnalysisResult] = useState(null);
  const [simAutoReclassified, setSimAutoReclassified] = useState(false);
  const [simAnalyzeError, setSimAnalyzeError] = useState("");
  function openSim(d) {
    setSimOpenId(d.id);
    setSimAnalyzeError("");
    setSimAnalysisResult(null);
    setSimAutoReclassified(false);
    setSimDraft({
      crd: d.simulation?.crd ?? "", crdDate: d.simulation?.crdDate ?? "",
      assuranceRestante: d.simulation?.assuranceRestante ?? "", dureeRestanteMois: d.simulation?.dureeRestanteMois ?? "",
            devisAssurance: d.simulation?.devisAssurance ?? "",
    });
  }
  function saveSim(id) {
    onUpdateDossierSimulation(id, {
      crd: simDraft.crd === "" ? null : Number(simDraft.crd),
      crdDate: simDraft.crdDate,
      assuranceRestante: simDraft.assuranceRestante === "" ? null : Number(simDraft.assuranceRestante),
            devisAssurance: simDraft.devisAssurance === "" ? null : Number(simDraft.devisAssurance),
      dureeRestanteMois: simDraft.dureeRestanteMois === "" ? null : Number(simDraft.dureeRestanteMois),
    });
    setSimOpenId(null);
  }
  const [notesDraft, setNotesDraft] = useState("");
  const [messageOpenId, setMessageOpenId] = useState(null);
  const [messageDraft, setMessageDraft] = useState("");
  const [historyOpenId, setHistoryOpenId] = useState(null);
  const [financeOpenId, setFinanceOpenId] = useState(null);
  const [financeDraft, setFinanceDraft] = useState({ caAmount: "", commissionAmount: "" });
  const STALE_HOURS = 24;
  const PRISE_EN_CHARGE_HOURS = 24;
  const DEVIS_HOURS = 72;
  const PAIEMENT_ALERT_DAYS = 15;
  const [nowTick, setNowTick] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60000);
    return () => clearInterval(t);
  }, []);
  // Côté admin les dossiers sont pliés par défaut : on ne mémorise que ceux
  // que l'utilisateur a ouverts. Une recherche les déplie tous temporairement.
  const [ouverts, setOuverts] = useState(new Set());
  const estPlie = (id) => !ouverts.has(id);
  function toggleFolder(id) {
    setOuverts(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }
  const bordereauInputs = useRef({});

  const newDeposits = liveDossiers.filter(d => d.status === "Déposé").length;
  const partnerName = (id) => data.partners.find(p => p.id === id)?.name || "—";

  async function handleAddPartner() {
    if (!newPartnerName.trim()) return;
    const p = await onAddPartner({
      name: newPartnerName.trim(),
      firstName: newPartnerFirstName.trim(),
      company: newPartnerCompany.trim(),
      ville: newPartnerVille.trim(),
      postalCode: newPartnerPostalCode.trim(),
      departement: newPartnerDepartement,
      email: newPartnerEmail.trim(),
      telephone: newPartnerTelephone.trim(),
      siret: newPartnerSiret.replace(/\D/g, ""),
      commercial: newPartnerCommercial,
      flatFee: newPartnerFlatFee !== "" ? Number(newPartnerFlatFee) : null,
    });
    setCreatedPartner(p);
    setNewPartnerName(""); setNewPartnerFirstName(""); setNewPartnerCompany("");
    setNewPartnerPostalCode(""); setNewPartnerVille(""); setNewPartnerDepartement(""); setNewPartnerEmail(""); setNewPartnerCommercial(COMMERCIAUX[0]); setNewPartnerFlatFee(""); setNewPartnerTelephone(""); setNewPartnerSiret("");
  }
  function startEdit(p) {
    setEditingId(p.id);
    setEditForm({
      name: p.name || "", firstName: p.firstName || "", company: p.company || "",
      ville: p.ville || "", postalCode: p.postalCode || "", email: p.email || "", commercial: p.commercial || COMMERCIAUX[0],
      telephone: p.telephone || "", siret: p.siret || "",
      departement: p.departement || "",
      flatFee: p.flatFee != null ? String(p.flatFee) : "",
      parrainId: p.parrainId || "",
    });
  }
  useEffect(() => {
    if (!editingId || !editForm.postalCode) return;
    let active = true;
    lookupVilleFromCodePostal(editForm.postalCode).then(res => {
      if (active && res) setEditForm(f => ({ ...f, ville: res.ville, departement: res.departement || f.departement }));
    });
    return () => { active = false; };
  }, [editForm.postalCode, editingId]);
  async function saveEdit(id) {
    await onUpdatePartner(id, { ...editForm, flatFee: editForm.flatFee !== "" ? Number(editForm.flatFee) : null });
    setEditingId(null);
  }
  // Délivre (ou renouvelle) le code d'activation d'un accès. Le mot de passe
  // lui-même vit chez Supabase : nous ne pouvons ni le lire ni le changer
  // depuis ici — c'est précisément le but. Ce code permet à la personne de
  // créer ou reprendre son mot de passe elle-même, une seule fois.
  async function reinitialiserAcces(genre, id) {
    const nouveauCode = genCode();
    const champs = { code: nouveauCode, accesReinitialise: true, codeEmisLe: Date.now() };
    if (genre === "partner") await onUpdatePartner(id, champs);
    else await onUpdateMandataire(id, champs);
  }

  async function toggleActive(p) {
    await onUpdatePartner(p.id, { active: p.active === false ? true : false });
  }
  const INACTIVITY_DAYS = 30;
  function daysSinceLastDossier(p) {
    const pDossiers = data.dossiers.filter(d => d.partnerId === p.id);
    const lastAt = pDossiers.length ? Math.max(...pDossiers.map(d => d.createdAt)) : p.createdAt;
    return Math.floor((nowTick - lastAt) / 86400000);
  }
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [confirmDeleteDossierId, setConfirmDeleteDossierId] = useState(null);
  const [adminExtraDocOpenId, setAdminExtraDocOpenId] = useState(null);
  const [adminExtraDocLabel, setAdminExtraDocLabel] = useState("");
  const [adminExtraDocFile, setAdminExtraDocFile] = useState(null);
  function renderDocUpload(d) {
    return (
      <>
        <div className="flex flex-wrap gap-2 mt-3">
          {Object.keys(DOC_LABELS).map(k => d.docs[k] ? (
            <span key={k} className="text-xs bg-white border border-gray-200 hover:border-teal-300 text-gray-600 px-2.5 py-1 rounded-full flex items-center gap-1">
              <button onClick={() => downloadStoredFile(d.docs[k].key, d.docs[k].name)}
                className="flex items-center gap-1 hover:text-teal-700 transition">
                <FileText size={12} /> {DOC_LABELS[k]} <Download size={11} />
              </button>
              <button onClick={() => onRemoveDoc(d.id, k)} className="fa-tap text-gray-400 hover:text-red-600 ml-0.5" title="Retirer ce document">
                <X size={12} />
              </button>
            </span>
          ) : (
            <label key={k} className="fa-tap text-xs bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-700 px-2.5 py-1 rounded-full flex items-center gap-1 transition cursor-pointer">
              <Upload size={12} /> Ajouter "{DOC_LABELS[k]}" (reçu par email)
              <input type="file" accept="application/pdf,image/*" className="hidden"
                onChange={e => e.target.files?.[0] && onAdminUploadDoc(d.id, k, e.target.files[0])} />
            </label>
          ))}
          {(d.extraDocs || []).map((ed, i) => (
            <span key={i} className="text-xs bg-teal-50 border border-teal-200 fa-teal-text px-2.5 py-1 rounded-full flex items-center gap-1">
              <button onClick={() => downloadStoredFile(ed.key, ed.name)} className="flex items-center gap-1 hover:underline">
                <FileText size={12} /> {ed.label} <Download size={11} />
              </button>
              <button onClick={() => onRemoveExtraDoc(d.id, i)} className="fa-tap text-teal-500 hover:text-red-600 ml-0.5" title="Retirer ce document">
                <X size={12} />
              </button>
            </span>
          ))}
        </div>
        <div className="mt-2">
          {adminExtraDocOpenId === d.id ? (
            <div className="flex flex-wrap items-center gap-2 bg-gray-50 rounded-lg p-2.5">
              <input value={adminExtraDocLabel} onChange={e => setAdminExtraDocLabel(e.target.value)}
                placeholder="Nom de la pièce" className="text-sm border border-gray-300 rounded-lg px-2.5 py-1.5 w-40 focus:outline-none focus:ring-2 focus:ring-teal-500" />
              <label className="text-xs border border-gray-300 rounded-lg px-2.5 py-1.5 cursor-pointer bg-white hover:border-teal-400 transition">
                {adminExtraDocFile ? adminExtraDocFile.name : "Choisir un PDF"}
                <input type="file" accept="application/pdf,image/*" className="hidden" onChange={e => setAdminExtraDocFile(e.target.files?.[0] || null)} />
              </label>
              <button onClick={async () => {
                if (!adminExtraDocFile) return;
                const ok = await onAddExtraDoc(d.id, adminExtraDocLabel.trim(), adminExtraDocFile);
                if (ok) { setAdminExtraDocOpenId(null); setAdminExtraDocLabel(""); setAdminExtraDocFile(null); }
              }} disabled={!adminExtraDocFile}
                className="fa-bg-teal disabled:opacity-50 text-xs font-medium px-3 py-1.5 rounded-lg transition">Ajouter</button>
              <button onClick={() => { setAdminExtraDocOpenId(null); setAdminExtraDocLabel(""); setAdminExtraDocFile(null); }}
                className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
            </div>
          ) : (
            <button onClick={() => setAdminExtraDocOpenId(d.id)} className="fa-tap text-xs text-gray-400 hover:fa-teal-text">
              + Déposer une pièce complémentaire reçue par email
            </button>
          )}
        </div>
      </>
    );
  }
  const [fileToutVoir, setFileToutVoir] = useState(false);
  const [viewingPartnerId, setViewingPartnerId] = useState(null);
  // Fiches dont la liste des filleuls est dépliée (clic sur la pastille dorée).
  const [filleulsOuverts, setFilleulsOuverts] = useState(new Set());
  function toggleFilleuls(id) {
    setFilleulsOuverts(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }
  const [viewingPartnerTab, setViewingPartnerTab] = useState("analytique");
  async function confirmDelete(id) {
    await onDeletePartner(id);
    setConfirmDeleteId(null);
  }
  function startEditDossier(d) {
    setEditingDossierId(d.id);
    setEditDossierForm({
      clientFirstName: d.clientFirstName || "", clientLastName: d.clientLastName || "", clientPhone: d.clientPhone || "",
      hasCoEmprunteur: !!d.hasCoEmprunteur, coClientLastName: d.coClientLastName || "", coClientFirstName: d.coClientFirstName || "", coClientPhone: d.coClientPhone || "",
    });
  }
  async function saveEditDossier(id) {
    await onUpdateDossierClient(id, editDossierForm);
    setEditingDossierId(null);
  }
  function openNotes(d) {
    setNotesOpenId(d.id);
    setNotesDraft(d.notes || "");
  }
  async function saveNotes(id) {
    await onUpdateDossierNotes(id, notesDraft);
    setNotesOpenId(null);
  }
  function openMessage(d) {
    setMessageOpenId(d.id);
    setMessageDraft(d.partnerMessage || "");
  }
  async function saveMessage(id) {
    await onUpdateDossierPartnerMessage(id, messageDraft);
    setMessageOpenId(null);
  }
  function openFinance(d) {
    setFinanceOpenId(d.id);
    setFinanceDraft({ caAmount: d.caAmount ?? "", commissionAmount: d.commissionAmount ?? "" });
  }
  async function saveFinance(id) {
    await onUpdateDossierClient(id, {
      caAmount: financeDraft.caAmount === "" ? null : Number(financeDraft.caAmount),
      commissionAmount: financeDraft.commissionAmount === "" ? null : Number(financeDraft.commissionAmount),
    });
    setFinanceOpenId(null);
  }
  function isStale(d) {
    if (d.status === "KO" || d.status === "Bordereau émis" || d.status === "Payé" || d.onHold) return false;
    return nowTick - (d.updatedAt || d.createdAt) > STALE_HOURS * 3600000;
  }
  function staleHours(d) {
    return Math.floor((nowTick - (d.updatedAt || d.createdAt)) / 3600000);
  }
  function formatDuration(ms) {
    if (ms < 0) ms = 0;
    const totalMin = Math.floor(ms / 60000);
    const days = Math.floor(totalMin / 1440);
    const hours = Math.floor((totalMin % 1440) / 60);
    const mins = totalMin % 60;
    if (days > 0) return `${days}j ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}min`;
    return `${mins}min`;
  }
  function getTakenChargeAt(d) {
    const entry = (d.history || []).find(h => h.status !== "Déposé");
    return entry ? entry.at : null;
  }
  function getQuoteIssuedAt(d) {
    const entry = (d.history || []).find(h => h.status === "Devis en cours");
    return entry ? entry.at : null;
  }
  function getBordereauAt(d) {
    const entry = (d.history || []).find(h => h.status === "Bordereau émis");
    return entry ? entry.at : null;
  }
  function actionReasons(d) {
    if (d.onHold || d.status === "KO" || d.status === "Payé") return [];
    const reasons = [];
    if (d.status === "Déposé") reasons.push("Nouveau dépôt à vérifier");
    if (d.status === "Bordereau émis") {
      const bAt = getBordereauAt(d);
      if (bAt && nowTick - bAt > PAIEMENT_ALERT_DAYS * 86400000) reasons.push(`Paiement en attente depuis ${Math.floor((nowTick - bAt) / 86400000)}j`);
      return reasons;
    }
    if (isStale(d)) reasons.push(`${staleHours(d)}h sans changement`);
    if (!getTakenChargeAt(d) && nowTick - d.createdAt > PRISE_EN_CHARGE_HOURS * 3600000) reasons.push("Prise en charge en retard (>24h)");
    if (!getQuoteIssuedAt(d) && nowTick - d.createdAt > DEVIS_HOURS * 3600000) reasons.push("Devis en retard (>72h)");
    return reasons;
  }
  async function toggleOnHold(d) {
    await onUpdateDossierClient(d.id, { onHold: !d.onHold });
  }
  function findDuplicates(d) {
    if (!d.clientLastName) return [];
    return data.dossiers.filter(other =>
      other.id !== d.id &&
      other.clientLastName?.trim().toLowerCase() === d.clientLastName.trim().toLowerCase() &&
      other.clientFirstName?.trim().toLowerCase() === (d.clientFirstName || "").trim().toLowerCase()
    );
  }
  function copyCode(code, id) {
    navigator.clipboard?.writeText(code);
    setCopiedId(id); setTimeout(() => setCopiedId(null), 1500);
  }

  return (
    <div className={`min-h-screen ${discret ? "mode-discret" : ""}`}>
      <header className="px-6 py-4 flex items-center justify-between border-b border-gray-100 bg-white">
        <Logo size="text-lg" />
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500 hidden sm:inline">Connecté : <strong className="fa-navy">{viewerLabel}</strong></span>
          <ChampTelephoneSignature valeur={viewerTelephone} onEnregistrer={onSetViewerTelephone} />
          <button onClick={() => downloadJson(`frangola-adp-sauvegarde-${new Date().toISOString().slice(0, 10)}.json`, data)}
            title="Sauvegarder toutes les données (JSON)"
            className="text-gray-400 hover:fa-teal-text transition">
            <Download size={18} />
          </button>
          <button onClick={onLogout} className="text-gray-400 hover:text-red-600"><LogOut size={18} /></button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        {(() => {
          // Barre d'onglets : elle est construite à partir du catalogue et de
          // l'ordre choisi par l'utilisateur, avec deux commandes à droite —
          // le mode discret (démonstration en visio) et la réorganisation.
          const catalogue = Object.fromEntries(ONGLETS_ADMIN.map(o => [o.id, o]));
          const visibles = ordreOnglets
            .map(id => catalogue[id])
            .filter(o => o && (!o.fullAdmin || isFullAdmin));

          const puce = "text-xs font-bold rounded-full min-w-[20px] h-5 px-1.5 flex items-center justify-center";
          const badgeDe = (id) => {
            if (id === "dossiers") {
              return newDeposits > 0
                ? <span className={`fa-bg-gold fa-navy ${puce}`}>{masqueNb(newDeposits)}</span>
                : null;
            }
            if (id === "partenaires") {
              return actionsPartenaires > 0 ? (
                <span className={`fa-bg-gold fa-navy ${puce}`}
                  title={[
                    parrainagesEnAttente > 0 ? `${parrainagesEnAttente} déclaration${parrainagesEnAttente > 1 ? "s" : ""} de parrainage à traiter` : null,
                    facturesEnAttente > 0 ? `${facturesEnAttente} facture${facturesEnAttente > 1 ? "s" : ""} à régler` : null,
                  ].filter(Boolean).join(" · ")}>
                  {masqueNb(actionsPartenaires)}
                </span>
              ) : null;
            }
            if (id === "facturation") {
              const n = data.partners.filter(p => !p.deleted).reduce((s2, p) => s2 + (p.factures || []).filter(f => f.statut === "Déposée").length, 0);
              return n > 0 ? <span className={`bg-amber-400 text-amber-950 ${puce}`}>{masqueNb(n)}</span> : null;
            }
            if (id === "corbeille") {
              const n = data.partners.filter(p => p.deleted).length;
              return n > 0 ? <span className={`bg-gray-200 text-gray-600 ${puce}`}>{masqueNb(n)}</span> : null;
            }
            return null;
          };

          // On permute dans l'ordre complet, mais d'après le voisin VISIBLE :
          // un onglet caché ne doit pas absorber un déplacement.
          const deplacer = (id, sens) => {
            const rang = visibles.findIndex(o => o.id === id);
            const cible = visibles[rang + sens];
            if (!cible) return;
            const suivant = [...ordreOnglets];
            const a = suivant.indexOf(id), b = suivant.indexOf(cible.id);
            if (a < 0 || b < 0) return;
            suivant[a] = cible.id; suivant[b] = id;
            setOrdreOnglets(suivant);
            ecrireOrdreOnglets(suivant);
          };

          return (
            <div className="mb-8">
              <div className="flex gap-2 items-center overflow-x-auto pb-1 -mx-1 px-1 sm:flex-wrap sm:overflow-visible">
                {visibles.map((o, i) => {
                  const Icone = o.icone ? ICONES_ONGLETS[o.icone] : null;
                  return (
                    <div key={o.id} className="flex items-center shrink-0">
                      {reorganiser && (
                        <button onClick={() => deplacer(o.id, -1)} disabled={i === 0}
                          title="Déplacer vers la gauche"
                          className="text-gray-400 hover:fa-teal-text disabled:opacity-20 px-1 text-lg leading-none">‹</button>
                      )}
                      <button onClick={() => { if (!reorganiser) setTab(o.id); }}
                        className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap ${tab === o.id ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"} ${reorganiser ? "ring-2 ring-teal-300" : ""}`}>
                        {Icone ? <Icone size={15} /> : <span>{o.emoji}</span>} {o.label}
                        {badgeDe(o.id)}
                      </button>
                      {reorganiser && (
                        <button onClick={() => deplacer(o.id, 1)} disabled={i === visibles.length - 1}
                          title="Déplacer vers la droite"
                          className="text-gray-400 hover:fa-teal-text disabled:opacity-20 px-1 text-lg leading-none">›</button>
                      )}
                    </div>
                  );
                })}
                <div className="flex items-center gap-1 shrink-0 sm:ml-auto">
                  <button onClick={basculerDiscret}
                    title={discret ? "Réafficher les chiffres" : "Mode discret : masquer chiffres et noms le temps d'une démonstration"}
                    className={`flex items-center gap-1.5 text-sm font-medium px-3 py-2 rounded-full transition whitespace-nowrap border ${discret ? "bg-amber-100 border-amber-300 text-amber-900" : "bg-white border-gray-200 text-gray-500 hover:fa-teal-text"}`}>
                    {discret ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                  <button onClick={() => setReorganiser(r => !r)}
                    title="Réorganiser mes onglets"
                    className={`flex items-center text-sm font-medium px-3 py-2 rounded-full transition whitespace-nowrap border ${reorganiser ? "fa-bg-teal text-white border-transparent" : "bg-white border-gray-200 text-gray-500 hover:fa-teal-text"}`}>
                    <ArrowLeftRight size={15} />
                  </button>
                </div>
              </div>

              {reorganiser && (
                <div className="mt-3 flex items-center gap-3 flex-wrap text-xs bg-teal-50 border border-teal-200 rounded-xl px-3 py-2">
                  <span className="fa-teal-text">Range tes onglets avec les flèches ‹ › — l'ordre est mémorisé sur cet ordinateur.</span>
                  <button onClick={() => { setOrdreOnglets([...ORDRE_ONGLETS_DEFAUT]); ecrireOrdreOnglets(ORDRE_ONGLETS_DEFAUT); }}
                    className="underline fa-teal-text">Remettre l'ordre d'origine</button>
                  <button onClick={() => setReorganiser(false)}
                    className="ml-auto fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg">Terminé</button>
                </div>
              )}

              {/* Aucun bandeau quand le mode discret est actif : il serait lu
                  par le partenaire en visio, à qui on n'a pas à signaler qu'on
                  lui masque quelque chose. Le seul repère est l'œil barré,
                  discret, et les « ••• » que seul l'admin sait interpréter. */}
            </div>
          );
        })()}

        {tab === "accueil" && (() => {
          const priorityItems = liveDossiers
            .map(d => ({ d, reasons: actionReasons(d) }))
            .filter(x => x.reasons.length > 0);

          // File d'attente unique : tout ce qui attend une action de Frangola,
          // quelle qu'en soit la nature, trié du plus ancien au plus récent.
          // Sans cela l'information reste éparpillée entre quatre onglets.
          const nomPartenaireParId = (id) => {
            const x = data.partners.find(p => p.id === id);
            return x ? nomPartenaire(x) : "—";
          };

          const fileAttente = [
            ...priorityItems.map(({ d, reasons }) => ({
              cle: "d-" + d.id,
              categorie: "Dossier",
              couleur: "bg-teal-100 text-teal-800",
              titre: clientName(d),
              detail: reasons.join(" · "),
              depuis: d.createdAt,
              aller: () => { setDossierFilter("tous"); setDossierSearch(`${d.clientFirstName} ${d.clientLastName}`); setTab("dossiers"); },
            })),
            ...(data.parrainages || []).filter(x => x.statut === "en_attente").map(x => ({
              cle: "p-" + x.id,
              categorie: "Parrainage",
              couleur: "bg-amber-100 text-amber-800",
              titre: MODE_DISCRET ? nomFictif(x.id || "") : (`${x.prenom || ""} ${up(x.nom || "")}`.trim() || "Filleul sans nom"),
              detail: `présenté par ${nomPartenaireParId(x.parrainId)} — à valider`,
              depuis: x.at,
              aller: () => setTab("partenaires"),
            })),
            ...data.partners.filter(p => !p.deleted).flatMap(p =>
              (p.factures || []).filter(f => f.statut === "Déposée").map(f => ({
                cle: "f-" + f.id,
                categorie: "Facture",
                couleur: "bg-violet-100 text-violet-800",
                titre: nomPartenaire(p),
                detail: `facture de ${fmtEuroPrecis(f.montant || 0)} à régler`,
                depuis: f.at,
                aller: () => setTab("partenaires"),
              }))),
            ...data.partners.filter(p => !p.deleted && filleulsDe(p.id).length > 0).map(p => {
              const du = bilanParrainage(p.id).gainTotal;
              const verse = (p.parrainageVerse || 0) + (p.parrainageVersements || []).reduce((sm, v) => sm + (v.montant || 0), 0);
              return { p, reste: du - verse };
            }).filter(x => x.reste > 0.5).map(x => ({
              cle: "v-" + x.p.id,
              categorie: "Parrainage",
              couleur: "bg-amber-100 text-amber-800",
              titre: nomPartenaire(x.p),
              detail: `rétrocession de ${fmtEuroPrecis(x.reste)} à verser`,
              depuis: x.p.createdAt,
              aller: () => setTab("partenaires"),
            })),
            ...(data.settings?.contratType
              ? data.partners.filter(p => !p.deleted && p.email && !p.contratAccepteLe).map(p => ({
                  cle: "c-" + p.id,
                  categorie: "Contrat",
                  couleur: "bg-red-100 text-red-800",
                  titre: nomPartenaire(p),
                  detail: "contrat de partenariat pas encore accepté",
                  depuis: p.createdAt,
                  aller: () => setTab("partenaires"),
                }))
              : []),
            ...data.partners.filter(p => !p.deleted && !p.email).map(p => ({
              cle: "i-" + p.id,
              categorie: "Fiche",
              couleur: "bg-gray-200 text-gray-700",
              titre: nomPartenaire(p),
              detail: "email manquant — accès impossible",
              depuis: p.createdAt,
              aller: () => setTab("partenaires"),
            })),
          ].sort((a, b) => (a.depuis || 0) - (b.depuis || 0));
          const now = new Date();
          const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
          const dossiersActifs = liveDossiers.filter(d => !["KO", "Payé"].includes(d.status)).length;
          // Encaissé ce mois : les échéances effectivement reçues, pas les
          // dossiers souscrits. Un dossier réglé en douze fois ne gonfle plus
          // le mois de la signature.
          const caduMois = liveDossiers.filter(d => d.status !== "KO").reduce((s, d) => {
            const ech = echeancesDe(d);
            const parts = repartir(d.caAmount || 0, ech.length);
            return s + ech.reduce((s2, e, i) => {
              const quand = e.encaisseLe ? new Date(e.encaisseLe + "T12:00:00").getTime()
                : (e.payeSansDate ? (d.paymentDate ? new Date(d.paymentDate).getTime() : d.updatedAt) : null);
              return s2 + (quand !== null && quand >= monthStart ? parts[i] : 0);
            }, 0);
          }, 0);
          const partenairesActifs = data.partners.filter(p => !p.deleted && p.active !== false).length;

          return (
            <div className="space-y-6">
              <div>
                <h1 className="font-display text-xl font-semibold fa-navy">Bonjour {viewerLabel} 👋</h1>
                <p className="text-sm text-gray-500">Voici où en est votre activité aujourd'hui.</p>
              </div>

              <div className="grid sm:grid-cols-4 gap-4">
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Dossiers actifs</div>
                  <div className="font-display text-2xl font-bold fa-navy">{masqueNb(dossiersActifs)}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Nouveaux dépôts</div>
                  <div className="font-display text-2xl font-bold text-amber-600">{masqueNb(newDeposits)}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Encaissé ce mois</div>
                  <div className="font-display text-2xl font-bold text-emerald-600">{fmtEuro(caduMois)}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Partenaires actifs</div>
                  <div className="font-display text-2xl font-bold fa-teal-text">{masqueNb(partenairesActifs)}</div>
                </div>
              </div>

              {fileAttente.length > 0 ? (
                <div className="border border-red-200 bg-red-50 rounded-2xl p-4">
                  <div className="flex items-center gap-2 font-display font-semibold text-red-800 mb-1">
                    <AlertCircle size={16} /> {fileAttente.length} chose{fileAttente.length > 1 ? "s" : ""} à traiter
                  </div>
                  <div className="text-xs text-red-700/70 mb-3">La plus ancienne en premier.</div>
                  <div className="space-y-1.5">
                    {fileAttente.slice(0, fileToutVoir ? fileAttente.length : 8).map(item => (
                      <button key={item.cle} onClick={item.aller}
                        className="w-full text-left text-sm bg-white hover:bg-red-100/50 border border-red-100 rounded-lg px-3 py-2 transition flex items-center gap-2 flex-wrap">
                        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full shrink-0 ${item.couleur}`}>{item.categorie}</span>
                        <span className="fa-navy font-bold">{item.titre}</span>
                        <span className="text-red-700 text-xs">{item.detail}</span>
                        <span className="ml-auto text-xs text-gray-400 shrink-0">{joursDepuis(item.depuis)}</span>
                      </button>
                    ))}
                  </div>
                  {fileAttente.length > 8 && (
                    <button onClick={() => setFileToutVoir(v => !v)} className="text-xs fa-teal-text hover:underline mt-3">
                      {fileToutVoir ? "Réduire la liste" : `Voir les ${fileAttente.length - 8} autres →`}
                    </button>
                  )}
                </div>
              ) : (
                <div className="text-center text-gray-400 text-sm py-8 border border-dashed border-gray-200 rounded-2xl">
                  ✅ Rien ne nécessite d'action pour l'instant.
                </div>
              )}

              <button onClick={() => setTab("dossiers")} className="fa-bg-teal text-sm font-medium px-5 py-2.5 rounded-lg transition">
                Voir tous les dossiers →
              </button>
            </div>
          );
        })()}

        {tab === "dossiers" && (
          <div className="space-y-4">
            {(() => {
              const priorityItems = data.dossiers
                .map(d => ({ d, reasons: actionReasons(d) }))
                .filter(x => x.reasons.length > 0)
                .sort((a, b) => b.reasons.length - a.reasons.length);
              if (priorityItems.length === 0) return null;
              return (
                <div className="border border-red-200 bg-red-50 rounded-2xl p-4">
                  <div className="flex items-center gap-2 font-display font-semibold text-red-800 mb-3">
                    <AlertCircle size={16} /> {priorityItems.length} dossier{priorityItems.length > 1 ? "s" : ""} nécessite{priorityItems.length > 1 ? "nt" : ""} une action — Priorités du jour
                  </div>
                  <div className="space-y-1.5">
                    {priorityItems.map(({ d, reasons }) => (
                      <button key={d.id} onClick={() => setDossierSearch(`${d.clientFirstName} ${d.clientLastName}`)}
                        className="w-full text-left text-sm bg-white hover:bg-red-100/50 border border-red-100 rounded-lg px-3 py-2 transition flex items-center justify-between gap-2 flex-wrap">
                        <span className="fa-navy font-bold">{clientName(d)}</span>
                        <span className="text-red-700 text-xs">{reasons.join(" · ")}</span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })()}
            <div className="flex gap-1.5 mb-1 overflow-x-auto pb-1 -mx-1 px-1 sm:flex-wrap sm:overflow-visible">
              {[
                ["tous", "Tous", liveDossiers.length],
                ["Déposé", "Déposé", liveDossiers.filter(d => d.status === "Déposé").length],
                ["En vérification", "En vérification", liveDossiers.filter(d => d.status === "En vérification").length],
                ["Devis en cours", "Devis en cours", liveDossiers.filter(d => d.status === "Devis en cours").length],
                ["Souscrit", "Souscrit", liveDossiers.filter(d => d.status === "Souscrit").length],
                ["Bordereau émis", "Bordereau émis", liveDossiers.filter(d => d.status === "Bordereau émis").length],
                ["Payé", "Payé", liveDossiers.filter(d => d.status === "Payé").length],
                ["KO", "KO", liveDossiers.filter(d => d.status === "KO").length],
                ["action", "Nécessite une action", liveDossiers.filter(d => actionReasons(d).length > 0).length],
              ].map(([val, label, count]) => (
                <button key={val} onClick={() => { setDossierFilter(val); setDossierSearch(""); }}
                  className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-full transition whitespace-nowrap shrink-0 ${dossierFilter === val ? "fa-bg-teal" : "bg-white border border-gray-200 text-gray-600 hover:border-teal-300"}`}>
                  {label}
                  <span className={`text-[10px] font-bold rounded-full w-4 h-4 flex items-center justify-center ${dossierFilter === val ? "bg-white/25" : "bg-gray-100 text-gray-500"}`}>
                    {count}
                  </span>
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 mb-2">
              <div className="relative flex-1">
                <input value={dossierSearch} onChange={e => setDossierSearch(e.target.value)}
                  placeholder="Rechercher un client par nom ou prénom…"
                  className="w-full border border-gray-300 rounded-lg pl-9 pr-8 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">⌕</span>
                {dossierSearch && (
                  <button onClick={() => setDossierSearch("")}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-red-600 transition">
                    <X size={15} />
                  </button>
                )}
              </div>
              <select value={commercialFilter} onChange={e => setCommercialFilter(e.target.value)}
                style={commercialFilter !== "tous" ? { backgroundColor: COMMERCIAL_COLORS[commercialFilter], color: "#fff" } : {}}
                className="text-sm font-medium border border-gray-300 rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-teal-500">
                <option value="tous">Tous les commerciaux</option>
                {COMMERCIAUX.map(c => <option key={c} value={c}>{commercialLabel(c)}</option>)}
              </select>
              <button onClick={() => exportDossiersCsv(data.dossiers, data.partners)}
                className="text-sm font-medium bg-white border border-gray-200 hover:border-teal-300 fa-teal-text px-4 py-2.5 rounded-lg transition whitespace-nowrap">
                Exporter CSV
              </button>
            </div>
            {data.partners.filter(p => !p.deleted).length === 0 && (
              <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">Aucun partenaire pour l'instant — crée-en un dans l'onglet "Partenaires".</div>
            )}
            {(() => {
              const searchTerm = dossierSearch.trim().toLowerCase();
              const matchesFilter = (d) => {
                if (dossierFilter === "tous") return true;
                if (dossierFilter === "action") return actionReasons(d).length > 0;
                return d.status === dossierFilter;
              };
              const matchesSearch = (d) => matchesFilter(d) && (!searchTerm || `${d.clientFirstName} ${d.clientLastName}`.toLowerCase().includes(searchTerm));
              const deptGroups = {};
              data.partners.filter(p => !p.deleted && (commercialFilter === "tous" || p.commercial === commercialFilter)).forEach(p => {
                const key = p.departement || "Non renseigné";
                if (!deptGroups[key]) deptGroups[key] = [];
                deptGroups[key].push(p);
              });
              const deptKeys = Object.keys(deptGroups).sort((a, b) => {
                if (a === "Non renseigné") return 1;
                if (b === "Non renseigné") return -1;
                return a.localeCompare(b, undefined, { numeric: true });
              });
              return deptKeys.map(deptKey => {
                const partnersInDeptAll = [...deptGroups[deptKey]].sort((a, b) => (a.ville || "").localeCompare(b.ville || ""));
                const filterActive = !!searchTerm || dossierFilter !== "tous";
                const partnersInDept = filterActive
                  ? partnersInDeptAll.filter(p => data.dossiers.some(d => d.partnerId === p.id && matchesSearch(d)))
                  : partnersInDeptAll;
                if (filterActive && partnersInDept.length === 0) return null;
                const deptDossiers = data.dossiers.filter(d => partnersInDeptAll.some(p => p.id === d.partnerId));
                const deptNewCount = deptDossiers.filter(d => d.status === "Déposé").length;
                const deptFolderKey = "dept:" + deptKey;
                const isDeptCollapsed = filterActive ? false : estPlie(deptFolderKey);
                return (
                  <div key={deptFolderKey} className="rounded-2xl overflow-hidden border-2 border-teal-100 shadow-sm">
                    <button onClick={() => toggleFolder(deptFolderKey)}
                      className="w-full flex items-center justify-between px-5 py-4 fa-bg-pink hover:brightness-95 transition">
                      <div className="flex items-center gap-3">
                        {isDeptCollapsed ? <Folder className="fa-navy" size={22} /> : <FolderOpen className="fa-navy" size={22} />}
                        <div className="text-left">
                          <div className="font-display font-bold fa-navy">
                            {deptKey === "Non renseigné" ? "Département non renseigné" : `Département ${deptKey}`}
                          </div>
                          <div className="text-xs text-teal-900/70">{partnersInDeptAll.length} partenaire{partnersInDeptAll.length !== 1 ? "s" : ""} · {deptDossiers.length} dossier{deptDossiers.length !== 1 ? "s" : ""}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2.5">
                        {deptNewCount > 0 && <span className="fa-bg-gold fa-navy text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center">{deptNewCount}</span>}
                        <ChevronDown size={16} className={`fa-navy transition-transform ${isDeptCollapsed ? "" : "rotate-180"}`} />
                      </div>
                    </button>

                    {!isDeptCollapsed && (
                      <div className="fa-bg-offwhite p-2.5 sm:p-4 space-y-4">
                        {partnersInDept.map(p => {
                          const partnerDossiersAll = data.dossiers.filter(d => d.partnerId === p.id).sort((a, b) => b.createdAt - a.createdAt);
                          const partnerDossiers = filterActive ? partnerDossiersAll.filter(matchesSearch) : partnerDossiersAll;
                          const newCount = partnerDossiersAll.filter(d => d.status === "Déposé").length;
                          const isCollapsed = filterActive ? false : estPlie(p.id);
                          return (
                            <div key={p.id} className="bg-white border border-gray-200 rounded-2xl overflow-hidden shadow-sm">
                              <button onClick={() => toggleFolder(p.id)}
                                className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-50 transition">
                                <div className="flex items-center gap-3">
                                  {isCollapsed ? <Folder className="fa-teal-text" size={20} /> : <FolderOpen className="fa-teal-text" size={20} />}
                                  <div className="text-left">
                                    <div className="font-display font-semibold fa-navy flex items-center gap-2">
                                      <span className="font-bold">{nomPartenaire(p)}</span>
                                      {p.active === false && <span className="text-xs font-semibold bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">Inactif</span>}
                                    </div>
                                    <div className="text-xs text-gray-400 flex items-center flex-wrap gap-1.5">{afficheReseau(p.company) || "—"} {!MODE_DISCRET && p.ville && `· ${p.ville}`} · Commercial : <span className="text-white text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[p.commercial] || "#999" }}>{commercialLabel(p.commercial) || "—"}</span> · {masqueNb(partnerDossiers.length)} dossier{partnerDossiers.length !== 1 ? "s" : ""}</div>
                                  </div>
                                </div>
                                <div className="flex items-center gap-2.5">
                                  {newCount > 0 && <span className="fa-bg-gold fa-navy text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center">{newCount}</span>}
                                  <ChevronDown size={16} className={`text-gray-400 transition-transform ${isCollapsed ? "" : "rotate-180"}`} />
                                </div>
                              </button>

                              {!isCollapsed && (
                                <div className="border-t border-gray-100 fa-bg-offwhite p-2.5 sm:p-4 space-y-4">
                                  {partnerDossiers.length === 0 && (
                                    <div className="text-center text-gray-400 text-sm py-8">Aucun dossier déposé par ce partenaire.</div>
                                  )}
                                  {partnerDossiers.map(d => (
                                    <div key={d.id} className="bg-white border border-gray-200 rounded-2xl p-3.5 sm:p-5 shadow-sm">
                                      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                                        {editingDossierId === d.id ? (
                                          <div className="w-full space-y-2">
                                            <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2">
                                              <input value={editDossierForm.clientLastName}
                                                onChange={e => setEditDossierForm(f => ({ ...f, clientLastName: e.target.value }))}
                                                placeholder="Nom" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-32 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                              <input value={editDossierForm.clientFirstName}
                                                onChange={e => setEditDossierForm(f => ({ ...f, clientFirstName: e.target.value }))}
                                                placeholder="Prénom" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-32 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                              <input value={editDossierForm.clientPhone}
                                                onChange={e => setEditDossierForm(f => ({ ...f, clientPhone: e.target.value }))}
                                                type="tel" placeholder="Téléphone" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                            <label className="flex items-center gap-2 text-xs text-gray-600">
                                              <input type="checkbox" checked={editDossierForm.hasCoEmprunteur}
                                                onChange={e => setEditDossierForm(f => ({ ...f, hasCoEmprunteur: e.target.checked }))}
                                                className="rounded border-gray-300" />
                                              Co-emprunteur
                                            </label>
                                            {editDossierForm.hasCoEmprunteur && (
                                              <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2 bg-violet-50 border border-violet-200 rounded-lg p-2">
                                                <input value={editDossierForm.coClientLastName}
                                                  onChange={e => setEditDossierForm(f => ({ ...f, coClientLastName: e.target.value }))}
                                                  placeholder="Nom co-emprunteur" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                                <input value={editDossierForm.coClientFirstName}
                                                  onChange={e => setEditDossierForm(f => ({ ...f, coClientFirstName: e.target.value }))}
                                                  placeholder="Prénom co-emprunteur" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                                <input value={editDossierForm.coClientPhone}
                                                  onChange={e => setEditDossierForm(f => ({ ...f, coClientPhone: e.target.value }))}
                                                  type="tel" placeholder="Téléphone" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full sm:w-36 focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                              </div>
                                            )}
                                            <div className="flex gap-2">
                                              <button onClick={() => saveEditDossier(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                                              <button onClick={() => setEditingDossierId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Annuler</button>
                                            </div>
                                          </div>
                                        ) : (
                                          <div>
                                            <div className="font-bold fa-navy flex items-center gap-2 flex-wrap">
                                              {clientName(d)}
                                              <CoEmprunteurBadge d={d} />
                                              <button onClick={() => startEditDossier(d)} className="fa-tap text-xs fa-teal-text hover:underline font-normal">Modifier</button>
                                              {findDuplicates(d).length > 0 && (
                                                <span className="text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200 px-2 py-0.5 rounded-full">
                                                  ⚠ Doublon possible ({findDuplicates(d).length})
                                                </span>
                                              )}
                                              {confirmDeleteDossierId === d.id ? (
                                                <span className="flex items-center gap-1.5 text-xs">
                                                  <span className="text-red-700">Supprimer définitivement ?</span>
                                                  <button onClick={() => { onDeleteDossier(d.id); setConfirmDeleteDossierId(null); }} className="font-semibold text-red-700 hover:underline">Oui</button>
                                                  <button onClick={() => setConfirmDeleteDossierId(null)} className="text-gray-500 hover:underline">Non</button>
                                                </span>
                                              ) : (
                                                <button onClick={() => setConfirmDeleteDossierId(d.id)} className="fa-tap text-xs text-gray-400 hover:text-red-600 font-normal">Supprimer</button>
                                              )}
                                            </div>
                                            <div className="text-xs text-gray-400">
                                              Déposé le {fmtDate(d.createdAt)}
                                              {d.clientPhone && <> · <a href={`tel:${d.clientPhone}`} className="fa-teal-text hover:underline">{d.clientPhone}</a></>}
                                              {d.clientInformeLe && (
                                                <> · <span className="text-emerald-700" title="Le partenaire a déclaré que le client est informé de la transmission de ses pièces">
                                                  client informé ✓
                                                </span></>
                                              )}
                                            </div>
                                          </div>
                                        )}
                                        <div className="flex items-center gap-2">
                                          {isStale(d) && (
                                            <span className="text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200 px-2 py-0.5 rounded-full flex items-center gap-1">
                                              <Clock size={11} /> {staleHours(d)}h sans changement
                                            </span>
                                          )}
                                          <StatusBadge status={d.status} />
                                          <PaiementBadge dossier={d} />
                                        </div>
                                      </div>
                                      <Stepper status={d.status} />
                                      {d.status === "Bordereau émis" && (() => {
                                        const bAt = getBordereauAt(d);
                                        if (!bAt) return null;
                                        const daysSince = Math.floor((nowTick - bAt) / 86400000);
                                        const overdue = daysSince > PAIEMENT_ALERT_DAYS;
                                        return (
                                          <div className="flex flex-wrap gap-2 mt-3">
                                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full flex items-center gap-1 ${overdue ? "bg-red-50 text-red-700" : "bg-violet-50 text-violet-700"}`}>
                                              <Clock size={11} /> {overdue ? `⚠ Paiement en attente depuis ${daysSince}j` : `Bordereau émis depuis ${daysSince}j`}
                                            </span>
                                          </div>
                                        );
                                      })()}
                                      {d.status !== "KO" && d.status !== "Bordereau émis" && d.status !== "Payé" && (d.onHold ? (
                                        <div className="flex flex-wrap gap-2 mt-3">
                                          <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-gray-100 text-gray-500 flex items-center gap-1">
                                            ⏸ En attente externe (alertes suspendues)
                                          </span>
                                        </div>
                                      ) : (() => {
                                        const takenAt = getTakenChargeAt(d);
                                        const quoteAt = getQuoteIssuedAt(d);
                                        const chargeDeadline = d.createdAt + PRISE_EN_CHARGE_HOURS * 3600000;
                                        const devisDeadline = d.createdAt + DEVIS_HOURS * 3600000;
                                        const devisOnTime = quoteAt ? (quoteAt - d.createdAt) <= DEVIS_HOURS * 3600000 : null;
                                        return (
                                          <div className="flex flex-wrap gap-2 mt-3">
                                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full flex items-center gap-1 ${
                                              quoteAt ? (devisOnTime ? "bg-emerald-50 text-emerald-700" : "bg-orange-50 text-orange-700") : nowTick > devisDeadline ? "bg-red-50 text-red-700" : "bg-teal-50 fa-teal-text"
                                            }`}>
                                              <Clock size={11} />
                                              {quoteAt
                                                ? `Devis édité en ${formatDuration(quoteAt - d.createdAt)}${devisOnTime ? "" : " (hors délai 72h)"}`
                                                : nowTick > devisDeadline
                                                  ? `⚠ Devis en retard — reçu depuis ${formatDuration(nowTick - d.createdAt)}`
                                                  : `Reçu depuis ${formatDuration(nowTick - d.createdAt)} · devis sous ${formatDuration(devisDeadline - nowTick)}`}
                                            </span>
                                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                                              takenAt ? "bg-emerald-50 text-emerald-700" : nowTick > chargeDeadline ? "bg-red-50 text-red-700" : "bg-sky-50 text-sky-700"
                                            }`}>
                                              {takenAt ? `Pris en charge en ${formatDuration(takenAt - d.createdAt)}` : nowTick > chargeDeadline ? "⚠ Prise en charge en retard (>24h)" : `Prise en charge sous ${formatDuration(chargeDeadline - nowTick)}`}
                                            </span>
                                          </div>
                                        );
                                      })())}
                                      {renderDocUpload(d)}
                                      <div className="flex flex-wrap items-center gap-3 mt-4 pt-4 border-t border-gray-100">
                                        <select value={d.status} onChange={e => onUpdateStatus(d.id, e.target.value)}
                                          className="text-sm border border-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-teal-500">
                                          {ADMIN_STATUS_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
                                        </select>
                                        {d.status === "KO" ? (
                                          <div className="flex flex-wrap items-center gap-2">
                                            <span className="text-sm text-red-700 flex items-center gap-1"><X size={15} /> Clôturé sans suite</span>
                                            <select value={d.koReason || ""} onChange={e => onUpdateDossierClient(d.id, { koReason: e.target.value })}
                                              className="text-xs border border-red-200 bg-red-50 text-red-700 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-red-300">
                                              <option value="">Motif du KO…</option>
                                              {KO_REASONS.map(r => <option key={r} value={r}>{r}</option>)}
                                            </select>
                                            {d.koReason === "Autre" && (
                                              <input value={d.koReasonDetail || ""} onChange={e => onUpdateDossierClient(d.id, { koReasonDetail: e.target.value })}
                                                placeholder="Préciser…" className="text-xs border border-red-200 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-red-300" />
                                            )}
                                          </div>
                                        ) : d.status === "Payé" ? (
                                          <div className="flex flex-wrap items-center gap-2">
                                            <span className="text-sm text-green-700 flex items-center gap-1"><CheckCircle2 size={15} /> Dossier payé</span>
                                            <select value={d.paymentMethod || ""} onChange={e => onUpdateDossierClient(d.id, { paymentMethod: e.target.value })}
                                              className="text-xs border border-green-200 bg-green-50 text-green-700 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-green-300">
                                              <option value="">Mode de paiement…</option>
                                              {PAYMENT_METHODS.map(m => <option key={m} value={m}>{m}</option>)}
                                            </select>
                                            <input type="date" value={d.paymentDate || ""} onChange={e => onUpdateDossierClient(d.id, { paymentDate: e.target.value })}
                                              className="text-xs border border-green-200 rounded-lg px-2 py-1 focus:outline-none focus:ring-2 focus:ring-green-300" />
                                          </div>
                                        ) : d.bordereau ? (
                                          <span className="text-sm text-violet-700 flex items-center gap-1"><CheckCircle2 size={15} /> Bordereau déposé ({d.bordereau.name})</span>
                                        ) : (
                                          <>
                                            <button onClick={() => bordereauInputs.current[d.id]?.click()} disabled={busy}
                                              className="text-sm flex items-center gap-1.5 bg-violet-50 hover:bg-violet-100 text-violet-700 px-3 py-1.5 rounded-lg transition disabled:opacity-50">
                                              <Upload size={14} /> Déposer le bordereau
                                            </button>
                                            <input type="file" accept="application/pdf,image/*" className="hidden"
                                              ref={el => bordereauInputs.current[d.id] = el}
                                              onChange={e => e.target.files?.[0] && onUploadBordereau(d.id, e.target.files[0])} />
                                          </>
                                        )}
                                      </div>

                                      {["Souscrit", "Bordereau émis", "Payé"].includes(d.status) && (
                                        <>
                                          <EcheancierDossier dossier={d} onUpdate={onUpdateDossierClient} />
                                          <RecurrenceDossier dossier={d} onUpdate={onUpdateDossierClient} assureurs={listeAssureurs(data)} />
                                        </>
                                      )}

                                      <div className="flex items-center gap-3 mt-3 pt-3 border-t border-gray-100">
                                        <button onClick={() => simOpenId === d.id ? setSimOpenId(null) : openSim(d)}
                                          className="fa-tap text-xs gap-1 text-gray-500 hover:fa-teal-text transition">
                                          <Sparkles size={13} /> Simulation client {d.simulation?.crd != null && <span className="fa-bg-gold fa-navy rounded-full w-1.5 h-1.5" />}
                                        </button>
                                        <button onClick={() => notesOpenId === d.id ? setNotesOpenId(null) : openNotes(d)}
                                          className="fa-tap text-xs gap-1 text-gray-500 hover:fa-teal-text transition">
                                          <StickyNote size={13} /> Notes {d.notes && <span className="fa-bg-gold fa-navy rounded-full w-1.5 h-1.5" />}
                                        </button>
                                        <button onClick={() => messageOpenId === d.id ? setMessageOpenId(null) : openMessage(d)}
                                          className="fa-tap text-xs gap-1 text-gray-500 hover:fa-teal-text transition">
                                          💬 Message partenaire
                                          {d.partnerMessage && (
                                            d.partnerMessageRead
                                              ? <span className="text-emerald-600 text-[10px] font-semibold flex items-center gap-0.5"><CheckCircle2 size={10} /> Lu</span>
                                              : <span className="fa-bg-gold fa-navy text-[10px] font-semibold px-1.5 py-0.5 rounded-full">Non lu</span>
                                          )}
                                        </button>
                                        <button onClick={() => setHistoryOpenId(historyOpenId === d.id ? null : d.id)}
                                          className="fa-tap text-xs gap-1 text-gray-500 hover:fa-teal-text transition">
                                          <History size={13} /> Historique
                                        </button>
                                        {d.status !== "KO" && (
                                          <button onClick={() => toggleOnHold(d)}
                                            className={`fa-tap text-xs gap-1 transition ${d.onHold ? "text-gray-500 hover:text-emerald-600" : "text-gray-500 hover:text-orange-600"}`}>
                                            {d.onHold ? "▶ Reprendre" : "⏸ Attente externe"}
                                          </button>
                                        )}
                                        {d.status !== "KO" && (
                                          <button onClick={() => financeOpenId === d.id ? setFinanceOpenId(null) : openFinance(d)}
                                            className="fa-tap text-xs gap-1 text-gray-500 hover:fa-teal-text transition">
                                            💶 Rémunération {(d.caAmount || d.commissionAmount) && <span className="fa-bg-gold fa-navy rounded-full w-1.5 h-1.5" />}
                                          </button>
                                        )}
                                      </div>

                                      {messageOpenId === d.id && (
                                        <div className="mt-2 bg-teal-50 rounded-lg p-3">
                                          <label className="block text-xs fa-teal-text mb-1">Ce message sera visible par le partenaire dans son espace</label>
                                          <textarea value={messageDraft} onChange={e => setMessageDraft(e.target.value)}
                                            placeholder="Ex. Il manque le recto de la carte d'identité"
                                            rows={3} className="w-full border border-teal-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                          <div className="flex gap-2 mt-2">
                                            <button onClick={() => saveMessage(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Envoyer</button>
                                            <button onClick={() => setMessageOpenId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Fermer</button>
                                          </div>
                                        </div>
                                      )}

                                      {financeOpenId === d.id && (
                                        <div className="mt-2 bg-gray-50 rounded-lg p-3">
                                          <div className="grid sm:grid-cols-2 gap-3">
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1">CA généré (€) — interne</label>
                                              <input type="number" value={financeDraft.caAmount}
                                                onChange={e => setFinanceDraft(f => ({ ...f, caAmount: e.target.value }))}
                                                placeholder="0" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1 flex items-center justify-between">
                                                Rétrocession partenaire (€)
                                                {p.flatFee ? (
                                                  <button type="button"
                                                    onClick={() => setFinanceDraft(f => ({ ...f, commissionAmount: String(p.flatFee) }))}
                                                    className="fa-teal-text hover:underline font-normal normal-case">Forfait {p.flatFee}€</button>
                                                ) : (
                                                  <button type="button"
                                                    onClick={() => setFinanceDraft(f => ({ ...f, commissionAmount: f.caAmount ? (Number(f.caAmount) / 2).toString() : f.commissionAmount }))}
                                                    className="fa-teal-text hover:underline font-normal normal-case">50% auto</button>
                                                )}
                                              </label>
                                              <input type="number" value={financeDraft.commissionAmount}
                                                onChange={e => setFinanceDraft(f => ({ ...f, commissionAmount: e.target.value }))}
                                                placeholder="0" className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                          </div>
                                          {financeDraft.caAmount !== "" && financeDraft.commissionAmount !== "" && (() => {
                                            const ca = Number(financeDraft.caAmount) || 0;
                                            const commission = Number(financeDraft.commissionAmount) || 0;
                                            const caReel = ca - commission;
                                            const mandataireCut = caReel / 2;
                                            const margeNette = caReel - mandataireCut;
                                            return (
                                              <div className="mt-3 pt-3 border-t border-gray-200 space-y-1 text-xs text-gray-600">
                                                <div className="flex justify-between"><span>CA réel Frangola (après apporteur)</span><span className="font-semibold fa-navy">{fmtEuro(caReel)}</span></div>
                                                <div className="flex justify-between"><span>Part {p.commercial || "commercial"} (mandataire, 50%)</span><span className="font-semibold" style={{ color: COMMERCIAL_COLORS[p.commercial] }}>{fmtEuro(mandataireCut)}</span></div>
                                                <div className="flex justify-between"><span>Marge nette finale Frangola</span><span className="font-bold text-emerald-700">{fmtEuro(margeNette)}</span></div>
                                              </div>
                                            );
                                          })()}
                                          <div className="flex gap-2 mt-3">
                                            <button onClick={() => saveFinance(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                                            <button onClick={() => setFinanceOpenId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Fermer</button>
                                          </div>
                                        </div>
                                      )}

                                      {simOpenId === d.id && (
                                        <div className="mt-2 bg-white border border-gray-200 rounded-xl p-4">
                                          <div className="flex items-center justify-between mb-1 flex-wrap gap-2">
                                            <div className="flex items-center gap-2">
                                              <Sparkles size={15} className="fa-teal-text" />
                                              <span className="text-sm font-semibold fa-navy">Simulation client</span>
                                            </div>
                                            {(d.docs?.offre || d.docs?.tableau) && (
                                              <button onClick={async () => {
                                                setSimAnalyzing(d.id); setSimAnalyzeError(""); setSimAnalysisResult(null); setSimAutoReclassified(false);
                                                const { result, error } = await onAnalyzeDossierIA(d.id);
                                                setSimAnalyzing(null);
                                                if (error) { setSimAnalyzeError(error); return; }
                                                const misclassified =
                                                  (result.offreSlotDetecte === "tableau" && result.tableauSlotDetecte === "offre") ||
                                                  (result.offreSlotDetecte === "tableau" && !d.docs?.tableau) ||
                                                  (result.tableauSlotDetecte === "offre" && !d.docs?.offre);
                                                if (misclassified) {
                                                  await onSwapDocs(d.id, "offre", "tableau");
                                                  setSimAutoReclassified(true);
                                                }
                                                setSimAnalysisResult(result);
                                                if (!d.clientLastName && result.clientNom) {
  await onUpdateDossierClient(d.id, {
    clientLastName: result.clientNom,
    clientFirstName: result.clientPrenom || "",
  });
}
                                                setSimDraft({
                                                  crd: result.crdMontant ?? "", crdDate: result.crdDate ?? "",
                                                  assuranceRestante: result.assuranceRestanteTotal ?? "",
                                                  dureeRestanteMois: result.dureeRestanteMois ?? "",
                                                });
                                              }} disabled={simAnalyzing === d.id}
                                                className="flex items-center gap-1.5 text-xs font-medium fa-bg-teal disabled:opacity-50 px-3 py-1.5 rounded-lg transition">
                                                <Sparkles size={12} /> {simAnalyzing === d.id ? "Analyse en cours…" : "Analyser avec l'IA"}
                                              </button>
                                            )}
                                          </div>
                                          {simAnalyzing === d.id && (
                                            <p className="text-xs text-gray-400 mb-3">Peut prendre jusqu'à 2 minutes sur des documents volumineux — tu peux continuer à travailler en parallèle, ça tourne en arrière-plan.</p>
                                          )}
                                          {!d.docs?.tableau && (
                                            <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3">
                                              <AlertCircle size={14} className="text-amber-600 shrink-0 mt-0.5" />
                                              <span className="text-xs text-amber-800">Tableau d'amortissement manquant — le CRD, le coût d'assurance restant et la durée restante ne pourront pas être calculés tant qu'il n'est pas déposé.</span>
                                            </div>
                                          )}
                                          {simAnalyzeError && (
                                            <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-3">
                                              <AlertCircle size={14} className="text-red-600 shrink-0 mt-0.5" />
                                              <span className="text-xs text-red-700">{simAnalyzeError}</span>
                                            </div>
                                          )}
                                          {simAutoReclassified && (
                                            <div className="flex items-start gap-2 bg-emerald-50 border border-emerald-200 rounded-lg px-3 py-2 mb-3">
                                              <Check size={14} className="text-emerald-600 shrink-0 mt-0.5" />
                                              <span className="text-xs text-emerald-800">"Offre de prêt" et "Tableau d'amortissement" étaient mal classés — reclassés automatiquement.</span>
                                            </div>
                                          )}
                                          {simAnalysisResult?.noteExplicative && (
                                            <div className="flex items-start gap-2 bg-sky-50 border border-sky-200 rounded-lg px-3 py-2 mb-3">
                                              <Sparkles size={14} className="text-sky-600 shrink-0 mt-0.5" />
                                              <span className="text-xs text-sky-800"><strong>Note de l'analyse :</strong> {simAnalysisResult.noteExplicative}</span>
                                            </div>
                                          )}

                                          <div className="flex items-center justify-between text-xs mb-1 px-0.5">
                                            <span className="text-gray-500">Client identifié</span>
                                            <span className="fa-navy font-medium flex items-center gap-1"><Check size={12} className="text-emerald-600" />{clientName(d)}</span>
                                          </div>
                                          {d.hasCoEmprunteur && (
                                            <div className="flex items-center justify-between text-xs mb-3 px-0.5">
                                              <span className="text-gray-500">Co-emprunteur</span>
                                              <span className="fa-navy font-medium">{`${(d.coClientLastName || "").toUpperCase()} ${d.coClientFirstName || ""}`.trim()}</span>
                                            </div>
                                          )}

                                          {simAnalysisResult && simAnalysisResult.clientNom && (
                                            (simAnalysisResult.clientNom.toUpperCase() !== (d.clientLastName || "").toUpperCase()
                                              || (simAnalysisResult.clientPrenom || "").toLowerCase() !== (d.clientFirstName || "").toLowerCase()) && (
                                              <div className="flex items-center justify-between gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-2 flex-wrap">
                                                <span className="text-xs text-amber-800">
                                                  ⚠️ Le document indique <strong>{simAnalysisResult.clientNom.toUpperCase()} {simAnalysisResult.clientPrenom}</strong>, le partenaire avait saisi <strong>{clientName(d)}</strong>.
                                                </span>
                                                <button onClick={() => onUpdateDossierClient(d.id, { clientLastName: simAnalysisResult.clientNom, clientFirstName: simAnalysisResult.clientPrenom })}
                                                  className="text-xs font-semibold bg-amber-600 hover:bg-amber-700 text-white px-2.5 py-1 rounded-lg transition shrink-0">
                                                  Corriger
                                                </button>
                                              </div>
                                            )
                                          )}
                                          {simAnalysisResult && d.hasCoEmprunteur && simAnalysisResult.coEmprunteurNom && (
                                            (simAnalysisResult.coEmprunteurNom.toUpperCase() !== (d.coClientLastName || "").toUpperCase()
                                              || (simAnalysisResult.coEmprunteurPrenom || "").toLowerCase() !== (d.coClientFirstName || "").toLowerCase()) && (
                                              <div className="flex items-center justify-between gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3 flex-wrap">
                                                <span className="text-xs text-amber-800">
                                                  ⚠️ Le document indique un co-emprunteur <strong>{simAnalysisResult.coEmprunteurNom.toUpperCase()} {simAnalysisResult.coEmprunteurPrenom}</strong>, le partenaire avait saisi <strong>{`${(d.coClientLastName || "").toUpperCase()} ${d.coClientFirstName || ""}`.trim() || "aucun"}</strong>.
                                                </span>
                                                <button onClick={() => onUpdateDossierClient(d.id, { hasCoEmprunteur: true, coClientLastName: simAnalysisResult.coEmprunteurNom, coClientFirstName: simAnalysisResult.coEmprunteurPrenom })}
                                                  className="text-xs font-semibold bg-amber-600 hover:bg-amber-700 text-white px-2.5 py-1 rounded-lg transition shrink-0">
                                                  Corriger
                                                </button>
                                              </div>
                                            )
                                          )}
                                          {simAnalysisResult && !d.hasCoEmprunteur && simAnalysisResult.coEmprunteurNom && (
                                            <div className="flex items-center justify-between gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3 flex-wrap">
                                              <span className="text-xs text-amber-800">
                                                ⚠️ Les documents mentionnent un co-emprunteur (<strong>{simAnalysisResult.coEmprunteurNom.toUpperCase()} {simAnalysisResult.coEmprunteurPrenom}</strong>) non déclaré par le partenaire.
                                              </span>
                                              <button onClick={() => onUpdateDossierClient(d.id, { hasCoEmprunteur: true, coClientLastName: simAnalysisResult.coEmprunteurNom, coClientFirstName: simAnalysisResult.coEmprunteurPrenom })}
                                                className="text-xs font-semibold bg-amber-600 hover:bg-amber-700 text-white px-2.5 py-1 rounded-lg transition shrink-0">
                                                Ajouter
                                              </button>
                                            </div>
                                          )}

                                          <div className="grid sm:grid-cols-2 gap-2 mb-2">
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1">CRD à M+3 (€)</label>
                                              <input type="number" value={simDraft.crd} onChange={e => setSimDraft(s => ({ ...s, crd: e.target.value }))}
                                                placeholder="0" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1">Date de l'échéance M+3</label>
                                              <input type="date" value={simDraft.crdDate} onChange={e => setSimDraft(s => ({ ...s, crdDate: e.target.value }))}
                                                className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                          </div>

                                          <div className="grid sm:grid-cols-2 gap-2 mb-2">
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1">Coût assurance restant (€)</label>
                                              <input type="number" value={simDraft.assuranceRestante} onChange={e => setSimDraft(s => ({ ...s, assuranceRestante: e.target.value }))}
                                                placeholder="0" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                            <div>
                                              <label className="block text-xs text-gray-500 mb-1">Durée restante (mois)</label>
                                              <input type="number" value={simDraft.dureeRestanteMois} onChange={e => setSimDraft(s => ({ ...s, dureeRestanteMois: e.target.value }))}
                                                placeholder="0" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                            </div>
                                          </div>

                                    {simAnalysisResult?.syntheseCrd && (
  <div className="flex items-start gap-2 bg-sky-50 border border-sky-200 rounded-lg px-3 py-2 mb-2">
    <Sparkles size={14} className="text-sky-600 shrink-0 mt-0.5" />
    <span className="text-xs text-sky-800"><strong>Comment ce CRD a été trouvé :</strong> {simAnalysisResult.syntheseCrd}</span>
  </div>
)}
                                          {simDraft.assuranceRestante && simDraft.dureeRestanteMois && Number(simDraft.dureeRestanteMois) > 0 && (
                                            <div className="fa-bg-offwhite rounded-lg px-3 py-2 mb-3 flex items-center justify-between">
                                              <span className="text-xs text-gray-500">Mensualité moyenne (linéaire)</span>
                                              <span className="text-sm font-bold fa-teal-text">{fmtEuroPrecis(Number(simDraft.assuranceRestante) / Number(simDraft.dureeRestanteMois))}</span>
                                            </div>
                                          )}

                                          <div className="flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-3">
                                            <AlertCircle size={14} className="text-amber-600 shrink-0 mt-0.5" />
                                            <span className="text-xs text-amber-800">Moyenne théorique linéaire — le vrai contrat peut être dégressif (au capital restant dû), avec une mensualité réelle différente.</span>
                                          </div>

<div className="mb-3">
  <label className="block text-xs text-gray-500 mb-1">Coût assurance restant avec Frangola — devis (€)</label>
  <input type="number" value={simDraft.devisAssurance}
    onChange={e => setSimDraft(s => ({ ...s, devisAssurance: e.target.value }))}
    placeholder="0" className="border border-gray-300 rounded-lg px-2.5 py-1.5 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
</div>
                                          {(() => {
  const actuel = Number(simDraft.assuranceRestante) || 0;
  const devis = Number(simDraft.devisAssurance) || 0;
  const mois = Number(simDraft.dureeRestanteMois) || 0;
  if (!actuel || !devis || !mois) return null;
  const gainTotal = actuel - devis;
  const gainMensuel = gainTotal / mois;
  const pct = Math.round((gainTotal / actuel) * 100);
  const favorable = gainTotal > 0;
  return (
    <div className={`rounded-lg p-3 mb-3 ${favorable ? "fa-bg-gold" : "bg-red-50 border border-red-200"}`}>
      <div className="flex items-center justify-between mb-1.5">
        <span className={`text-xs font-semibold ${favorable ? "fa-navy" : "text-red-700"}`}>
          {favorable ? "Économie pour le client" : "Le devis est plus cher que le contrat actuel"}
        </span>
        <span className={`text-xs font-bold ${favorable ? "fa-navy" : "text-red-700"}`}>
          {favorable ? `−${pct}%` : `+${Math.abs(pct)}%`}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-xs fa-navy">Gain total sur {mois} mois</span>
        <span className="text-lg font-bold fa-navy">{fmtEuro(Math.abs(gainTotal))}</span>
      </div>
      <div className="flex items-center justify-between">
        <span className="text-xs fa-navy">Gain par mois</span>
        <span className="text-sm font-bold fa-navy">{fmtEuroPrecis(Math.abs(gainMensuel))}</span>
      </div>
      <div className="flex items-center justify-between mt-1.5 pt-1.5 border-t border-black/10">
        <span className="text-[11px] text-teal-900/70">Mensualité moyenne Frangola</span>
        <span className="text-xs font-semibold fa-navy">{fmtEuroPrecis(devis / mois)}</span>
      </div>
            {favorable && (
        <div className="flex items-center justify-between mt-1.5 pt-1.5 border-t border-black/10">
          <span className="text-[11px] fa-navy font-semibold">Honoraires Frangola (10% du gain)</span>
          <span className="text-sm font-bold fa-navy">{fmtEuroPrecis(gainTotal * 0.1)}</span>
        </div>
      )}
    </div>
  );
})()}
                                          <div className="flex gap-2">
                                            <button onClick={() => saveSim(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                                            <button onClick={() => setSimOpenId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Fermer</button>
                                          </div>
                                        </div>
                                      )}

                                      {notesOpenId === d.id && (
                                        <div className="mt-2 bg-gray-50 rounded-lg p-3">
                                          <textarea value={notesDraft} onChange={e => setNotesDraft(e.target.value)}
                                            placeholder="Note interne — visible uniquement par toi"
                                            rows={3} className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                                          <div className="flex gap-2 mt-2">
                                            <button onClick={() => saveNotes(d.id)} className="fa-bg-teal text-xs font-medium px-3 py-1.5 rounded-lg transition">Enregistrer</button>
                                            <button onClick={() => setNotesOpenId(null)} className="text-xs text-gray-500 hover:text-gray-700 px-2">Fermer</button>
                                          </div>
                                        </div>
                                      )}

                                      {historyOpenId === d.id && (
                                        <div className="mt-2 bg-gray-50 rounded-lg p-3 space-y-1.5">
                                          {(d.history || []).slice().reverse().map((h, i) => (
                                            <div key={i} className="text-xs text-gray-500 flex items-center gap-2">
                                              <span className="w-1.5 h-1.5 rounded-full fa-bg-teal shrink-0" />
                                              <span className="fa-navy font-medium">{h.status}</span> — {fmtDate(h.at)} {new Date(h.at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}
                                            </div>
                                          ))}
                                          {(!d.history || d.history.length === 0) && <div className="text-xs text-gray-400">Pas d'historique disponible pour ce dossier.</div>}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              });
            })()}
          </div>
        )}

        {tab === "partenaires" && (
          <div>
                        <RegistreParrainages data={data} onTraiter={onTraiterParrainage} />

            <ContratTypePanel contrat={data.settings?.contratType} partners={data.partners}
              onUpload={onUploadContratType} canEdit={isFullAdmin} busy={busy} />


            {(() => {
              // Les fiches créées depuis une déclaration de parrainage arrivent
              // incomplètes et sans département : sans ce raccourci elles se
              // perdent dans un dossier replié.
              const aCompleter = data.partners.filter(p => !p.deleted && !p.email);
              if (aCompleter.length === 0) return null;
              return (
                <div className="bg-white border border-amber-200 rounded-2xl p-5 mb-4">
                  <div className="font-display font-semibold fa-navy mb-1">
                    ✎ Fiches à compléter
                    <span className="ml-2 fa-bg-gold fa-navy text-xs font-bold px-2 py-0.5 rounded-full">{aCompleter.length}</span>
                  </div>
                  <p className="text-sm text-gray-500 mb-4">
                    Ces partenaires n'ont pas encore d'adresse email : ils ne peuvent pas se connecter tant qu'elle manque.
                  </p>
                  <div className="space-y-2">
                    {aCompleter.map(p => (
                      <div key={p.id} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
                        <div>
                          <div className="text-sm fa-navy font-bold">
                            {nomPartenaire(p)}
                            {p.issuDuParrainage && <span className="ml-2 text-xs text-teal-700">issu du parrainage</span>}
                          </div>
                          <div className="text-xs text-gray-400">
                            {afficheReseau(p.company) || "réseau non précisé"}
                            {p.telephone && ` · ${p.telephone}`}
                            {p.siret && ` · SIRET ${p.siret}`}
                            {p.parrainId && nomParrain(p.parrainId) && ` · parrainé par ${nomParrain(p.parrainId)}`}
                          </div>
                        </div>
                        <button onClick={() => {
                          const com = p.commercial || "Sans commercial";
                          const dep = p.departement || "Sans département";
                          setOuverts(prev => new Set([...prev, "pcom:" + com, "pdep:" + com + ":" + dep]));
                          startEdit(p);
                        }} className="text-xs font-semibold fa-navy fa-bg-gold px-3 py-1.5 rounded-lg transition">
                          Compléter la fiche
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
            <div className="flex items-center justify-between mb-6 flex-wrap gap-2">
              <h2 className="font-display text-lg font-semibold fa-navy">Partenaires</h2>
              <div className="flex items-center gap-2">
                <button onClick={() => exportPartnersCsv(data.partners.filter(p => !p.deleted))}
                  className="text-sm font-medium bg-white border border-gray-200 hover:border-teal-300 fa-teal-text px-4 py-2 rounded-full transition">
                  Exporter CSV
                </button>
                <button onClick={() => setShowAddPartnerForm(v => !v)}
                  className="flex items-center gap-1.5 fa-bg-gold font-medium text-sm px-4 py-2 rounded-full transition">
                  <Plus size={16} /> Ajouter un partenaire
                </button>
              </div>
            </div>

            {showAddPartnerForm && (
            <div className="bg-white border border-gray-200 rounded-2xl p-6 mb-6 shadow-sm">
              <h3 className="font-display font-semibold fa-navy mb-4 flex items-center gap-2"><Landmark size={17} className="fa-teal-text" /> Ajouter un partenaire</h3>
              <div className="grid sm:grid-cols-2 gap-4 mb-4">
                <input value={newPartnerName} onChange={e => setNewPartnerName(e.target.value)} placeholder="Nom du partenaire"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <input value={newPartnerFirstName} onChange={e => setNewPartnerFirstName(e.target.value)} placeholder="Prénom"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <div className="flex items-center gap-2">
                  <input value={newPartnerCompany} onChange={e => setNewPartnerCompany(e.target.value)} placeholder="Agence / société (réseau)"
                    className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  {newPartnerCompany.trim() && (
                    <div className="flex items-center gap-1 shrink-0">
                      <label className="fa-tap flex items-center gap-1 text-xs border border-gray-300 rounded-lg px-2 py-1.5 cursor-pointer bg-white hover:border-teal-400 transition" title="Logo du réseau">
                        {reseauLogoFor(newPartnerCompany) ? (
                          <img src={reseauLogoFor(newPartnerCompany).data} alt="" className="w-9 h-9 rounded object-contain" />
                        ) : (
                          <ImagePlus size={18} className="text-gray-400" />
                        )}
                        <input type="file" accept="image/*" className="hidden"
                          onChange={e => e.target.files?.[0] && onUploadReseauLogo(newPartnerCompany, e.target.files[0])} />
                      </label>
                      {reseauLogoFor(newPartnerCompany) && (
                        <button type="button" onClick={() => onRemoveReseauLogo(newPartnerCompany)}
                          className="fa-tap text-gray-400 hover:text-red-600" title="Retirer ce logo">
                          <X size={16} />
                        </button>
                      )}
                    </div>
                  )}
                </div>
                <input value={newPartnerPostalCode} onChange={e => setNewPartnerPostalCode(e.target.value.replace(/\D/g, "").slice(0, 5))} placeholder="Code postal" inputMode="numeric"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <input value={newPartnerVille} onChange={e => setNewPartnerVille(e.target.value)} placeholder="Ville (auto)"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <select value={newPartnerDepartement} onChange={e => setNewPartnerDepartement(e.target.value)}
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500">
                  <option value="">Département</option>
                  {DEPARTEMENTS.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
                <input value={newPartnerEmail} onChange={e => setNewPartnerEmail(e.target.value)} type="email" placeholder="Adresse email *"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <input value={newPartnerTelephone} onChange={e => setNewPartnerTelephone(e.target.value)} type="tel" placeholder="Téléphone"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                {/* Un apporteur hors immobilier est un particulier : il n'a pas de SIRET. */}
                {newPartnerFlatFee === "" && (
                  <input value={newPartnerSiret} onChange={e => setNewPartnerSiret(e.target.value.replace(/\D/g, "").slice(0, 14))} inputMode="numeric" placeholder="N° SIRET (14 chiffres)"
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                )}
                <select value={newPartnerCommercial} onChange={e => setNewPartnerCommercial(e.target.value)}
                  style={{ backgroundColor: COMMERCIAL_COLORS[newPartnerCommercial], color: "#fff" }}
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-teal-500">
                  {COMMERCIAUX.map(c => <option key={c} value={c} style={{ backgroundColor: COMMERCIAL_COLORS[c], color: "#fff" }}>{commercialLabel(c)}</option>)}
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-600 mb-4">
                <input type="checkbox" checked={newPartnerFlatFee !== ""}
                  onChange={e => { setNewPartnerFlatFee(e.target.checked ? "100" : ""); if (e.target.checked) setNewPartnerSiret(""); }}
                  className="rounded border-gray-300" />
                Hors immobilier (rémunéré au forfait fixe, pas en % du CA)
              </label>
              {newPartnerFlatFee !== "" && (
                <div className="mb-4 max-w-xs">
                  <label className="block text-xs text-gray-500 mb-1">Forfait par contrat (€)</label>
                  <input type="number" value={newPartnerFlatFee} onChange={e => setNewPartnerFlatFee(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                </div>
              )}
              <div className="flex gap-2 items-start flex-wrap">
                <button onClick={handleAddPartner} disabled={!newPartnerName.trim() || !newPartnerEmail.trim()}
                  className="fa-bg-teal disabled:opacity-50 text-white text-sm font-medium px-5 py-2 rounded-lg transition">
                  Créer l'accès
                </button>
                <button onClick={() => setShowAddPartnerForm(false)} className="text-sm text-gray-500 hover:text-gray-700 px-3 py-2">Annuler</button>
              </div>
              {createdPartner && (
                <div className="mt-4 text-sm bg-teal-50 border border-teal-200 rounded-lg px-4 py-3">
                  <strong>{createdPartner.name}</strong> peut se connecter avec son email (<strong>{createdPartner.email || "non renseigné"}</strong>) — il créera son mot de passe à sa 1ère connexion.
                </div>
              )}
            </div>
            )}

            <div className="space-y-3">
                           <div className="relative mb-2">
                <input value={partnerSearch} onChange={e => setPartnerSearch(e.target.value)}
                  placeholder="Rechercher un partenaire, une agence, une ville…"
                  className="w-full border border-gray-300 rounded-lg pl-9 pr-8 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">⌕</span>
                {partnerSearch && (
                  <button onClick={() => setPartnerSearch("")}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-red-600 transition">
                    <X size={15} />
                  </button>
                )}
              </div>
              {data.partners.filter(p => !p.deleted).length === 0 && <div className="text-center text-gray-400 text-sm py-10">Aucun partenaire pour l'instant.</div>}
                         {(() => {
                const q = partnerSearch.trim().toLowerCase();
                const filtreActif = q.length > 0;
                const cles = (p) => [p.commercial || "Sans commercial", p.departement || "Sans département"];
                const vivants = data.partners.filter(p => !p.deleted).filter(p =>
                  !filtreActif || `${p.firstName || ""} ${p.name || ""} ${p.company || ""} ${p.ville || ""} ${p.email || ""}`.toLowerCase().includes(q)
                );
                const tri = vivants.slice().sort((a, b) => {
                  const [ca, da] = cles(a), [cb, db] = cles(b);
                  if (ca !== cb) return ca.localeCompare(cb);
                  if (da !== db) return da.localeCompare(db, undefined, { numeric: true });
                  return (a.name || "").localeCompare(b.name || "");
                });
                const lignes = [];
                let comCourant = null, depCourant = null;
                for (const p of tri) {
                  const [com, dep] = cles(p);
                  const cleCom = "pcom:" + com;
                  const cleDep = "pdep:" + com + ":" + dep;
                  if (com !== comCourant) {
                    comCourant = com; depCourant = null;
                    lignes.push({ __header: "commercial", id: cleCom, nom: com, nb: tri.filter(x => cles(x)[0] === com).length });
                  }
                  if (!filtreActif && estPlie(cleCom)) continue;
                  if (dep !== depCourant) {
                    depCourant = dep;
                    lignes.push({ __header: "departement", id: cleDep, nom: dep, nb: tri.filter(x => cles(x)[0] === com && cles(x)[1] === dep).length });
                  }
                  if (!filtreActif && estPlie(cleDep)) continue;
                  lignes.push(p);
                }
                return lignes;
              })().map(p => p.__header ? (
                p.__header === "commercial" ? (
                  <button key={p.id} onClick={() => toggleFolder(p.id)}
                    className="w-full flex items-center justify-between px-5 py-3.5 rounded-xl fa-bg-pink hover:brightness-95 transition">
                    <div className="flex items-center gap-3">
                      {estPlie(p.id) ? <Folder className="fa-navy" size={20} /> : <FolderOpen className="fa-navy" size={20} />}
                      <span className="font-display font-bold fa-navy">{commercialLabel(p.nom)}</span>
                      <span className="text-xs text-teal-900/70">{p.nb} partenaire{p.nb > 1 ? "s" : ""}</span>
                    </div>
                    <ChevronDown size={16} className={`fa-navy transition-transform ${estPlie(p.id) ? "" : "rotate-180"}`} />
                  </button>
                ) : (
                  <button key={p.id} onClick={() => toggleFolder(p.id)}
                    className="w-full flex items-center justify-between pl-10 pr-5 py-2.5 rounded-lg bg-white border border-gray-200 hover:bg-gray-50 transition">
                    <div className="flex items-center gap-2">
                      {estPlie(p.id) ? <Folder className="fa-teal-text" size={16} /> : <FolderOpen className="fa-teal-text" size={16} />}
                      <span className="text-sm font-semibold fa-navy">{p.nom === "Sans département" ? p.nom : `Département ${p.nom}`}</span>
                      <span className="text-xs text-gray-400">{p.nb}</span>
                    </div>
                    <ChevronDown size={14} className={`text-gray-400 transition-transform ${estPlie(p.id) ? "" : "rotate-180"}`} />
                  </button>
                )
              ) : (
                <div key={p.id} className={`bg-white border rounded-xl px-5 py-4 ${p.active === false ? "border-gray-200 opacity-60" : "border-gray-200"}`}>
                  {editingId === p.id ? (
                    <div>
                      <div className="grid sm:grid-cols-2 gap-3 mb-3">
                        <input value={editForm.name} onChange={e => setEditForm(f => ({ ...f, name: e.target.value }))} placeholder="Nom"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <input value={editForm.firstName} onChange={e => setEditForm(f => ({ ...f, firstName: e.target.value }))} placeholder="Prénom"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <div className="flex items-center gap-2">
                          <input value={editForm.company} onChange={e => setEditForm(f => ({ ...f, company: e.target.value }))} placeholder="Agence / société (réseau)"
                            className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                          {editForm.company.trim() && (
                            <div className="flex items-center gap-1 shrink-0">
                              <label className="fa-tap flex items-center gap-1 text-xs border border-gray-300 rounded-lg px-2 py-1.5 cursor-pointer bg-white hover:border-teal-400 transition" title="Logo du réseau">
                                {reseauLogoFor(editForm.company) ? (
                                  <img src={reseauLogoFor(editForm.company).data} alt="" className="w-9 h-9 rounded object-contain" />
                                ) : (
                                  <ImagePlus size={18} className="text-gray-400" />
                                )}
                                <input type="file" accept="image/*" className="hidden"
                                  onChange={e => e.target.files?.[0] && onUploadReseauLogo(editForm.company, e.target.files[0])} />
                              </label>
                              {reseauLogoFor(editForm.company) && (
                                <button type="button" onClick={() => onRemoveReseauLogo(editForm.company)}
                                  className="fa-tap text-gray-400 hover:text-red-600" title="Retirer ce logo">
                                  <X size={16} />
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                        <input value={editForm.postalCode} onChange={e => setEditForm(f => ({ ...f, postalCode: e.target.value.replace(/\D/g, "").slice(0, 5) }))} placeholder="Code postal" inputMode="numeric"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <input value={editForm.ville} onChange={e => setEditForm(f => ({ ...f, ville: e.target.value }))} placeholder="Ville (auto)"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <select value={editForm.departement} onChange={e => setEditForm(f => ({ ...f, departement: e.target.value }))}
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500">
                          <option value="">Département</option>
                          {DEPARTEMENTS.map(d => <option key={d} value={d}>{d}</option>)}
                        </select>
                        <input value={editForm.email} onChange={e => setEditForm(f => ({ ...f, email: e.target.value }))} type="email" placeholder="Adresse email"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <input value={editForm.telephone} onChange={e => setEditForm(f => ({ ...f, telephone: e.target.value }))} type="tel" placeholder="Téléphone"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        {/* Idem en modification : cocher « hors immobilier » retire le SIRET. */}
                        {editForm.flatFee === "" && (
                          <input value={editForm.siret} onChange={e => setEditForm(f => ({ ...f, siret: e.target.value.replace(/\D/g, "").slice(0, 14) }))} inputMode="numeric" placeholder="N° SIRET (14 chiffres)"
                            className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        )}
                        <select value={editForm.commercial} onChange={e => setEditForm(f => ({ ...f, commercial: e.target.value }))}
                          style={{ backgroundColor: COMMERCIAL_COLORS[editForm.commercial], color: "#fff" }}
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-teal-500">
                          {COMMERCIAUX.map(c => <option key={c} value={c} style={{ backgroundColor: COMMERCIAL_COLORS[c], color: "#fff" }}>{commercialLabel(c)}</option>)}
                        </select>
                        <select value={editForm.parrainId} onChange={e => setEditForm(f => ({ ...f, parrainId: e.target.value }))}
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500">
                          <option value="">Parrainé par… (aucun)</option>
                          {data.partners.filter(x => !x.deleted && x.id !== p.id).map(x => (
                            <option key={x.id} value={x.id}>
                              {nomPartenaire(x)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <label className="flex items-center gap-2 text-sm text-gray-600 mb-3">
                        <input type="checkbox" checked={editForm.flatFee !== ""}
                          onChange={e => setEditForm(f => ({ ...f, flatFee: e.target.checked ? "100" : "", siret: e.target.checked ? "" : f.siret }))}
                          className="rounded border-gray-300" />
                        Hors immobilier (rémunéré au forfait fixe, pas en % du CA)
                      </label>
                      {editForm.flatFee !== "" && (
                        <div className="mb-3 max-w-xs">
                          <label className="block text-xs text-gray-500 mb-1">Forfait par contrat (€)</label>
                          <input type="number" value={editForm.flatFee} onChange={e => setEditForm(f => ({ ...f, flatFee: e.target.value }))}
                            className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        </div>
                      )}
                      <div className="flex gap-2">
                        <button onClick={() => saveEdit(p.id)} className="fa-bg-teal text-sm font-medium px-4 py-1.5 rounded-lg transition">Enregistrer</button>
                        <button onClick={() => setEditingId(null)} className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div>
                        <div className="font-medium fa-navy flex items-center gap-2">
                          <span className="font-bold">{nomPartenaire(p)}</span>
                          {p.flatFee != null && <span className="text-xs font-semibold bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 rounded-full">Forfait {p.flatFee}€</span>}
                          {filleulsDe(p.id).length > 0 && (() => {
                            const n = filleulsDe(p.id).length;
                            return (
                              <button onClick={() => toggleFilleuls(p.id)}
                                title="Voir les filleuls"
                                className="text-xs font-semibold fa-bg-gold fa-navy px-2 py-0.5 rounded-full hover:brightness-95 transition inline-flex items-center gap-1">
                                🤝 {n} parrainage{n > 1 ? "s" : ""}
                                <ChevronDown size={12} className={filleulsOuverts.has(p.id) ? "rotate-180 transition" : "transition"} />
                              </button>
                            );
                          })()}
                          {!p.email && (
                            <span className="text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 px-2 py-0.5 rounded-full">
                              ✎ Fiche à compléter
                            </span>
                          )}
                          {p.parrainId && nomParrain(p.parrainId) && (
                            <span className="text-xs font-semibold bg-teal-50 text-teal-700 border border-teal-200 px-2 py-0.5 rounded-full">
                              🤝 Filleul de {nomParrain(p.parrainId)}
                            </span>
                          )}
                          {p.active === false && <span className="text-xs font-semibold bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">Inactif</span>}
                          {p.active !== false && daysSinceLastDossier(p) > INACTIVITY_DAYS && (
                            <span className="text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200 px-2 py-0.5 rounded-full">
                              ⚠ Sans activité depuis {daysSinceLastDossier(p)}j
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-gray-400 flex items-center flex-wrap gap-1.5">
                          {afficheReseau(p.company) || "—"} {!MODE_DISCRET && p.ville && `· ${p.ville}`} {!MODE_DISCRET && p.departement && `(dép. ${p.departement})`} · Commercial : <span className="text-white text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[p.commercial] || "#999" }}>{commercialLabel(p.commercial) || "—"}</span> · depuis le {fmtDate(p.createdAt)}
                          {filleulsOuverts.has(p.id) && filleulsDe(p.id).length > 0 && (() => {
                            const bilan = bilanParrainage(p.id);
                            return (
                              <div className="w-full mt-2 bg-amber-50 border border-amber-200 rounded-lg p-3">
                                <div className="text-xs font-semibold fa-navy mb-2">
                                  Filleuls de {nomPartenaire(p)}
                                </div>
                                <div className="space-y-1.5">
                                  {filleulsDe(p.id).map(f => {
                                    const ca = caGenerePar(f.id);
                                    return (
                                      <div key={f.id} className="flex items-baseline justify-between gap-3 flex-wrap text-xs">
                                        <span className="fa-navy font-medium">
                                          {nomPartenaire(f)}
                                          {f.company && <span className="text-gray-500 font-normal"> · {afficheReseau(f.company)}</span>}
                                          {f.active === false && <span className="text-gray-400 font-normal"> · inactif</span>}
                                        </span>
                                        <span className="text-gray-500">
                                          depuis le {fmtDate(f.createdAt)} · C.A. généré <strong className="fa-navy">{fmtEuroPrecis(ca)}</strong>
                                        </span>
                                      </div>
                                    );
                                  })}
                                </div>
                                <div className="mt-2 pt-2 border-t border-amber-200 text-xs fa-navy">
                                  Rétrocession due à {p.firstName || up(p.name)} : <strong>{fmtEuroPrecis(bilan.gainTotal)}</strong>
                                  <span className="text-gray-500"> (10 % de {fmtEuro(bilan.caTotal)})</span>
                                </div>
                              </div>
                            );
                          })()}
                        </div>
                        {p.email && <div className="text-xs text-gray-400">{p.email}</div>}
                      </div>
                      <div className="flex items-center gap-2">
                        <button onClick={() => { setViewingPartnerId(viewingPartnerId === p.id ? null : p.id); setViewingPartnerTab("analytique"); }}
                          className="text-sm fa-navy fa-bg-gold px-3 py-1.5 rounded-lg font-medium transition">
                          {viewingPartnerId === p.id ? "Fermer" : "Voir"}
                        </button>
                        <button onClick={() => onApercuPartner(p.id)}
                          title="Voir son espace exactement comme lui le voit — en lecture seule"
                          className="fa-tap text-sm fa-teal-text hover:underline px-2">👁 Son espace</button>
                        <button onClick={() => startEdit(p)} className="fa-tap text-sm fa-teal-text hover:underline px-2">Modifier</button>
                        <button onClick={() => toggleActive(p)}
                          className={`text-xs font-semibold px-3 py-1.5 rounded-full transition ${p.active === false ? "bg-emerald-50 text-emerald-700 hover:bg-emerald-100" : "bg-red-50 text-red-700 hover:bg-red-100"}`}>
                          {p.active === false ? "Réactiver" : "Désactiver"}
                        </button>
                        <span className="text-xs fa-bg-offwhite border border-gray-200 px-3 py-1.5 rounded-lg text-gray-500">
                          {p.email || "email manquant"} · {p.lastLoginAt ? `dernière connexion ${fmtDate(p.lastLoginAt)}` : "jamais connecté"}
                        </span>
                        <BlocAcces cible={p} expediteur={viewerLabel} telephone={viewerTelephone} genre="partenaire" onReinitialiser={() => reinitialiserAcces("partner", p.id)} />
                        {data.settings?.contratType && (
                          p.contratAccepteLe ? (
                            <span className="text-xs bg-emerald-50 border border-emerald-200 text-emerald-700 px-2.5 py-1 rounded-lg">
                              Contrat accepté le {fmtDate(p.contratAccepteLe)}
                            </span>
                          ) : (
                            <span className="text-xs bg-red-50 border border-red-200 text-red-700 px-2.5 py-1 rounded-lg">
                              Contrat non accepté
                            </span>
                          )
                        )}
                        {confirmDeleteId === p.id ? (
                          <span className="flex items-center gap-1.5 text-xs">
                            <span className="text-red-700">Confirmer ?</span>
                            <button onClick={() => confirmDelete(p.id)} className="font-semibold text-red-700 hover:underline">Oui</button>
                            <button onClick={() => setConfirmDeleteId(null)} className="text-gray-500 hover:underline">Non</button>
                          </span>
                        ) : (
                          <button onClick={() => setConfirmDeleteId(p.id)} className="fa-tap text-xs text-gray-400 hover:text-red-600 px-2">Supprimer</button>
                        )}
                      </div>
                    </div>
                  )}

                  {viewingPartnerId === p.id && (() => {
                    const pDossiers = data.dossiers.filter(d => d.partnerId === p.id);
                    const won = pDossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));
                    const paid = pDossiers.filter(d => d.status === "Payé");
                    const ko = pDossiers.filter(d => d.status === "KO");
                    const totalCaP = paid.reduce((s, d) => s + (d.caAmount || 0), 0);
                    const totalCommP = paid.reduce((s, d) => s + (d.commissionAmount || 0), 0);
                    const transformRateP = (pDossiers.length - ko.length) > 0 ? Math.round((paid.length / (pDossiers.length - ko.length)) * 100) : 0;
                    return (
                      <div className="mt-4 pt-4 border-t border-gray-100">
                        <div className="flex gap-1.5 mb-4">
                          <button onClick={() => setViewingPartnerTab("analytique")}
                            className={`text-xs font-medium px-3 py-1.5 rounded-full transition ${viewingPartnerTab === "analytique" ? "fa-bg-teal" : "bg-gray-100 text-gray-600"}`}>
                            Analytique
                          </button>
                          <button onClick={() => setViewingPartnerTab("dossiers")}
                            className={`text-xs font-medium px-3 py-1.5 rounded-full transition ${viewingPartnerTab === "dossiers" ? "fa-bg-teal" : "bg-gray-100 text-gray-600"}`}>
                            Ses dossiers ({pDossiers.length})
                          </button>
                          <button onClick={() => setViewingPartnerTab("contrat")}
                            className={`text-xs font-medium px-3 py-1.5 rounded-full transition ${viewingPartnerTab === "contrat" ? "fa-bg-teal" : "bg-gray-100 text-gray-600"}`}>
                            Contrat &amp; RIB
                          </button>
                        </div>

                        {viewingPartnerTab === "analytique" && (
                          <div className="grid sm:grid-cols-3 gap-3">
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Dossiers déposés</div><div className="font-display text-xl font-bold fa-navy">{pDossiers.length}</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Dossiers gagnés</div><div className="font-display text-xl font-bold text-emerald-600">{won.length}</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Dossiers payés</div><div className="font-display text-xl font-bold text-green-600">{paid.length}</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Taux de transformation</div><div className="font-display text-xl font-bold fa-teal-text">{transformRateP}%</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Dossiers KO</div><div className="font-display text-xl font-bold text-red-500">{ko.length}</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">CA généré (payé)</div><div className="font-display text-xl font-bold fa-navy">{fmtEuro(totalCaP)}</div></div>
                            <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Dernière connexion</div><div className="font-display text-sm font-bold fa-navy">{p.lastLoginAt ? fmtDate(p.lastLoginAt) : "Jamais connecté"}</div></div>
                            {(() => {
                              // La valeur réelle d'un partenaire, ce n'est pas
                              // seulement l'honoraire : c'est la récurrence qu'il
                              // nous apporte, et qu'il ne voit jamais.
                              const recMoisP = pDossiers.filter(contratEnCours).reduce((sm, x) => sm + recurrenceMensuelle(x), 0);
                              const recCumulP = pDossiers.reduce((sm, x) => sm + recurrenceCumulee(x), 0);
                              return (
                                <div className="bg-violet-50 border border-violet-200 rounded-xl p-4 sm:col-span-2">
                                  <div className="text-xs text-gray-500">Récurrence générée par ce partenaire</div>
                                  <div className="font-display text-xl font-bold text-violet-700">{fmtEuroPrecis(recCumulP)}</div>
                                  <div className="text-[11px] text-gray-400 mt-0.5">
                                    {fmtEuroPrecis(recMoisP)}/mois en cours · {fmtEuro(recMoisP * 12)} par an — non rétrocédé
                                  </div>
                                </div>
                              );
                            })()}
                            <div className="fa-bg-gold rounded-xl p-4"><div className="text-xs text-teal-900/70">Rétrocession perçue par ce partenaire</div><div className="font-display text-xl font-bold fa-navy">{fmtEuroPrecis(totalCommP)}</div></div>
                          </div>
                        )}

                        {viewingPartnerTab === "dossiers" && (
                          <div className="space-y-2">
                            {pDossiers.length === 0 && <div className="text-sm text-gray-400">Aucun dossier pour ce partenaire.</div>}
                            {pDossiers.sort((a, b) => b.createdAt - a.createdAt).map(d => (
                              <div key={d.id} className="bg-white border border-gray-200 rounded-lg px-3 py-2">
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  {/* Ouvrir le dossier depuis la fiche du partenaire évite
                                      d'aller le rechercher dans l'onglet Dossiers. */}
                                  <button
                                    onClick={() => {
                                      // Même format que le filtre de recherche, sinon rien ne remonte.
                                      setDossierFilter("tous");
                                      setDossierSearch(`${d.clientFirstName || ""} ${d.clientLastName || ""}`.trim());
                                      setViewingPartnerId(null);
                                      setTab("dossiers");
                                    }}
                                    title="Ouvrir ce dossier"
                                    className="text-sm fa-navy font-bold hover:fa-teal-text hover:underline transition text-left">
                                    {clientName(d)}
                                  </button>
                                  <div className="flex items-center gap-2 text-xs text-gray-500">
                                    <button onClick={() => setAdminExtraDocOpenId(adminExtraDocOpenId === d.id ? null : d.id)}
                                      className="fa-tap text-gray-400 hover:fa-teal-text" title="Déposer des pièces">
                                      <Upload size={13} />
                                    </button>
                                    <StatusBadge status={d.status} />
                                    <PaiementBadge dossier={d} />
                                    <span>{fmtDate(d.createdAt)}</span>
                                    {d.commissionAmount != null && <span className="fa-teal-text font-semibold">{fmtEuro(d.commissionAmount)}</span>}
                                  </div>
                                </div>
                                {adminExtraDocOpenId === d.id && (
                                  <div className="mt-2 pt-2 border-t border-gray-100">{renderDocUpload(d)}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}

                        {viewingPartnerTab === "contrat" && (
                          <div className="space-y-4">
                            <div className="fa-bg-offwhite rounded-xl p-4">
                              <div className="text-sm font-semibold fa-navy mb-2">Contrat d'apporteur d'affaires</div>
                              {p.contractFile ? (
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  <button onClick={() => downloadStoredFile(p.contractFile.key, p.contractFile.name)}
                                    className="text-xs fa-teal-text hover:underline font-medium">
                                    📄 {p.contractFile.name} — déposé le {fmtDate(p.contractFile.uploadedAt)}
                                  </button>
                                </div>
                              ) : (
                                <div className="text-xs text-gray-400 mb-2">Aucun contrat déposé pour l'instant.</div>
                              )}
                              <label className="inline-block mt-2 text-xs border border-gray-300 rounded-lg px-3 py-1.5 cursor-pointer bg-white hover:border-teal-400 transition">
                                {p.contractFile ? "Remplacer le contrat signé" : "Déposer le contrat signé"}
                                <input type="file" accept="application/pdf,image/*" className="hidden"
                                  onChange={e => e.target.files?.[0] && onUploadPartnerContract(p.id, e.target.files[0])} />
                              </label>
                            </div>

                            <div className="fa-bg-offwhite rounded-xl p-4">
                              <div className="text-sm font-semibold fa-navy mb-2">RIB</div>
                              {p.ribFile ? (
                                <button onClick={() => downloadStoredFile(p.ribFile.key, p.ribFile.name)}
                                  className="text-xs fa-teal-text hover:underline font-medium">
                                  🏦 {p.ribFile.name} — fourni le {fmtDate(p.ribFile.uploadedAt)}
                                </button>
                              ) : (
                                <div className="text-xs text-gray-400">Ce partenaire n'a pas encore déposé son RIB.</div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === "corbeille" && (() => {
          const deletedPartners = data.partners.filter(p => p.deleted).sort((a, b) => (b.deletedAt || 0) - (a.deletedAt || 0));
          const q = corbeilleSearch.trim().toLowerCase();
          const filtered = q
            ? deletedPartners.filter(p => `${p.name} ${p.firstName || ""}`.toLowerCase().includes(q))
            : deletedPartners;
          return (
            <div className="space-y-3">
              <h2 className="font-display text-lg font-semibold fa-navy mb-3">Partenaires supprimés</h2>
              {deletedPartners.length > 0 && (
                <div className="relative mb-2 max-w-sm">
                  <input value={corbeilleSearch} onChange={e => setCorbeilleSearch(e.target.value)}
                    placeholder="Rechercher un partenaire supprimé…"
                    className="w-full border border-gray-300 rounded-lg pl-9 pr-8 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">⌕</span>
                  {corbeilleSearch && (
                    <button onClick={() => setCorbeilleSearch("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      <X size={15} />
                    </button>
                  )}
                </div>
              )}
              {deletedPartners.length === 0 && (
                <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">La corbeille est vide.</div>
              )}
              {deletedPartners.length > 0 && filtered.length === 0 && (
                <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">Aucun résultat pour "{corbeilleSearch}".</div>
              )}
              {filtered.map(p => (
                <div key={p.id} className="bg-white border border-gray-200 rounded-xl px-5 py-4 flex items-center justify-between flex-wrap gap-2 opacity-80">
                  <div>
                    <div className="font-medium fa-navy"><span className="font-bold">{nomPartenaire(p)}</span></div>
                    <div className="text-xs text-gray-400">
                      {afficheReseau(p.company) || "—"} {!MODE_DISCRET && p.ville && `· ${p.ville}`} · supprimé le {p.deletedAt ? fmtDate(p.deletedAt) : "—"}
                    </div>
                  </div>
                  <button onClick={() => onRestorePartner(p.id)}
                    className="flex items-center gap-1.5 text-xs font-semibold bg-emerald-50 text-emerald-700 hover:bg-emerald-100 px-3 py-1.5 rounded-full transition">
                    <RotateCcw size={13} /> Restaurer
                  </button>
                </div>
              ))}

              <h2 className="font-display text-lg font-semibold fa-navy mt-8 mb-3">Mandataires supprimés</h2>
              {(() => {
                const deletedMandataires = data.mandataires.filter(m => m.deleted).sort((a, b) => (b.deletedAt || 0) - (a.deletedAt || 0));
                const qm = corbeilleMandataireSearch.trim().toLowerCase();
                const filteredM = qm
                  ? deletedMandataires.filter(m => `${m.name} ${m.firstName || ""}`.toLowerCase().includes(qm))
                  : deletedMandataires;
                return (
                  <div className="space-y-3">
                    {deletedMandataires.length > 0 && (
                      <div className="relative mb-2 max-w-sm">
                        <input value={corbeilleMandataireSearch} onChange={e => setCorbeilleMandataireSearch(e.target.value)}
                          placeholder="Rechercher un mandataire supprimé…"
                          className="w-full border border-gray-300 rounded-lg pl-9 pr-8 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm">⌕</span>
                        {corbeilleMandataireSearch && (
                          <button onClick={() => setCorbeilleMandataireSearch("")} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                            <X size={15} />
                          </button>
                        )}
                      </div>
                    )}
                    {deletedMandataires.length === 0 && (
                      <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">Aucun mandataire supprimé.</div>
                    )}
                    {deletedMandataires.length > 0 && filteredM.length === 0 && (
                      <div className="text-center text-gray-400 text-sm py-16 border border-dashed border-gray-200 rounded-2xl">Aucun résultat pour "{corbeilleMandataireSearch}".</div>
                    )}
                    {filteredM.map(m => (
                      <div key={m.id} className="bg-white border border-gray-200 rounded-xl px-5 py-4 flex items-center justify-between flex-wrap gap-2 opacity-80">
                        <div>
                          <div className="font-medium fa-navy">
                            <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[m.name] }}>{up(m.name)} {m.firstName}</span>
                          </div>
                          <div className="text-xs text-gray-400 mt-1">
                            {m.email} · supprimé le {m.deletedAt ? fmtDate(m.deletedAt) : "—"}
                          </div>
                        </div>
                        <button onClick={() => onRestoreMandataire(m.id)}
                          className="flex items-center gap-1.5 text-xs font-semibold bg-emerald-50 text-emerald-700 hover:bg-emerald-100 px-3 py-1.5 rounded-full transition">
                          <RotateCcw size={13} /> Restaurer
                        </button>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          );
        })()}

        {tab === "stats" && (() => {
          const allDepartements = [...new Set(data.partners.map(p => p.departement).filter(Boolean))].sort();
          const allReseaux = [...new Set(data.partners.map(p => p.company).filter(Boolean))].sort((a, b) => a.localeCompare(b));
          const scopedPartnerIds = new Set(
            data.partners
              .filter(p => statsDepartementFilter === "tous" || p.departement === statsDepartementFilter)
              .filter(p => statsReseauFilter === "tous" || p.company === statsReseauFilter)
              .map(p => p.id)
          );
          const scopedFilterActive = statsDepartementFilter !== "tous" || statsReseauFilter !== "tous";
          const partners = scopedFilterActive ? data.partners.filter(p => scopedPartnerIds.has(p.id)) : data.partners;
          const dossiers = scopedFilterActive ? data.dossiers.filter(d => scopedPartnerIds.has(d.partnerId)) : data.dossiers;

          const activePartners = partners.filter(p => !p.deleted && p.active !== false);
          const inactivePartners = partners.filter(p => !p.deleted && p.active === false);
          const deletedPartners = partners.filter(p => p.deleted);
          const totalEver = partners.length || 1;
          const pct = (n) => Math.round((n / totalEver) * 100);

          const totalDossiers = dossiers.length;
          const statusCounts = ADMIN_STATUS_OPTIONS.map(s => ({
            status: s, count: dossiers.filter(d => d.status === s).length,
          }));
          const koCount = dossiers.filter(d => d.status === "KO").length;
          const paidCount = dossiers.filter(d => d.status === "Payé").length;
          const transformDenom = totalDossiers - koCount;
          const transformRate = transformDenom > 0 ? Math.round((paidCount / transformDenom) * 100) : 0;
          const koRate = totalDossiers ? Math.round((koCount / totalDossiers) * 100) : 0;

          function buildBuckets(period) {
            const now = new Date();
            const buckets = [];
            if (period === "jour") {
              for (let i = 13; i >= 0; i--) {
                const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i);
                const next = new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1);
                buckets.push({ label: d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }), start: d.getTime(), end: next.getTime() });
              }
            } else if (period === "semaine") {
              for (let i = 7; i >= 0; i--) {
                const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i * 7 - 6);
                const end = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i * 7 + 1);
                buckets.push({ label: "Sem. du " + start.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }), start: start.getTime(), end: end.getTime() });
              }
            } else {
              for (let i = 5; i >= 0; i--) {
                const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
                const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
                buckets.push({ label: start.toLocaleDateString("fr-FR", { month: "short", year: "2-digit" }), start: start.getTime(), end: end.getTime() });
              }
            }
            return buckets;
          }
          const buckets = buildBuckets(statsPeriod);
          const chartData = buckets.map(b => ({
            name: b.label,
            Dossiers: dossiers.filter(d => d.createdAt >= b.start && d.createdAt < b.end).length,
          }));

          const partnerCommercial = (d) => partners.find(p => p.id === d.partnerId)?.commercial || null;
          const WON = ["Payé"];
          const wonDossiers = dossiers.filter(d => WON.includes(d.status));

          const totalCa = wonDossiers.reduce((s, d) => s + (d.caAmount || 0), 0);
          const avgCaPerDossier = wonDossiers.length ? totalCa / wonDossiers.length : 0;
          const totalCommission = wonDossiers.reduce((s, d) => s + (d.commissionAmount || 0), 0);
          const totalCaReelFrangola = totalCa - totalCommission;
          const totalMandataireCut = wonDossiers.reduce((s, d) => {
            return s + ((d.caAmount || 0) - (d.commissionAmount || 0)) / 2;
          }, 0);
          const totalMarge = totalCaReelFrangola - totalMandataireCut;

          const now2 = new Date();
          const curMonthStart = new Date(now2.getFullYear(), now2.getMonth(), 1).getTime();
          const prevMonthStart = new Date(now2.getFullYear(), now2.getMonth() - 1, 1).getTime();
          const paidAt = (d) => d.paymentDate ? new Date(d.paymentDate).getTime() : (d.updatedAt || d.createdAt);
          const curMonthPaid = wonDossiers.filter(d => paidAt(d) >= curMonthStart);
          const prevMonthPaid = wonDossiers.filter(d => paidAt(d) >= prevMonthStart && paidAt(d) < curMonthStart);
          const curMonthCa = curMonthPaid.reduce((s, d) => s + (d.caAmount || 0), 0);
          const prevMonthCa = prevMonthPaid.reduce((s, d) => s + (d.caAmount || 0), 0);
          const curMonthDossiers = dossiers.filter(d => d.createdAt >= curMonthStart).length;
          const prevMonthDossiers = dossiers.filter(d => d.createdAt >= prevMonthStart && d.createdAt < curMonthStart).length;
          const pctChange = (cur, prev) => prev === 0 ? (cur > 0 ? 100 : 0) : Math.round(((cur - prev) / prev) * 100);
          const caChange = pctChange(curMonthCa, prevMonthCa);
          const dossiersChange = pctChange(curMonthDossiers, prevMonthDossiers);

          const commercialStats = COMMERCIAUX.map(c => {
            const partnersOfC = partners.filter(p => !p.deleted && p.commercial === c);
            const dossiersOfC = wonDossiers.filter(d => partnersOfC.some(p => p.id === d.partnerId));
            const ca = dossiersOfC.reduce((s, d) => s + (d.caAmount || 0), 0);
            const commission = dossiersOfC.reduce((s, d) => s + (d.commissionAmount || 0), 0);
            const caReel = ca - commission;
            const mandataireCut = caReel * PART_MANDATAIRE;
            const margeFinale = caReel - mandataireCut;
            // La récurrence se partage aussi en deux, mais sans rétrocession
            // préalable : l'apporteur n'en touche rien.
            const recMensuelle = dossiersOfC.filter(contratEnCours).reduce((sm, d) => sm + recurrenceMensuelle(d), 0);
            const recCumulee = dossiersOfC.reduce((sm, d) => sm + recurrenceCumulee(d), 0);
            return {
              commercial: c, partners: partnersOfC.length,
              dossiers: dossiers.filter(d => partnersOfC.some(p => p.id === d.partnerId)).length,
              ca, commission, mandataireCut, margeFinale, recMensuelle, recCumulee,
            };
          });

          const topPartners = partners.filter(p => !p.deleted)
            .map(p => ({ partner: p, count: dossiers.filter(d => d.partnerId === p.id).length }))
            .filter(x => x.count > 0)
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);

          const topPartnersByRevenue = partners.filter(p => !p.deleted)
            .map(p => {
              const pd = wonDossiers.filter(d => d.partnerId === p.id);
              const tousLesSiens = dossiers.filter(d => d.partnerId === p.id);
              return {
                partner: p,
                ca: pd.reduce((s, d) => s + (d.caAmount || 0), 0),
                commission: pd.reduce((s, d) => s + (d.commissionAmount || 0), 0),
                rec: tousLesSiens.filter(contratEnCours).reduce((s, d) => s + recurrenceMensuelle(d), 0),
              };
            })
            .filter(x => x.ca > 0 || x.commission > 0)
            .sort((a, b) => b.ca - a.ca)
            .slice(0, 5);

          // Top réseaux : l'échelon au-dessus du partenaire. Il dit quelles
          // enseignes ouvrir en priorité — recruter dans un réseau qui produit
          // déjà coûte moins cher que d'en défricher un nouveau.
          const topReseaux = (() => {
            const m = new Map();
            for (const p of partners.filter(x => !x.deleted)) {
              const nom = afficheReseau((p.company || "").trim()) || "Sans réseau";
              if (!m.has(nom)) m.set(nom, { nom, partenaires: 0, dossiers: 0, ca: 0, rec: 0 });
              const g = m.get(nom);
              g.partenaires += 1;
              const siens = dossiers.filter(d => d.partnerId === p.id);
              g.dossiers += siens.length;
              g.ca += siens.filter(d => STATUTS_CONTRAT_VIVANT.includes(d.status)).reduce((s, d) => s + (d.caAmount || 0), 0);
              g.rec += siens.filter(contratEnCours).reduce((s, d) => s + recurrenceMensuelle(d), 0);
            }
            return [...m.values()]
              .filter(g => g.dossiers > 0 || g.partenaires > 0)
              .sort((a, b) => b.dossiers - a.dossiers || b.partenaires - a.partenaires)
              .slice(0, 6);
          })();

          const STATUS_BAR_COLORS = {
            "Déposé": "#F0C61A", "En vérification": "#0EA5E9", "Devis en cours": "#008BA8",
            "Souscrit": "#10B981", "KO": "#EF4444", "Bordereau émis": "#8B5CF6",
          };

          return (
            <div className="space-y-8">
              {/* Vue trésorerie : volontairement hors filtres, on ne pilote pas
                  une caisse par département. */}
              <Vision360 data={data} />
              <ProjectionCA data={data} />
              <ObjectifsCA data={data} />

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-3">Dernières connexions</div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS["Sébastien"] }}>Sébastien</span>
                    <span className="text-gray-500 text-xs">{data.settings.admin.lastLoginAt ? `${fmtDate(data.settings.admin.lastLoginAt)} à ${new Date(data.settings.admin.lastLoginAt).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}` : "Jamais connecté"}</span>
                  </div>
                  {data.mandataires.map(m => (
                    <div key={m.id} className="flex items-center justify-between text-sm">
                      <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[m.name] }}>{commercialLabel(m.name)}</span>
                      <span className="text-gray-500 text-xs">{m.lastLoginAt ? `${fmtDate(m.lastLoginAt)} à ${new Date(m.lastLoginAt).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}` : "Jamais connecté"}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-3">Journal d'activité</div>
                {(!data.activityLog || data.activityLog.length === 0) ? (
                  <div className="text-sm text-gray-400">Aucune action enregistrée pour l'instant.</div>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {data.activityLog.slice(0, 30).map(entry => (
                      <div key={entry.id} className="flex items-start justify-between gap-2 text-sm">
                        <span className="text-gray-600">
                          <strong className="fa-navy" style={{ color: COMMERCIAL_COLORS[entry.actor] }}>{entry.actor}</strong> {entry.message}
                        </span>
                        <span className="text-gray-400 text-xs whitespace-nowrap">{fmtDate(entry.at)} {new Date(entry.at).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>


              <div className="flex flex-wrap items-center gap-2">
                <select value={statsDepartementFilter} onChange={e => setStatsDepartementFilter(e.target.value)}
                  className="text-sm border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-teal-500">
                  <option value="tous">Tous les départements</option>
                  {allDepartements.map(d => <option key={d} value={d}>{d}</option>)}
                </select>
                <select value={statsReseauFilter} onChange={e => setStatsReseauFilter(e.target.value)}
                  className="text-sm border border-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-teal-500">
                  <option value="tous">Tous les réseaux</option>
                  {allReseaux.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                {scopedFilterActive && (
                  <button onClick={() => { setStatsDepartementFilter("tous"); setStatsReseauFilter("tous"); }}
                    className="text-xs text-gray-400 hover:text-red-600 underline underline-offset-2">
                    Réinitialiser les filtres
                  </button>
                )}
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div className="bg-white border border-gray-200 rounded-2xl p-5 flex items-center justify-between">
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Dossiers ce mois-ci vs mois dernier</div>
                    <div className="font-display text-xl font-bold fa-navy">{curMonthDossiers} <span className="text-sm font-normal text-gray-400">({prevMonthDossiers} le mois dernier)</span></div>
                  </div>
                  <span className={`text-sm font-bold px-2.5 py-1 rounded-full ${dossiersChange >= 0 ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
                    {dossiersChange >= 0 ? "↑" : "↓"} {Math.abs(dossiersChange)}%
                  </span>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5 flex items-center justify-between">
                  <div>
                    <div className="text-xs text-gray-400 mb-1">CA payé ce mois-ci vs mois dernier</div>
                    <div className="font-display text-xl font-bold fa-navy">{fmtEuro(curMonthCa)} <span className="text-sm font-normal text-gray-400">({fmtEuro(prevMonthCa)} le mois dernier)</span></div>
                  </div>
                  <span className={`text-sm font-bold px-2.5 py-1 rounded-full ${caChange >= 0 ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
                    {caChange >= 0 ? "↑" : "↓"} {Math.abs(caChange)}%
                  </span>
                </div>
              </div>

              <ProductionParAssureur data={data} dossiers={dossiers} />

              <div>
                <h2 className="font-display text-lg font-semibold fa-navy mb-3">Partenaires</h2>
                <div className="grid sm:grid-cols-4 gap-4">
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Total partenaires</div>
                    <div className="font-display text-2xl font-bold fa-navy">{totalEver === 1 && partners.length === 0 ? 0 : partners.length}</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Actifs</div>
                    <div className="font-display text-2xl font-bold text-emerald-600">{activePartners.length} <span className="text-sm font-normal text-gray-400">({pct(activePartners.length)}%)</span></div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Inactifs</div>
                    <div className="font-display text-2xl font-bold text-gray-500">{inactivePartners.length} <span className="text-sm font-normal text-gray-400">({pct(inactivePartners.length)}%)</span></div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Supprimés</div>
                    <div className="font-display text-2xl font-bold text-red-500">{deletedPartners.length} <span className="text-sm font-normal text-gray-400">({pct(deletedPartners.length)}%)</span></div>
                  </div>
                </div>

                {/* Deux réseaux dans le réseau : les apporteurs immobiliers,
                    rémunérés en pourcentage, et les apporteurs hors immobilier,
                    au forfait et réglés le plus souvent en carte cadeau. */}
                {(() => {
                  const vivants = partners.filter(p => !p.deleted);
                  const horsImmo = vivants.filter(p => p.flatFee != null);
                  const immo = vivants.filter(p => p.flatFee == null);
                  const forfaitMoyen = horsImmo.length
                    ? horsImmo.reduce((sm, p) => sm + (Number(p.flatFee) || 0), 0) / horsImmo.length
                    : 0;
                  const dossiersDe = (liste) => {
                    const ids = new Set(liste.map(p => p.id));
                    return dossiers.filter(d => ids.has(d.partnerId)).length;
                  };
                  return (
                    <div className="grid sm:grid-cols-2 gap-4 mt-4">
                      <div className="bg-white border border-gray-200 rounded-2xl p-5">
                        <div className="text-xs text-gray-400 mb-1">Apporteurs immobiliers</div>
                        <div className="font-display text-2xl font-bold fa-teal-text">{immo.length}</div>
                        <div className="text-xs text-gray-400 mt-1">
                          rémunérés en pourcentage · {dossiersDe(immo)} dossier{dossiersDe(immo) > 1 ? "s" : ""}
                        </div>
                      </div>
                      <div className="bg-white border border-violet-200 rounded-2xl p-5">
                        <div className="text-xs text-gray-400 mb-1">Apporteurs hors immobilier</div>
                        <div className="font-display text-2xl font-bold text-violet-700">{horsImmo.length}</div>
                        <div className="text-xs text-gray-400 mt-1">
                          au forfait{forfaitMoyen > 0 && <> · {fmtEuro(forfaitMoyen)} en moyenne</>} · {dossiersDe(horsImmo)} dossier{dossiersDe(horsImmo) > 1 ? "s" : ""}
                        </div>
                      </div>
                    </div>
                  );
                })()}
              </div>

              <div>
                <h2 className="font-display text-lg font-semibold fa-navy mb-3">Dossiers</h2>
                <div className="grid sm:grid-cols-3 gap-4 mb-5">
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Total dossiers</div>
                    <div className="font-display text-2xl font-bold fa-navy">{totalDossiers}</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Taux de transformation</div>
                    <div className="font-display text-2xl font-bold text-violet-600">{transformRate}%</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Taux de KO</div>
                    <div className="font-display text-2xl font-bold text-red-500">{koRate}%</div>
                  </div>
                </div>

                <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-5">
                  <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
                    <div className="font-display font-semibold fa-navy">Dossiers reçus</div>
                    <div className="flex gap-1.5">
                      {[["jour", "Par jour"], ["semaine", "Par semaine"], ["mois", "Par mois"]].map(([val, label]) => (
                        <button key={val} onClick={() => setStatsPeriod(val)}
                          className={`text-xs font-medium px-3 py-1.5 rounded-full transition ${statsPeriod === val ? "fa-bg-teal" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div style={{ width: "100%", height: 220 }}>
                    <ResponsiveContainer>
                      <BarChart data={chartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#eee" />
                        <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={statsPeriod === "jour" ? 1 : 0} />
                        <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={28} />
                        <Tooltip />
                        <Bar dataKey="Dossiers" fill="#008BA8" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="font-display font-semibold fa-navy mb-4">Répartition par statut</div>
                  <div className="space-y-2.5">
                    {statusCounts.map(sc => (
                      <div key={sc.status} className="flex items-center gap-3">
                        <div className="w-32 text-xs text-gray-500 shrink-0">{sc.status}</div>
                        <div className="flex-1 bg-gray-100 rounded-full h-2.5 overflow-hidden">
                          <div className="h-full rounded-full" style={{
                            width: totalDossiers ? `${(sc.count / totalDossiers) * 100}%` : "0%",
                            background: STATUS_BAR_COLORS[sc.status],
                          }} />
                        </div>
                        <div className="w-16 text-xs text-gray-500 text-right shrink-0">{sc.count} ({totalDossiers ? Math.round((sc.count / totalDossiers) * 100) : 0}%)</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div>
                <h2 className="font-display text-lg font-semibold fa-navy mb-3">Chiffre d'affaires &amp; rétrocessions</h2>
                {(() => {
                  // Honoraires et récurrence ont le même poids : les présenter
                  // séparément puis additionnés est la seule lecture honnête.
                  const recCumul = dossiers.reduce((sm, d) => sm + recurrenceCumulee(d), 0);
                  const recMois = dossiers.filter(contratEnCours).reduce((sm, d) => sm + recurrenceMensuelle(d), 0);
                  const sansRec = dossiers.filter(d => STATUTS_CONTRAT_VIVANT.includes(d.status) && recurrenceMensuelle(d) <= 0).length;
                  return (
                    <>
                      <div className="grid sm:grid-cols-4 gap-4 mb-4">
                        <div className="bg-white border border-gray-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-400 mb-1">Honoraires générés</div>
                          <div className="font-display text-2xl font-bold fa-navy">{fmtEuro(totalCa)}</div>
                        </div>
                        <div className="bg-violet-50 border border-violet-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-500 mb-1">Récurrence perçue</div>
                          <div className="font-display text-2xl font-bold text-violet-700">{fmtEuro(recCumul)}</div>
                          <div className="text-[11px] text-gray-400 mt-0.5">{fmtEuroPrecis(recMois)}/mois en cours</div>
                        </div>
                        <div className="fa-bg-teal rounded-2xl p-5">
                          <div className="text-xs text-white/80 mb-1">Chiffre d'affaires total</div>
                          <div className="font-display text-2xl font-bold text-white">{fmtEuro(totalCa + recCumul)}</div>
                        </div>
                        <div className="bg-white border border-gray-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-400 mb-1">CA moyen / dossier payé</div>
                          <div className="font-display text-2xl font-bold fa-teal-text">{fmtEuro(avgCaPerDossier)}</div>
                          <div className="text-[11px] text-gray-400 mt-0.5">honoraires seuls</div>
                        </div>
                      </div>
                      <div className="grid sm:grid-cols-3 gap-4 mb-5">
                        <div className="bg-white border border-gray-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-400 mb-1">Rétrocessions apporteurs</div>
                          <div className="font-display text-xl font-bold text-violet-600">{fmtEuro(totalCommission)}</div>
                          <div className="text-[11px] text-gray-400 mt-0.5">sur les honoraires uniquement</div>
                        </div>
                        <div className="bg-white border border-gray-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-400 mb-1">Part mandataires</div>
                          <div className="font-display text-xl font-bold fa-navy">{fmtEuro((totalCa - totalCommission) * PART_MANDATAIRE + recCumul * PART_MANDATAIRE)}</div>
                          <div className="text-[11px] text-gray-400 mt-0.5">moitié des honoraires nets et de la récurrence</div>
                        </div>
                        <div className="bg-white border border-gray-200 rounded-2xl p-5">
                          <div className="text-xs text-gray-400 mb-1">Marge nette Frangola</div>
                          <div className="font-display text-xl font-bold text-emerald-600">
                            {fmtEuro(totalMarge + recCumul * (1 - PART_MANDATAIRE))}
                          </div>
                          <div className="text-[11px] text-gray-400 mt-0.5">récurrence comprise</div>
                        </div>
                      </div>
                      {sansRec > 0 && (
                        <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-5">
                          {sansRec} contrat{sansRec > 1 ? "s" : ""} sans cotisation ni taux renseignés — leur récurrence
                          n'entre dans aucun de ces chiffres.
                        </div>
                      )}
                    </>
                  );
                })()}
              </div>

              <div className="grid sm:grid-cols-2 gap-5">
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="font-display font-semibold fa-navy mb-4">Par commercial</div>
                  <div className="space-y-3">
                    {commercialStats.map(cs => (
                      <div key={cs.commercial} className="flex items-center justify-between text-sm">
                        <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[cs.commercial] || "#999" }}>{commercialLabel(cs.commercial)}</span>
                        <span className="text-gray-500">{cs.partners} partenaire{cs.partners !== 1 ? "s" : ""} · {cs.dossiers} dossier{cs.dossiers !== 1 ? "s" : ""}</span>
                      </div>
                    ))}
                    <div className="pt-2 mt-2 border-t border-gray-100 space-y-1.5">
                      {commercialStats.map(cs => (
                        <div key={cs.commercial + "-fin"} className="text-xs text-gray-500">
                          <div className="flex items-center justify-between">
                            <span>{cs.commercial}</span>
                            <span>CA {fmtEuro(cs.ca)} · Apporteur {fmtEuro(cs.commission)}</span>
                          </div>
                          <div className="flex items-center justify-between pl-3 text-gray-400">
                            <span>Part {cs.commercial} (mandataire)</span>
                            <span>{fmtEuro(cs.mandataireCut)}</span>
                          </div>
                          <div className="flex items-center justify-between pl-3 text-violet-700">
                            <span>Récurrence · {fmtEuroPrecis(cs.recMensuelle)}/mois</span>
                            <span>{fmtEuro(cs.recCumulee)} perçus</span>
                          </div>
                          <div className="flex items-center justify-between pl-6 text-gray-400">
                            <span>dont part {cs.commercial}</span>
                            <span>{fmtEuro(cs.recCumulee * PART_MANDATAIRE)}</span>
                          </div>
                          <div className="flex items-center justify-between pl-3 font-semibold text-emerald-700">
                            <span>Marge nette Frangola</span>
                            <span>{fmtEuro(cs.margeFinale + cs.recCumulee * (1 - PART_MANDATAIRE))}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="font-display font-semibold fa-navy mb-4">Top partenaires (volume)</div>
                  {topPartners.length === 0 && <div className="text-sm text-gray-400">Pas encore de dossier déposé.</div>}
                  <div className="space-y-2.5">
                    {topPartners.map((tp, i) => (
                      <div key={tp.partner.id} className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2">
                          <span className="fa-navy font-bold">{i + 1}. {nomPartenaire(tp.partner)}</span>
                          {reseauLogoFor(tp.partner.company) && (
                            <img src={reseauLogoFor(tp.partner.company).data} alt={tp.partner.company} className="h-4 max-w-[52px] object-contain" />
                          )}
                        </span>
                        <span className="fa-bg-gold fa-navy text-xs font-bold px-2.5 py-0.5 rounded-full">{tp.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-4">Top partenaires (chiffre d'affaires)</div>
                {topPartnersByRevenue.length === 0 && <div className="text-sm text-gray-400">Aucun montant renseigné pour l'instant.</div>}
                <div className="space-y-2.5">
                  {topPartnersByRevenue.map((tp, i) => (
                    <div key={tp.partner.id} className="flex items-center justify-between text-sm">
                      <span className="flex items-center gap-2">
                        <span className="fa-navy font-bold">{i + 1}. {nomPartenaire(tp.partner)}</span>
                        {reseauLogoFor(tp.partner.company) && (
                          <img src={reseauLogoFor(tp.partner.company).data} alt={tp.partner.company} className="h-4 max-w-[52px] object-contain" />
                        )}
                      </span>
                      <span className="text-gray-500 text-xs">
                        CA {fmtEuro(tp.ca)} · Rétro {fmtEuro(tp.commission)}
                        {tp.rec > 0 && <span className="text-violet-700"> · +{fmtEuroPrecis(tp.rec)}/mois</span>}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-1">Top réseaux</div>
                <p className="text-sm text-gray-500 mb-4">
                  Où votre réseau produit déjà. Recruter dans une enseigne qui tourne coûte moins cher
                  que d'en ouvrir une nouvelle.
                </p>
                {topReseaux.length === 0 ? (
                  <div className="text-sm text-gray-400">Aucun réseau pour l'instant.</div>
                ) : (
                  <div className="space-y-2">
                    {topReseaux.map((r, i) => (
                      <div key={r.nom} className="flex items-center gap-3 flex-wrap text-sm fa-bg-offwhite rounded-lg px-3 py-2">
                        <span className="text-xs text-gray-400 w-4 shrink-0">{i + 1}</span>
                        {reseauLogoFor(r.nom)
                          ? <img src={reseauLogoFor(r.nom).data} alt={r.nom} className="h-6 max-w-[70px] object-contain shrink-0" />
                          : <Building2 size={16} className="text-gray-300 shrink-0" />}
                        <span className={`font-semibold ${r.nom === "Sans réseau" ? "text-gray-400" : "fa-navy"}`}>{r.nom}</span>
                        <span className="text-xs text-gray-500">
                          {r.partenaires} partenaire{r.partenaires > 1 ? "s" : ""} · {r.dossiers} dossier{r.dossiers > 1 ? "s" : ""}
                        </span>
                        <span className="ml-auto text-xs text-right">
                          <span className="fa-navy font-semibold">{fmtEuro(r.ca)}</span>
                          {r.rec > 0 && <span className="text-violet-700"> · +{fmtEuroPrecis(r.rec)}/mois</span>}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                <p className="text-xs text-gray-400 mt-3">
                  Les logos apparaissent dès que vous les déposez sur la fiche du réseau.
                </p>
              </div>

              {(() => {
                const decls = data.parrainages || [];
                const parrains = data.partners.filter(p => !p.deleted && filleulsDe(p.id).length > 0);
                const filleuls = data.partners.filter(p => !p.deleted && p.parrainId);
                if (decls.length === 0 && filleuls.length === 0) return null;

                const valides = decls.filter(d => d.statut === "valide").length;
                const refusees = decls.filter(d => d.statut === "refuse").length;
                const attente = decls.filter(d => d.statut === "en_attente").length;
                const tauxValidation = decls.length ? Math.round((valides / decls.length) * 100) : 0;

                const idsFilleuls = new Set(filleuls.map(p => p.id));
                const caParrainage = data.dossiers
                  .filter(d => d.status === "Payé" && idsFilleuls.has(d.partnerId))
                  .reduce((s, d) => s + (d.caAmount || 0), 0);
                const caTotal = data.dossiers
                  .filter(d => d.status === "Payé")
                  .reduce((s, d) => s + (d.caAmount || 0), 0);
                const partCA = caTotal ? Math.round((caParrainage / caTotal) * 100) : 0;
                const filleulsActifs = filleuls.filter(p => data.dossiers.some(d => d.partnerId === p.id)).length;
                const tauxActivation = filleuls.length ? Math.round((filleulsActifs / filleuls.length) * 100) : 0;
                const coutTotal = parrains.reduce((s, p) => s + bilanParrainage(p.id).gainTotal, 0);

                const classement = parrains
                  .map(p => ({ p, ...bilanParrainage(p.id) }))
                  .sort((a, b) => b.caTotal - a.caTotal)
                  .slice(0, 5);

                return (
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="font-display font-semibold fa-navy mb-1">Parrainage — performance</div>
                    <p className="text-sm text-gray-500 mb-4">Ce que le bouche-à-oreille entre apporteurs rapporte réellement.</p>

                    <div className="grid sm:grid-cols-4 gap-3 mb-4">
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">Déclarations reçues</div>
                        <div className="font-display text-xl font-bold fa-navy">{decls.length}</div>
                        <div className="text-[11px] text-gray-400 mt-0.5">{valides} validées · {refusees} refusées · {attente} en attente</div>
                      </div>
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">Taux de validation</div>
                        <div className="font-display text-xl font-bold fa-navy">{tauxValidation}%</div>
                        <div className="text-[11px] text-gray-400 mt-0.5">des déclarations retenues</div>
                      </div>
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">Filleuls rattachés</div>
                        <div className="font-display text-xl font-bold fa-navy">{filleuls.length}</div>
                        <div className="text-[11px] text-gray-400 mt-0.5">{filleulsActifs} actifs — {tauxActivation}%</div>
                      </div>
                      <div className="fa-bg-gold rounded-xl p-4">
                        <div className="text-xs text-teal-900/70">CA issu du parrainage</div>
                        <div className="font-display text-xl font-bold fa-navy">{fmtEuro(caParrainage)}</div>
                        <div className="text-[11px] text-teal-900/70 mt-0.5">{partCA}% du CA encaissé</div>
                      </div>
                    </div>

                    <div className="grid sm:grid-cols-2 gap-3 mb-4">
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">Coût du dispositif</div>
                        <div className="font-display text-lg font-bold fa-navy">{fmtEuroPrecis(coutTotal)}</div>
                        <div className="text-[11px] text-gray-400 mt-0.5">{Math.round(PARRAINAGE_TAUX * 100)} % reversés aux parrains</div>
                      </div>
                      <div className="fa-bg-offwhite rounded-xl p-4">
                        <div className="text-xs text-gray-400">Net conservé sur ces dossiers</div>
                        <div className="font-display text-lg font-bold text-emerald-600">{fmtEuro(caParrainage / 2 - coutTotal)}</div>
                        <div className="text-[11px] text-gray-400 mt-0.5">après rétrocession apporteur et prime parrain</div>
                      </div>
                    </div>

                    {classement.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold fa-navy mb-2">Meilleurs parrains</div>
                        <div className="space-y-1">
                          {classement.map((x, i) => (
                            <div key={x.p.id} className="flex items-center justify-between flex-wrap gap-2 text-sm py-1">
                              <span className="fa-navy font-bold">
                                {i + 1}. {nomPartenaire(x.p)}
                              </span>
                              <span className="text-xs text-gray-500">
                                {x.filleuls.length} filleul{x.filleuls.length > 1 ? "s" : ""} · {x.actifs} actif{x.actifs > 1 ? "s" : ""} · CA {fmtEuroPrecis(x.caTotal)} · prime {fmtEuroPrecis(x.gainTotal)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

                            <SauvegardesPanel />

              <div className="bg-white border border-gray-200 rounded-2xl p-5">
                <div className="font-display font-semibold fa-navy mb-4">Évolution du nombre de partenaires</div>
                <div style={{ width: "100%", height: 200 }}>
                  <ResponsiveContainer>
                    <LineChart data={(() => {
                      const now = new Date();
                      const monthBuckets = [];
                      for (let i = 5; i >= 0; i--) {
                        const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
                        monthBuckets.push({
                          name: new Date(now.getFullYear(), now.getMonth() - i, 1).toLocaleDateString("fr-FR", { month: "short", year: "2-digit" }),
                          Partenaires: partners.filter(p => p.createdAt < end.getTime()).length,
                        });
                      }
                      return monthBuckets;
                    })()}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#eee" />
                      <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={28} />
                      <Tooltip />
                      <Line type="monotone" dataKey="Partenaires" stroke="#008BA8" strokeWidth={2.5} dot={{ r: 3 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>
          );
        })()}

              {tab === "facturation" && (
          <FacturationAdmin data={data} onSetStatut={onSetFactureStatut} onAddVersement={onAddVersementParrainage}
            onVirementPartenaire={onVirementPartenaire} onAnnulerVirement={onAnnulerVirement} busy={busy} />
        )}
        {tab === "challenge" && (
          <div className="space-y-6">
            {/* Les objectifs se modifient dans le tableau ci-dessous, pas ici :
                un seul endroit pour une même valeur. */}
            <ProductionDuMois data={data} commerciaux={COMMERCIAUX}
              onSetGoals={onSetChallengeGoals} canEdit={isFullAdmin} />
            <ChallengePartenaires data={data} onSet={onSetChallengePartenaires} canEdit={isFullAdmin} />
            <ChallengeBoard data={data} commerciaux={COMMERCIAUX}
              onSetGoals={onSetChallengeGoals} canEdit={isFullAdmin} />
          </div>
        )}
        {tab === "mandataires" && isFullAdmin && (
          <div>
            <FicheAdmin admin={data.settings.admin} onUpdate={onUpdateAdmin} />

            <AssureursPanel data={data} onSet={onSetAssureurs} canEdit={isFullAdmin} busy={busy} />

            <div className="flex items-center justify-between mb-6 flex-wrap gap-2">
              <h2 className="font-display text-lg font-semibold fa-navy">Mandataires</h2>
              <button onClick={() => setShowAddMandataireForm(v => !v)}
                className="flex items-center gap-1.5 fa-bg-gold font-medium text-sm px-4 py-2 rounded-full transition">
                <Plus size={16} /> Ajouter un mandataire
              </button>
            </div>

            {showAddMandataireForm && (
              <div className="bg-white border border-gray-200 rounded-2xl p-6 mb-6 shadow-sm">
                <h3 className="font-display font-semibold fa-navy mb-4">Ajouter un mandataire</h3>
                <div className="grid sm:grid-cols-3 gap-4 mb-4">
                  <input value={newMandataireName} onChange={e => setNewMandataireName(e.target.value)} placeholder="Nom"
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <input value={newMandataireFirstName} onChange={e => setNewMandataireFirstName(e.target.value)} placeholder="Prénom"
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                  <input value={newMandataireEmail} onChange={e => setNewMandataireEmail(e.target.value)} type="email" placeholder="Adresse email"
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                </div>
                <div className="flex items-center gap-3 mb-4">
                  <label className="text-sm text-gray-500">Couleur d'affichage</label>
                  <input type="color" value={newMandataireColor} onChange={e => setNewMandataireColor(e.target.value)}
                    className="w-10 h-9 rounded-lg border border-gray-300 cursor-pointer p-0.5" />
                  <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: newMandataireColor }}>
                    {newMandataireName.trim() || "Aperçu"}
                  </span>
                </div>
                <div className="mb-4 max-w-sm">
                  <label className="block text-sm font-medium fa-navy mb-1">Niveau d'accès</label>
                  <select value={newMandataireRole} onChange={e => setNewMandataireRole(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500">
                    <option value="standard">Mandataire standard — voit uniquement sa production</option>
                    <option value="manager">Manager — accès complet, comme l'admin</option>
                  </select>
                </div>
                <div className="flex gap-2">
                  <button onClick={async () => {
                    if (!newMandataireName.trim() || !newMandataireEmail.trim()) return;
                    const m = await onAddMandataire({ name: newMandataireName.trim(), firstName: newMandataireFirstName.trim(), email: newMandataireEmail.trim(), color: newMandataireColor, role: newMandataireRole });
                    setCreatedMandataire(m);
                    setNewMandataireName(""); setNewMandataireFirstName(""); setNewMandataireEmail(""); setNewMandataireColor("#545454"); setNewMandataireRole("standard"); setShowAddMandataireForm(false);
                  }} disabled={!newMandataireName.trim() || !newMandataireEmail.trim()}
                    className="fa-bg-teal disabled:opacity-50 text-white text-sm font-medium px-5 py-2 rounded-lg transition">
                    Créer l'accès
                  </button>
                  <button onClick={() => setShowAddMandataireForm(false)} className="text-sm text-gray-500 hover:text-gray-700 px-3 py-2">Annuler</button>
                </div>
                <p className="text-xs text-gray-400 mt-3">Le mandataire créera lui-même son mot de passe à sa première connexion, avec cette adresse email.</p>
              </div>
            )}

            {createdMandataire && (
              <div className="mt-2 mb-6 text-sm bg-teal-50 border border-teal-200 rounded-lg px-4 py-3">
                <strong>{createdMandataire.name}</strong> peut se connecter avec son email (<strong>{createdMandataire.email}</strong>) — il créera son mot de passe à sa 1ère connexion.
              </div>
            )}

            <div className="space-y-3">
              {data.mandataires.filter(m => !m.deleted).length === 0 && <div className="text-center text-gray-400 text-sm py-10">Aucun mandataire pour l'instant — Sébastien reste le commercial par défaut.</div>}
              {data.mandataires.filter(m => !m.deleted).map(m => (
                <div key={m.id} className={`bg-white border rounded-xl px-5 py-4 ${m.active === false ? "border-gray-200 opacity-60" : "border-gray-200"}`}>
                  {editingMandataireId === m.id ? (
                    <div>
                      <div className="grid sm:grid-cols-3 gap-3 mb-3">
                        <input value={editMandataireForm.name} onChange={e => setEditMandataireForm(f => ({ ...f, name: e.target.value }))} placeholder="Nom"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <input value={editMandataireForm.firstName} onChange={e => setEditMandataireForm(f => ({ ...f, firstName: e.target.value }))} placeholder="Prénom"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                        <input value={editMandataireForm.email} onChange={e => setEditMandataireForm(f => ({ ...f, email: e.target.value }))} type="email" placeholder="Adresse email"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                      </div>
                      <div className="flex items-center gap-3 mb-3">
                        <label className="text-sm text-gray-500">Couleur d'affichage</label>
                        <input type="color" value={editMandataireForm.color} onChange={e => setEditMandataireForm(f => ({ ...f, color: e.target.value }))}
                          className="w-10 h-9 rounded-lg border border-gray-300 cursor-pointer p-0.5" />
                      </div>
                      <div className="mb-3 max-w-sm">
                        <label className="block text-sm font-medium fa-navy mb-1">Niveau d'accès</label>
                        <select value={editMandataireForm.role} onChange={e => setEditMandataireForm(f => ({ ...f, role: e.target.value }))}
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm w-full focus:outline-none focus:ring-2 focus:ring-teal-500">
                          <option value="standard">Mandataire standard — voit uniquement sa production</option>
                          <option value="manager">Manager — accès complet, comme l'admin</option>
                        </select>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => saveEditMandataire(m.id)} className="fa-bg-teal text-sm font-medium px-4 py-1.5 rounded-lg transition">Enregistrer</button>
                        <button onClick={() => setEditingMandataireId(null)} className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div>
                        <div className="font-medium fa-navy flex items-center gap-2">
                          <span className="text-white text-xs font-semibold px-2.5 py-1 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[m.name] }}>{up(m.name)} {m.firstName}</span>
                          {m.role === "manager" && <span className="text-xs font-semibold bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 rounded-full">Manager</span>}
                          {m.active === false && <span className="text-xs font-semibold bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">Inactif</span>}
                        </div>
                        <div className="text-xs text-gray-400">
                          {m.email} · {m.lastLoginAt ? `dernière connexion ${fmtDate(m.lastLoginAt)}` : "jamais connecté"}
                        </div>
                        <div className="mt-1.5">
                          <BlocAcces cible={m} expediteur={viewerLabel} telephone={viewerTelephone} genre="mandataire" onReinitialiser={() => reinitialiserAcces("mandataire", m.id)} />
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button onClick={() => setViewingMandataireId(viewingMandataireId === m.id ? null : m.id)}
                          className="text-sm fa-navy fa-bg-gold px-3 py-1.5 rounded-lg font-medium transition">
                          {viewingMandataireId === m.id ? "Fermer" : "Voir"}
                        </button>
                        <button onClick={() => startEditMandataire(m)} className="text-sm fa-teal-text hover:underline px-2">Modifier</button>
                        <button onClick={() => onUpdateMandataire(m.id, { active: m.active === false ? true : false })}
                          className={`text-xs font-semibold px-3 py-1.5 rounded-full transition ${m.active === false ? "bg-emerald-50 text-emerald-700 hover:bg-emerald-100" : "bg-red-50 text-red-700 hover:bg-red-100"}`}>
                          {m.active === false ? "Réactiver" : "Désactiver"}
                        </button>
                                                {m.totpEnabled && (
                          <button onClick={() => onResetMandataireTotp(m.id)}
                            title="Efface son Authenticator — il le reconfigurera à sa prochaine connexion"
                            className="text-xs font-semibold bg-amber-50 text-amber-700 hover:bg-amber-100 px-3 py-1.5 rounded-full transition">
                            Réinit. authentification
                          </button>
                        )}
                        {confirmDeleteMandataireId === m.id ? (
                          <span className="flex items-center gap-1.5 text-xs">
                            <span className="text-red-700">Confirmer ?</span>
                            <button onClick={() => confirmDeleteMandataire(m.id)} className="font-semibold text-red-700 hover:underline">Oui</button>
                            <button onClick={() => setConfirmDeleteMandataireId(null)} className="text-gray-500 hover:underline">Non</button>
                          </span>
                        ) : (
                          <button onClick={() => setConfirmDeleteMandataireId(m.id)} className="fa-tap text-xs text-gray-400 hover:text-red-600 px-2">Supprimer</button>
                        )}
                      </div>
                    </div>
                  )}

                  {viewingMandataireId === m.id && (() => {
                    const mPartners = data.partners.filter(p => !p.deleted && p.commercial === m.name);
                    const mDossiers = data.dossiers.filter(d => mPartners.some(p => p.id === d.partnerId));
                    const mPaid = mDossiers.filter(d => d.status === "Payé");
                    const mWon = mDossiers.filter(d => ["Souscrit", "Bordereau émis", "Payé"].includes(d.status));
                    const mKo = mDossiers.filter(d => d.status === "KO");
                    const mCa = mPaid.reduce((s, d) => s + (d.caAmount || 0), 0);
                    const mCommission = mPaid.reduce((s, d) => s + (d.commissionAmount || 0), 0);
                    const mPart = (mCa - mCommission) / 2;
                    return (
                      <div className="mt-4 pt-4 border-t border-gray-100">
                        <div className="text-xs text-gray-400 mb-3">Aperçu de ce que {m.name} voit dans son espace :</div>
                        <div className="grid sm:grid-cols-2 gap-3 mb-4">
                          <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">Sa part (mandataire, 50%)</div><div className="font-display text-lg font-bold fa-navy">{fmtEuro(mPart)}</div></div>
                          <div className="fa-bg-offwhite rounded-xl p-4"><div className="text-xs text-gray-400">CA total généré (payé)</div><div className="font-display text-lg font-bold fa-navy">{fmtEuro(mCa)}</div></div>
                        </div>
                        <div className="grid sm:grid-cols-4 gap-3 mb-4">
                          <div className="fa-bg-offwhite rounded-xl p-3"><div className="text-xs text-gray-400">Partenaires</div><div className="font-display font-bold fa-navy">{mPartners.length}</div></div>
                          <div className="fa-bg-offwhite rounded-xl p-3"><div className="text-xs text-gray-400">Dossiers</div><div className="font-display font-bold fa-navy">{mDossiers.length}</div></div>
                          <div className="fa-bg-offwhite rounded-xl p-3"><div className="text-xs text-gray-400">Gagnés</div><div className="font-display font-bold text-emerald-600">{mWon.length}</div></div>
                          <div className="fa-bg-offwhite rounded-xl p-3"><div className="text-xs text-gray-400">KO</div><div className="font-display font-bold text-red-500">{mKo.length}</div></div>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>

  );
}
