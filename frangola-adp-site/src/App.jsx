import { useState, useEffect, useRef } from "react";
import { storage } from "./storage";
import { supabase } from "./supabaseClient";
import {
  Shield, Users, Building2, Upload, FileText, CheckCircle2, Clock,
  Bell, LogOut, Download, Plus, ArrowLeft, Copy, Check, AlertCircle,
  FileCheck2, Landmark, X, Folder, FolderOpen, ChevronDown, Trash2, RotateCcw, BarChart3, StickyNote, History, Home, Target, Eye, EyeOff, ImagePlus, Sparkles, ArrowLeftRight, TrendingUp, Key
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
function fmtEuro(n) {
  return (n || 0).toLocaleString("fr-FR", { style: "currency", currency: "EUR", maximumFractionDigits: 0 });
}
function fmtEuroPrecis(n) {
  return (n || 0).toLocaleString("fr-FR", { style: "currency", currency: "EUR", minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function up(s) {
  return (s || "").toUpperCase();
}
function clientName(d) {
  const full = `${(d.clientLastName || "").toUpperCase()} ${d.clientFirstName || ""}`.trim();
  return full || "(Sans nom)";
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
const PARRAINAGE_TAUX = 0.10;

function filleulsDe(partnerId) {
  if (!_colorDataRef || !partnerId) return [];
  return _colorDataRef.partners.filter(p => !p.deleted && p.parrainId === partnerId);
}

function caGenerePar(partnerId) {
  if (!_colorDataRef) return 0;
  return _colorDataRef.dossiers
    .filter(d => d.partnerId === partnerId && d.status === "Payé")
    .reduce((s, d) => s + (d.caAmount || 0), 0);
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
  return p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name);
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
  const partnerName = (id) => { const p = partners.find(p => p.id === id); return p ? (p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)) : "—"; };
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

    if (emailConnecte && emailConnecte === (data.settings?.admin?.email || "").trim().toLowerCase()) {
      setPendingAuth({ kind: "admin", account: data.settings.admin });
      return;
    }
    const m = data.mandataires.find(x => !x.deleted && (x.email || "").trim().toLowerCase() === emailConnecte);
    if (m) {
      if (m.active === false) { deconnexion("desactive"); return; }
      setPendingAuth({ kind: "mandataire", account: m });
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
    if (file.size > 1024 * 1024) { setGlobalError(`"${file.name}" dépasse 1 Mo — utilise une image plus légère pour un logo.`); return false; }
    setBusy(true);
    try {
      const dataUrl = await fileToDataURL(file);
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

  async function createDossier(clientFirstName, clientLastName, clientPhone, files, hasCoEmprunteur, coClientLastName, coClientFirstName, coClientPhone) {
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
                👁 Aperçu de l'espace de <strong>{cible.firstName ? `${cible.firstName} ${up(cible.name)}` : up(cible.name)}</strong> — lecture seule
              </span>
              <button onClick={() => setApercuPartnerId(null)}
                className="text-xs font-semibold fa-navy bg-white/70 hover:bg-white px-3 py-1.5 rounded-lg transition">
                Quitter l'aperçu
              </button>
            </div>
            <PartnerDashboard
              partner={cible}
              dossiers={data.dossiers.filter(d => d.partnerId === cible.id)}
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
          onLogout={logout}
          onAddPartner={addPartner}
          onUpdatePartner={updatePartner}
          onUploadPartnerContract={uploadPartnerContract}
          onDeletePartner={deletePartner}
          onRestorePartner={restorePartner}
          onAddMandataire={addMandataire}
          onUpdateMandataire={updateMandataire}
          onDeleteMandataire={deleteMandataire}
                    onResetMandataireTotp={resetMandataireTotp}
                    onSetChallengeGoals={setChallengeGoals}
                    onTraiterParrainage={traiterParrainage}
                    onSetFactureStatut={setFactureStatut}
                    onAddVersementParrainage={addVersementParrainage}
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
          onLogout={logout}
          onAddPartner={addPartner}
          onUpdatePartner={updatePartner}
          onUploadPartnerContract={uploadPartnerContract}
          onDeletePartner={deletePartner}
          onRestorePartner={restorePartner}
          onAddMandataire={addMandataire}
          onUpdateMandataire={updateMandataire}
          onDeleteMandataire={deleteMandataire}
                    onResetMandataireTotp={resetMandataireTotp}
                    onSetChallengeGoals={setChallengeGoals}
                    onTraiterParrainage={traiterParrainage}
                    onSetFactureStatut={setFactureStatut}
                    onAddVersementParrainage={addVersementParrainage}
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
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

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
        onDone();
        return;
      }
      const ok = await verifyTotp(account.totpSecret, code);
      if (!ok) { setError("Code incorrect."); return; }
      await onUpdateAccount({ lastLoginAt: Date.now() });
      onDone();
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
            <button onClick={onDone} className="w-full fa-bg-teal font-medium rounded-lg py-2.5 text-sm transition">
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

// =============================================================================
// CODE D'ACTIVATION — ce qu'un partenaire ou un mandataire doit recevoir pour
// créer son mot de passe la première fois, ou le reprendre s'il l'a perdu.
//
// Le mot de passe n'apparaît nulle part : il est détenu par Supabase sous
// forme d'empreinte. Personne, pas même l'administrateur, ne peut le lire.
// =============================================================================
function BlocAcces({ cible, onReinitialiser }) {
  const [copie, setCopie] = useState(false);
  const [confirme, setConfirme] = useState(false);
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
                <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                  d.statut === "valide" ? "bg-emerald-50 text-emerald-700"
                  : d.statut === "refuse" ? "bg-red-50 text-red-700"
                  : "bg-amber-50 text-amber-700"}`}>
                  {d.statut === "valide" ? "Validée" : d.statut === "refuse" ? "Refusée" : "En cours de vérification"}
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
function PartnerDashboard({ partner, dossiers, onLogout, onCreateDossier, onDeclarerParrainage, onAddExtraDoc, onUploadDocToSlot, onRemoveDoc, onRemoveExtraDoc, onUploadRib, onUploadFacture, onSetGoal, onMarkMessageRead, onUpdateDossierClient, busy }) {
  const [tab, setTabRaw] = useState(() => getStoredTab("adp:partnerTab", "encours"));
  const setTab = (t) => { setTabRaw(t); setStoredTab("adp:partnerTab", t); };
  const [showForm, setShowForm] = useState(false);
  const [clientFirstName, setClientFirstName] = useState("");
  const [clientLastName, setClientLastName] = useState("");
  const [clientPhone, setClientPhone] = useState("");
  const [hasCoEmprunteur, setHasCoEmprunteur] = useState(false);
  const [coClientFirstName, setCoClientFirstName] = useState("");
  const [coClientLastName, setCoClientLastName] = useState("");
  const [coClientPhone, setCoClientPhone] = useState("");
  const [files, setFiles] = useState({ offre: null, tableau: null, cni: null });

  function isFormComplete() {
    return true;
  }
  async function submit() {
    if (!isFormComplete()) return;
    const ok = await onCreateDossier(
      clientFirstName.trim(), clientLastName.trim(), clientPhone.trim(), files,
      hasCoEmprunteur, coClientLastName.trim(), coClientFirstName.trim(), coClientPhone.trim()
    );
    if (ok) {
      setShowForm(false); setClientFirstName(""); setClientLastName(""); setClientPhone(""); setFiles({ offre: null, tableau: null, cni: null });
      setHasCoEmprunteur(false); setCoClientFirstName(""); setCoClientLastName(""); setCoClientPhone("");
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
                  - {partner.company}
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
            <div className="flex gap-3 items-center">
              <button onClick={submit} disabled={busy || !isFormComplete()}
                className="fa-bg-teal disabled:opacity-50 text-white text-sm font-medium px-5 py-2 rounded-lg transition">
                {busy ? "Envoi…" : "Déposer le dossier"}
              </button>
              <button onClick={() => setShowForm(false)} className="text-sm text-gray-500 hover:text-gray-700 px-3">Annuler</button>
            </div>
          </div>
        )}

        {(() => {
          const CLOSED = ["Souscrit", "Bordereau émis", "Payé", "KO"];
          const visibleDossiers = dossiers.filter(d => tab === "clotures" ? CLOSED.includes(d.status) : !CLOSED.includes(d.status));
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
                      <button onClick={() => startEditDossier(d)} className="fa-tap text-xs fa-teal-text hover:underline font-normal">Modifier</button>
                    </div>
                    <div className="text-xs text-gray-400">Déposé le {fmtDate(d.createdAt)}{d.clientPhone && ` · ${d.clientPhone}`}</div>
                  </div>
                  <StatusBadge status={d.status} />
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
                    {d.status !== "KO" && (
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
                    {d.status !== "KO" && (
                      <button onClick={() => onRemoveExtraDoc(d.id, i)} className="fa-tap text-teal-500 hover:text-red-600 ml-0.5" title="Retirer ce document">
                        <X size={12} />
                      </button>
                    )}
                  </span>
                ))}
              </div>

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
              {d.status !== "KO" && d.commissionAmount != null && (
                d.status === "Payé" ? (
                  <div className="mt-3 flex items-center gap-2 text-sm font-semibold fa-navy fa-bg-gold px-3 py-2 rounded-lg w-fit">
                    💶 Votre rémunération perçue : {fmtEuro(d.commissionAmount)}
                    {d.paymentMethod && ` · ${d.paymentMethod}`}{d.paymentDate && ` · ${fmtDate(new Date(d.paymentDate).getTime())}`}
                  </div>
                ) : (
                  <div className="mt-3 flex items-center gap-2 text-sm font-semibold fa-teal-text bg-teal-50 border border-teal-200 px-3 py-2 rounded-lg w-fit">
                    💶 Rémunération estimée : {fmtEuro(d.commissionAmount)}
                  </div>
                )
              )}
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
          const totalRemuneration = paid.reduce((s, d) => s + (d.commissionAmount || 0), 0);
          const avgRemuneration = paid.length ? totalRemuneration / paid.length : (partner.flatFee != null ? partner.flatFee : 150);
          const bilanPar = bilanParrainage(partner.id);
          const revenuPassif = bilanPar.gainTotal;
          const revenuGlobal = totalRemuneration + revenuPassif;
          const transformDenominator = total - ko.length;
          const transformRate = transformDenominator > 0 ? Math.round((paid.length / transformDenominator) * 100) : 0;

          const now = new Date();
          const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
          const earnedThisMonth = paid.filter(d => {
            const t = d.paymentDate ? new Date(d.paymentDate).getTime() : d.updatedAt || d.createdAt;
            return t >= monthStart;
          }).reduce((s, d) => s + (d.commissionAmount || 0), 0);
          const goalProgress = partner.monthlyGoal ? Math.min(100, Math.round((earnedThisMonth / partner.monthlyGoal) * 100)) : 0;
          const dossiersNeededForGoal = partner.monthlyGoal && avgRemuneration > 0 ? Math.ceil(partner.monthlyGoal / avgRemuneration) : null;
          const monthly = [];
          for (let i = 5; i >= 0; i--) {
            const start = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const end = new Date(now.getFullYear(), now.getMonth() - i + 1, 1);
            monthly.push({
              name: start.toLocaleDateString("fr-FR", { month: "short", year: "2-digit" }),
              "Rémunération (€)": paid.filter(d => {
                const t = d.paymentDate ? new Date(d.paymentDate).getTime() : d.updatedAt || d.createdAt;
                return t >= start.getTime() && t < end.getTime();
              }).reduce((s, d) => s + (d.commissionAmount || 0), 0),
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
                        Soit environ {dossiersNeededForGoal} dossier{dossiersNeededForGoal > 1 ? "s" : ""} gagné{dossiersNeededForGoal > 1 ? "s" : ""} à votre moyenne actuelle ({fmtEuro(avgRemuneration)}/dossier).
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
                  <div className="font-display text-3xl font-bold text-white">{fmtEuro(totalRemuneration)}</div>
                  {revenuPassif > 0 && (
                    <div className="text-xs text-white/70 mt-1">Avec le parrainage : {fmtEuro(revenuGlobal)}</div>
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
                  <div className="text-xs text-teal-900/70 mb-1">Rémunération moyenne / dossier payé</div>
                  <div className="font-display text-3xl font-bold fa-navy">{fmtEuro(avgRemuneration)}</div>
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
                            <div className="font-display text-xl font-bold fa-navy">{fmtEuro(bilan.gainTotal)}</div>
                          </div>
                        </div>
                        <div className="space-y-2">
                          {bilan.filleuls.slice().sort((a, b) => b.ca - a.ca).map(f => (
                            <div key={f.partner.id} className="flex items-center justify-between flex-wrap gap-2 fa-bg-offwhite rounded-lg px-3 py-2.5">
                              <div>
                                <div className="text-sm fa-navy font-bold">
                                  {f.partner.firstName ? `${f.partner.firstName} ${up(f.partner.name)}` : up(f.partner.name)}
                                </div>
                                <div className="text-xs text-gray-400">
                                  {f.dossiers} dossier{f.dossiers !== 1 ? "s" : ""} · CA généré {fmtEuro(f.ca)}
                                </div>
                              </div>
                              <span className="text-sm font-bold fa-bg-gold fa-navy px-2.5 py-1 rounded-full">{fmtEuro(f.gain)}</span>
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
                    En moyenne, chaque dossier gagné vous rapporte <strong>{fmtEuro(avgRemuneration)}</strong>.
                    Un dossier de plus par mois, c'est environ <strong>{fmtEuro(avgRemuneration * 12)}</strong> de plus sur l'année.
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
    const found = _colorDataRef.mandataires?.find(m => m.name === name);
    if (found?.firstName) return found.firstName;
  }
  return name;
}
function reseauLogoFor(companyName) {
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
                  <span className="fa-navy font-bold">{ps.partner.firstName ? `${ps.partner.firstName} ${up(ps.partner.name)}` : up(ps.partner.name)}</span>
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
    return p ? (p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)) : "—";
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
  const nomDe = (p) => p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name);

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
          <div className="font-display text-xl font-bold fa-navy">{fmtEuro(totalDu)}</div>
        </div>
        <div className="fa-bg-offwhite rounded-xl p-4">
          <div className="text-xs text-gray-400">Déjà versé</div>
          <div className="font-display text-xl font-bold text-emerald-600">{fmtEuro(totalVerse)}</div>
        </div>
        <div className="fa-bg-gold rounded-xl p-4">
          <div className="text-xs text-teal-900/70">Reste à payer</div>
          <div className="font-display text-xl font-bold fa-navy">{fmtEuro(Math.max(0, totalDu - totalVerse))}</div>
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
                  <span className="text-xs text-gray-500">Dû {fmtEuro(x.gainTotal)} · versé {fmtEuro(x.verse)}</span>
                  <span className={`text-sm font-bold px-2.5 py-1 rounded-full ${x.reste > 0.5 ? "fa-bg-gold fa-navy" : "bg-emerald-50 text-emerald-700"}`}>
                    {x.reste > 0.5 ? `à verser ${fmtEuro(x.reste)}` : "à jour"}
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
                          {clientName(d)} <span className="text-gray-400">— via {filleul.firstName ? `${filleul.firstName} ${up(filleul.name)}` : up(filleul.name)}</span>
                        </span>
                        <span className="fa-navy">
                          CA {fmtEuro(d.caAmount || 0)} → prime {fmtEuro((d.caAmount || 0) * PARRAINAGE_TAUX)}
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
  const nomDe = (p) => p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name);

  return (
    <div className="bg-white border border-gray-200 rounded-2xl p-5 mb-4">
      <div className="font-display font-semibold fa-navy mb-1">
        Factures partenaires
        {attente.length > 0 && (
          <span className="ml-2 fa-bg-gold fa-navy text-xs font-bold px-2 py-0.5 rounded-full">
            {attente.length} à régler · {fmtEuro(totalDu)}
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

function AdminDashboard({ data, currentAdmin, isFullAdmin, viewerLabel, onLogout, onAddPartner, onUpdatePartner, onUploadPartnerContract, onDeletePartner, onRestorePartner, onUpdateStatus, onUpdateDossierClient, onDeleteDossier, onUpdateDossierNotes, onUpdateDossierSimulation, onAnalyzeDossierIA, onUpdateDossierPartnerMessage, onUploadBordereau, onAdminUploadDoc, onRemoveDoc, onSwapDocs, onAddExtraDoc, onRemoveExtraDoc, onAddMandataire, onUpdateMandataire, onDeleteMandataire, onResetMandataireTotp, onSetChallengeGoals, onTraiterParrainage, onSetFactureStatut, onAddVersementParrainage, onApercuPartner, onRestoreMandataire, onUploadReseauLogo, onRemoveReseauLogo, busy }) {
  const COMMERCIAUX = ["Sébastien", ...data.mandataires.filter(m => !m.deleted).map(m => m.name)];
  const parrainagesEnAttente = (data.parrainages || []).filter(x => x.statut === "en_attente").length;
  const facturesEnAttente = data.partners.reduce((s, p) => s + (p.factures || []).filter(f => f.statut === "Déposée").length, 0);
  const actionsPartenaires = parrainagesEnAttente + facturesEnAttente;
  const livePartnerIds = new Set(data.partners.filter(p => !p.deleted).map(p => p.id));
  const liveDossiers = data.dossiers.filter(d => livePartnerIds.has(d.partnerId));
  const [tab, setTabRaw] = useState(() => getStoredTab("adp:adminTab", "accueil"));
  const setTab = (t) => { setTabRaw(t); setStoredTab("adp:adminTab", t); };
  useEffect(() => { if (tab === "mandataires" && !isFullAdmin) setTab("accueil"); }, []);
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
  const [viewingPartnerId, setViewingPartnerId] = useState(null);
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
    <div className="min-h-screen">
      <header className="px-6 py-4 flex items-center justify-between border-b border-gray-100 bg-white">
        <Logo size="text-lg" />
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-500 hidden sm:inline">Connecté : <strong className="fa-navy">{viewerLabel}</strong></span>
          <button onClick={() => downloadJson(`frangola-adp-sauvegarde-${new Date().toISOString().slice(0, 10)}.json`, data)}
            title="Sauvegarder toutes les données (JSON)"
            className="text-gray-400 hover:fa-teal-text transition">
            <Download size={18} />
          </button>
          <button onClick={onLogout} className="text-gray-400 hover:text-red-600"><LogOut size={18} /></button>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        <div className="flex gap-2 mb-8 overflow-x-auto pb-1 -mx-1 px-1 sm:flex-wrap sm:overflow-visible">
          <button onClick={() => setTab("accueil")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "accueil" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <Home size={15} /> Accueil
          </button>
          <button onClick={() => setTab("dossiers")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "dossiers" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <FileText size={15} /> Dossiers
            {newDeposits > 0 && <span className="fa-bg-gold fa-navy text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center">{newDeposits}</span>}
          </button>
          <button onClick={() => setTab("partenaires")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "partenaires" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <Building2 size={15} /> Partenaires
            {actionsPartenaires > 0 && (
              <span className="fa-bg-gold fa-navy text-xs font-bold rounded-full min-w-[20px] h-5 px-1.5 flex items-center justify-center"
                title={[
                  parrainagesEnAttente > 0 ? `${parrainagesEnAttente} déclaration${parrainagesEnAttente > 1 ? "s" : ""} de parrainage à traiter` : null,
                  facturesEnAttente > 0 ? `${facturesEnAttente} facture${facturesEnAttente > 1 ? "s" : ""} à régler` : null,
                ].filter(Boolean).join(" · ")}>
                {actionsPartenaires}
              </span>
            )}
          </button>
          <button onClick={() => setTab("corbeille")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "corbeille" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <Trash2 size={15} /> Corbeille
            {data.partners.filter(p => p.deleted).length > 0 && (
              <span className="bg-gray-200 text-gray-600 text-xs font-bold rounded-full w-5 h-5 flex items-center justify-center">
                {data.partners.filter(p => p.deleted).length}
              </span>
            )}
          </button>
          <button onClick={() => setTab("stats")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "stats" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            <BarChart3 size={15} /> Statistiques
          </button>
                    <button onClick={() => setTab("challenge")}
            className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "challenge" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
            🏆 Challenge
          </button>
          {isFullAdmin && (
            <button onClick={() => setTab("mandataires")}
              className={`flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-full transition whitespace-nowrap shrink-0 ${tab === "mandataires" ? "fa-bg-teal text-white" : "bg-white border border-gray-200 text-gray-600"}`}>
              <Landmark size={15} /> Mandataires
            </button>
          )}
        </div>

        {tab === "accueil" && (() => {
          const priorityItems = liveDossiers
            .map(d => ({ d, reasons: actionReasons(d) }))
            .filter(x => x.reasons.length > 0)
            .sort((a, b) => b.reasons.length - a.reasons.length);
          const now = new Date();
          const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();
          const dossiersActifs = liveDossiers.filter(d => !["KO", "Payé"].includes(d.status)).length;
          const caduMois = liveDossiers.filter(d => d.status === "Payé" && (d.paymentDate ? new Date(d.paymentDate).getTime() : d.updatedAt) >= monthStart).reduce((s, d) => s + (d.caAmount || 0), 0);
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
                  <div className="font-display text-2xl font-bold fa-navy">{dossiersActifs}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Nouveaux dépôts</div>
                  <div className="font-display text-2xl font-bold text-amber-600">{newDeposits}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">CA du mois (encaissé)</div>
                  <div className="font-display text-2xl font-bold text-emerald-600">{fmtEuro(caduMois)}</div>
                </div>
                <div className="bg-white border border-gray-200 rounded-2xl p-5">
                  <div className="text-xs text-gray-400 mb-1">Partenaires actifs</div>
                  <div className="font-display text-2xl font-bold fa-teal-text">{partenairesActifs}</div>
                </div>
              </div>

              {priorityItems.length > 0 ? (
                <div className="border border-red-200 bg-red-50 rounded-2xl p-4">
                  <div className="flex items-center gap-2 font-display font-semibold text-red-800 mb-3">
                    <AlertCircle size={16} /> {priorityItems.length} dossier{priorityItems.length > 1 ? "s" : ""} nécessite{priorityItems.length > 1 ? "nt" : ""} une action
                  </div>
                  <div className="space-y-1.5">
                    {priorityItems.slice(0, 6).map(({ d, reasons }) => (
                      <button key={d.id} onClick={() => { setTab("dossiers"); setDossierSearch(`${d.clientFirstName} ${d.clientLastName}`); }}
                        className="w-full text-left text-sm bg-white hover:bg-red-100/50 border border-red-100 rounded-lg px-3 py-2 transition flex items-center justify-between gap-2 flex-wrap">
                        <span className="fa-navy font-bold">{clientName(d)}</span>
                        <span className="text-red-700 text-xs">{reasons.join(" · ")}</span>
                      </button>
                    ))}
                  </div>
                  {priorityItems.length > 6 && (
                    <button onClick={() => setTab("dossiers")} className="text-xs fa-teal-text hover:underline mt-3">Voir les {priorityItems.length - 6} autres →</button>
                  )}
                </div>
              ) : (
                <div className="text-center text-gray-400 text-sm py-8 border border-dashed border-gray-200 rounded-2xl">
                  ✅ Rien ne nécessite d'action pour l'instant.
                </div>
              )}

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
                                      <span className="font-bold">{p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)}</span>
                                      {p.active === false && <span className="text-xs font-semibold bg-gray-100 text-gray-500 px-2 py-0.5 rounded-full">Inactif</span>}
                                    </div>
                                    <div className="text-xs text-gray-400 flex items-center flex-wrap gap-1.5">{p.company || "—"} {p.ville && `· ${p.ville}`} · Commercial : <span className="text-white text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[p.commercial] || "#999" }}>{commercialLabel(p.commercial) || "—"}</span> · {partnerDossiers.length} dossier{partnerDossiers.length !== 1 ? "s" : ""}</div>
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

            <FacturesPartenaires data={data} onSetStatut={onSetFactureStatut} />

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
                            {p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)}
                            {p.issuDuParrainage && <span className="ml-2 text-xs text-teal-700">issu du parrainage</span>}
                          </div>
                          <div className="text-xs text-gray-400">
                            {p.company || "réseau non précisé"}
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
                <input value={newPartnerSiret} onChange={e => setNewPartnerSiret(e.target.value.replace(/\D/g, "").slice(0, 14))} inputMode="numeric" placeholder="N° SIRET (14 chiffres)"
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
                <select value={newPartnerCommercial} onChange={e => setNewPartnerCommercial(e.target.value)}
                  style={{ backgroundColor: COMMERCIAL_COLORS[newPartnerCommercial], color: "#fff" }}
                  className="border border-gray-300 rounded-lg px-3 py-2 text-sm font-semibold focus:outline-none focus:ring-2 focus:ring-teal-500">
                  {COMMERCIAUX.map(c => <option key={c} value={c} style={{ backgroundColor: COMMERCIAL_COLORS[c], color: "#fff" }}>{commercialLabel(c)}</option>)}
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-600 mb-4">
                <input type="checkbox" checked={newPartnerFlatFee !== ""} onChange={e => setNewPartnerFlatFee(e.target.checked ? "100" : "")}
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
                        <input value={editForm.siret} onChange={e => setEditForm(f => ({ ...f, siret: e.target.value.replace(/\D/g, "").slice(0, 14) }))} inputMode="numeric" placeholder="N° SIRET (14 chiffres)"
                          className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-teal-500" />
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
                              {x.firstName ? `${x.firstName} ${up(x.name)}` : up(x.name)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <label className="flex items-center gap-2 text-sm text-gray-600 mb-3">
                        <input type="checkbox" checked={editForm.flatFee !== ""} onChange={e => setEditForm(f => ({ ...f, flatFee: e.target.checked ? "100" : "" }))}
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
                          <span className="font-bold">{p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)}</span>
                          {p.flatFee != null && <span className="text-xs font-semibold bg-violet-50 text-violet-700 border border-violet-200 px-2 py-0.5 rounded-full">Forfait {p.flatFee}€</span>}
                          {filleulsDe(p.id).length > 0 && (
                            <span className="text-xs font-semibold fa-bg-gold fa-navy px-2 py-0.5 rounded-full"
                              title={"Filleuls : " + filleulsDe(p.id).map(f => f.firstName ? `${f.firstName} ${up(f.name)}` : up(f.name)).join(", ")}>
                              🤝 Parrain de {filleulsDe(p.id).length}
                            </span>
                          )}
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
                          {p.company || "—"} {p.ville && `· ${p.ville}`} {p.departement && `(dép. ${p.departement})`} · Commercial : <span className="text-white text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: COMMERCIAL_COLORS[p.commercial] || "#999" }}>{commercialLabel(p.commercial) || "—"}</span> · depuis le {fmtDate(p.createdAt)}
                          {filleulsDe(p.id).length > 0 && (
                            <span className="w-full text-xs text-teal-700">
                              Filleuls : {filleulsDe(p.id).map(f => f.firstName ? `${f.firstName} ${up(f.name)}` : up(f.name)).join(" · ")}
                            </span>
                          )}
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
                        <BlocAcces cible={p} onReinitialiser={() => reinitialiserAcces("partner", p.id)} />
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
                            <div className="fa-bg-gold rounded-xl p-4 sm:col-span-3"><div className="text-xs text-teal-900/70">Rétrocession totale perçue par ce partenaire</div><div className="font-display text-xl font-bold fa-navy">{fmtEuro(totalCommP)}</div></div>
                          </div>
                        )}

                        {viewingPartnerTab === "dossiers" && (
                          <div className="space-y-2">
                            {pDossiers.length === 0 && <div className="text-sm text-gray-400">Aucun dossier pour ce partenaire.</div>}
                            {pDossiers.sort((a, b) => b.createdAt - a.createdAt).map(d => (
                              <div key={d.id} className="bg-white border border-gray-200 rounded-lg px-3 py-2">
                                <div className="flex items-center justify-between flex-wrap gap-2">
                                  <span className="text-sm fa-navy font-bold">{clientName(d)}</span>
                                  <div className="flex items-center gap-2 text-xs text-gray-500">
                                    <button onClick={() => setAdminExtraDocOpenId(adminExtraDocOpenId === d.id ? null : d.id)}
                                      className="fa-tap text-gray-400 hover:fa-teal-text" title="Déposer des pièces">
                                      <Upload size={13} />
                                    </button>
                                    <StatusBadge status={d.status} />
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
                    <div className="font-medium fa-navy"><span className="font-bold">{p.firstName ? `${p.firstName} ${up(p.name)}` : up(p.name)}</span></div>
                    <div className="text-xs text-gray-400">
                      {p.company || "—"} {p.ville && `· ${p.ville}`} · supprimé le {p.deletedAt ? fmtDate(p.deletedAt) : "—"}
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
            const mandataireCut = caReel / 2;
            const margeFinale = caReel - mandataireCut;
            return { commercial: c, partners: partnersOfC.length, dossiers: dossiers.filter(d => partnersOfC.some(p => p.id === d.partnerId)).length, ca, commission, mandataireCut, margeFinale };
          });

          const topPartners = partners.filter(p => !p.deleted)
            .map(p => ({ partner: p, count: dossiers.filter(d => d.partnerId === p.id).length }))
            .filter(x => x.count > 0)
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);

          const topPartnersByRevenue = partners.filter(p => !p.deleted)
            .map(p => {
              const pd = wonDossiers.filter(d => d.partnerId === p.id);
              return { partner: p, ca: pd.reduce((s, d) => s + (d.caAmount || 0), 0), commission: pd.reduce((s, d) => s + (d.commissionAmount || 0), 0) };
            })
            .filter(x => x.ca > 0 || x.commission > 0)
            .sort((a, b) => b.ca - a.ca)
            .slice(0, 5);

          const STATUS_BAR_COLORS = {
            "Déposé": "#F0C61A", "En vérification": "#0EA5E9", "Devis en cours": "#008BA8",
            "Souscrit": "#10B981", "KO": "#EF4444", "Bordereau émis": "#8B5CF6",
          };

          return (
            <div className="space-y-8">
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
                <div className="grid sm:grid-cols-4 gap-4 mb-5">
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">CA total généré</div>
                    <div className="font-display text-2xl font-bold fa-navy">{fmtEuro(totalCa)}</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Rétrocessions versées</div>
                    <div className="font-display text-2xl font-bold text-violet-600">{fmtEuro(totalCommission)}</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">Marge nette</div>
                    <div className="font-display text-2xl font-bold text-emerald-600">{fmtEuro(totalMarge)}</div>
                  </div>
                  <div className="bg-white border border-gray-200 rounded-2xl p-5">
                    <div className="text-xs text-gray-400 mb-1">CA moyen / dossier payé</div>
                    <div className="font-display text-2xl font-bold fa-teal-text">{fmtEuro(avgCaPerDossier)}</div>
                  </div>
                </div>
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
                          <div className="flex items-center justify-between pl-3 font-semibold text-emerald-700">
                            <span>Marge nette Frangola</span>
                            <span>{fmtEuro(cs.margeFinale)}</span>
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
                        <span className="fa-navy font-bold">{i + 1}. {tp.partner.firstName ? `${tp.partner.firstName} ${up(tp.partner.name)}` : up(tp.partner.name)}</span>
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
                      <span className="fa-navy font-bold">{i + 1}. {tp.partner.firstName ? `${tp.partner.firstName} ${up(tp.partner.name)}` : up(tp.partner.name)}</span>
                      <span className="text-gray-500 text-xs">CA {fmtEuro(tp.ca)} · Rétro {fmtEuro(tp.commission)}</span>
                    </div>
                  ))}
                </div>
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
                        <div className="font-display text-lg font-bold fa-navy">{fmtEuro(coutTotal)}</div>
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
                                {i + 1}. {x.p.firstName ? `${x.p.firstName} ${up(x.p.name)}` : up(x.p.name)}
                              </span>
                              <span className="text-xs text-gray-500">
                                {x.filleuls.length} filleul{x.filleuls.length > 1 ? "s" : ""} · {x.actifs} actif{x.actifs > 1 ? "s" : ""} · CA {fmtEuro(x.caTotal)} · prime {fmtEuro(x.gainTotal)}
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

              <VersementsParrainage data={data} onAddVersement={onAddVersementParrainage} />
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

              {tab === "challenge" && (
          <ChallengeBoard data={data} commerciaux={COMMERCIAUX}
            onSetGoals={onSetChallengeGoals} canEdit={isFullAdmin} />
        )}
        {tab === "mandataires" && isFullAdmin && (
          <div>
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
                          <BlocAcces cible={m} onReinitialiser={() => reinitialiserAcces("mandataire", m.id)} />
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
