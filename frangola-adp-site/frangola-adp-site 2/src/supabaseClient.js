import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  // eslint-disable-next-line no-console
  console.error(
    "Variables Supabase manquantes. Vérifie que VITE_SUPABASE_URL et VITE_SUPABASE_ANON_KEY sont définies (fichier .env en local, ou variables d'environnement sur Vercel)."
  );
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
