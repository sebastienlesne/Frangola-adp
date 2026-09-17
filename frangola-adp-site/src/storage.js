import { supabase } from "./supabaseClient";

/**
 * Remplace l'ancien window.storage (spécifique aux artefacts Claude) par
 * une implémentation identique en façade, mais qui persiste réellement les
 * données dans Supabase (table kv_store). Le reste de l'app (App.jsx) n'a
 * pas eu besoin d'être modifié au-delà de "window.storage" -> "storage".
 */
export const storage = {
  async get(key) {
    const { data, error } = await supabase
      .from("kv_store")
      .select("value")
      .eq("key", key)
      .maybeSingle();

    if (error) throw error;
    if (!data) return null;
    return { key, value: data.value, shared: true };
  },

  async set(key, value) {
    const { error } = await supabase
      .from("kv_store")
      .upsert({ key, value, updated_at: new Date().toISOString() }, { onConflict: "key" });

    if (error) throw error;
    return { key, value, shared: true };
  },
};
