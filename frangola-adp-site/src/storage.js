import { supabase } from "./supabaseClient";

/**
 * Façade de stockage clé/valeur au-dessus de la table Supabase kv_store.
 *
 * Ajouts par rapport à la version précédente :
 *   - list(prefix) : indispensable aux sauvegardes automatiques, qui
 *     l'appelaient sans qu'elle existe — aucune sauvegarde n'était créée.
 *   - delete(key)  : même chose, pour la purge des sauvegardes anciennes.
 *
 * Les préfixes utilisés par l'application ne contiennent ni % ni _,
 * les deux caractères joker de SQL LIKE.
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

  /**
   * Renvoie les clés commençant par `prefix`, sans charger les valeurs :
   * une sauvegarde pèse plusieurs mégaoctets, on ne les rapatrie pas
   * seulement pour dresser une liste.
   */
  async list(prefix = "") {
    let requete = supabase.from("kv_store").select("key");
    if (prefix) requete = requete.like("key", `${prefix}%`);

    const { data, error } = await requete;
    if (error) throw error;
    return { keys: (data || []).map(r => r.key) };
  },

  async delete(key) {
    const { error } = await supabase.from("kv_store").delete().eq("key", key);
    if (error) throw error;
    return { key, deleted: true };
  },
};
