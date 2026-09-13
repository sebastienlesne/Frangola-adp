# FRANGOLA ADP — site autonome

Ce dossier contient exactement la même application (même design, mêmes couleurs,
même police, mêmes fonctionnalités) que celle utilisée jusqu'ici dans Claude,
mais reconfigurée pour être hébergée sur un vrai site, avec une vraie base de
données (Supabase) à la place du stockage propre à Claude.

## 1. Créer le projet Supabase (gratuit)

1. Va sur https://supabase.com, crée un compte, puis "New project"
2. Une fois le projet créé, va dans **SQL Editor** et colle ceci, puis exécute :

```sql
create table kv_store (
  key text primary key,
  value text,
  updated_at timestamptz default now()
);

alter table kv_store enable row level security;

create policy "allow all access"
on kv_store
for all
using (true)
with check (true);
```

3. Va dans **Project Settings > API**. Tu y trouveras :
   - **Project URL** → à mettre dans `VITE_SUPABASE_URL`
   - **anon public key** → à mettre dans `VITE_SUPABASE_ANON_KEY`

⚠️ **Point de sécurité important à comprendre** : la policy ci-dessus autorise
n'importe qui possédant la clé "anon" (visible dans le code du site une fois
en ligne, ce n'est pas un secret) à lire et écrire dans cette table. C'est
volontairement permissif pour que l'app fonctionne telle quelle — la
protection réelle reste les codes d'accès partenaires et les identifiants
admin dans l'app elle-même, pas la base de données. Si tu veux un jour une
vraie sécurité côté base de données (RLS plus stricte, authentification
Supabase), ce sera une étape supplémentaire à prévoir.

## 2. Tester en local (optionnel mais recommandé)

```bash
npm install
cp .env.example .env
# remplis .env avec tes vraies valeurs Supabase
npm run dev
```

Le site s'ouvre sur http://localhost:5173

## 3. Mettre le code sur GitHub

1. Crée un compte GitHub si tu n'en as pas (https://github.com)
2. Crée un nouveau dépôt (repository), par exemple `frangola-adp`
3. Dépose tous les fichiers de ce dossier dedans (tu peux glisser-déposer
   directement sur la page du dépôt GitHub, ou utiliser `git push` si tu es
   à l'aise avec)

## 4. Héberger sur Vercel (gratuit)

1. Va sur https://vercel.com, connecte-toi avec ton compte GitHub
2. "Add New Project" → sélectionne ton dépôt `frangola-adp`
3. Vercel détecte automatiquement que c'est un projet Vite — ne change rien
4. Avant de cliquer sur "Deploy", ouvre la section **Environment Variables**
   et ajoute les deux mêmes valeurs que dans ton `.env` :
   - `VITE_SUPABASE_URL`
   - `VITE_SUPABASE_ANON_KEY`
5. Clique sur "Deploy"

Une fois déployé, Vercel te donne une adresse (ex. `frangola-adp.vercel.app`).
Tu pourras ensuite lui associer ton propre nom de domaine si tu en as un.

## 5. Mettre à jour le site plus tard

À chaque fois que tu (ou moi) modifie le code et le dépose sur GitHub, Vercel
redéploie automatiquement le site en 1 à 2 minutes, sans rien à faire de ton
côté. C'est exactement le fonctionnement "mise à jour simple, sans bug de
déploiement" que tu recherchais.

## Ce qui change par rapport à la version Claude, et ce qui ne change pas

- **Ne change pas** : le design (couleurs, police Fredoka/Nunito), toutes les
  fonctionnalités (dossiers, partenaires, statistiques, rémunération, etc.)
- **Change** : les données sont maintenant stockées dans Supabase au lieu du
  stockage de l'artefact Claude — c'est ce qui permet au site de fonctionner
  de façon autonome, en dehors de Claude
