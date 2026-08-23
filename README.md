# Update Monitor

Surveille et met à jour un nombre arbitraire de machines Debian/Ubuntu
via SSH. **Tout se gère depuis l'interface web** : ajout/suppression de
hosts, webhook Discord, planning des vérifications automatiques, et
déclenchement manuel de vérifications ou de vraies mises à jour (`apt
upgrade`).

## Pages

- **Dashboard** (`/`) : statut de chaque host (à jour / N mises à
  jour / erreur), détail des paquets, log de la dernière mise à jour,
  boutons "Vérifier" et "Mettre à jour" par host, + un bouton global
  pour mettre à jour tous les hosts en attente.
- **Hosts** (`/hosts`) : ajoute, modifie ou supprime des machines.
  Aucune limite de nombre — le formulaire écrit directement en base.
- **Réglages** (`/settings`) : webhook Discord, planning cron des
  vérifications automatiques, timeout SSH.

## Prérequis sur chaque machine surveillée

**Si tu connectes le host en `root`** : aucune config sudoers requise,
l'app détecte automatiquement l'utilisateur `root` et lance les
commandes `apt-get` directement, sans `sudo`.

**Si tu connectes le host avec un utilisateur non-root**, il doit
pouvoir lancer `apt-get update` et `apt-get upgrade` en sudo **sans
mot de passe** (sinon la vérification et la mise à jour échoueront
silencieusement côté SSH). Sur chaque host cible :

```bash
sudo visudo -f /etc/sudoers.d/update-monitor
```
Ajoute (remplace `DEFAULTUSER` par l'utilisateur SSH que tu vas déclarer dans
l'interface) :
```
DEFAULTUSER ALL=(ALL) NOPASSWD: /usr/bin/apt-get update, /usr/bin/apt-get upgrade
```

Génère une clé SSH dédiée si tu n'en as pas déjà une, et déploie la
clé publique sur chaque host (`ssh-copy-id`). L'authentification par
clé est recommandée ; le mot de passe SSH est supporté mais stocké en
clair dans la base SQLite locale (acceptable pour un homelab, à éviter
si le conteneur est exposé au-delà de ton réseau).

## Installation

```bash
git clone <ce projet> update-monitor
cd update-monitor
mkdir -p keys data
cp ~/.ssh/id_rsa keys/id_rsa   # clé privée dédiée au monitoring
docker compose up -d --build
```

Ouvre `http://<ip-du-serveur>:5000`, va dans **Hosts** et ajoute tes
machines. Si tu utilises l'authentification par clé, le chemin par
défaut proposé (`/app/keys/id_rsa`) correspond au montage du
`docker-compose.yml` fourni — laisse-le tel quel si tu n'as qu'une clé
pour tout le parc.

## Planification

`schedule_cron` (page Réglages) utilise une syntaxe cron standard
(`minute heure jour mois jour_semaine`). Exemple : `0 8 * * *` = tous
les jours à 8h. Le changement est appliqué immédiatement, pas besoin
de redémarrer le conteneur.

## Mise à jour manuelle

Le bouton "Mettre à jour" sur un host ouvre une **console live** qui
affiche la sortie SSH en temps réel (téléchargement des paquets,
installation, etc.) au fur et à mesure, plutôt que d'attendre la fin
pour tout afficher d'un coup. Une confirmation est demandée avant
exécution. À la fin, la console indique le code de sortie et relance
automatiquement une vérification pour rafraîchir le compteur ; ferme
la fenêtre pour recharger la page. Le log complet reste aussi
consultable après coup sur le dashboard ("Log").

Le bouton global "Mettre à jour les hosts en attente" (opération
groupée) n'a pas de console live — il attend simplement la fin de
toutes les mises à jour puis recharge la page.

Selon le nombre de paquets à installer, l'opération peut prendre
plusieurs minutes.

## Notification Discord

- "Ne notifier Discord que s'il y a des mises à jour" (activé par
  défaut) : le webhook n'est appelé que si au moins un host a des
  mises à jour en attente.
- Les messages sont automatiquement découpés s'ils dépassent la
  limite de 2000 caractères de Discord.

## Gestionnaires de paquets supportés

Choisi par host dans le formulaire d'ajout/édition (**APT** par défaut) :

| Gestionnaire | Distributions |
|---|---|
| **APT** (défaut) | Debian, Ubuntu, Raspbian, Mint... |
| **APK** | Alpine Linux |
| **DNF** | Fedora, RHEL 8+, CentOS Stream |
| **YUM** | RHEL / CentOS 7 |
| **Pacman** | Arch Linux, Manjaro |
| **Zypper** | openSUSE |

Le filtre "sécurité uniquement" ne fonctionne de façon fiable que pour
APT (il se base sur le nom du dépôt `-security`). Pour les autres
gestionnaires, la case n'a pour l'instant aucun effet.

Le parsing de la sortie (comptage/liste des paquets) pour DNF/YUM,
Pacman et Zypper est basé sur le format habituel de ces outils — si ta
distribution renvoie un format légèrement différent, le comptage peut
être imprécis ; APT et APK sont les plus éprouvés.

## Limites connues

- Ne surveille pas les mises à jour de conteneurs Docker — utilise
  **Diun** pour ça, en complément.
- Les mots de passe SSH stockés en base ne sont pas chiffrés.
