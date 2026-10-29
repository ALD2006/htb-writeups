# HTB — Cap (Easy, Linux)

> Première box après le Starting Point, rootée en solo (aucune indication demandée jusqu'au foothold). Chaîne courte et élégante : **IDOR** sur un dashboard web → **capture réseau (pcap) avec des creds FTP en clair** → SSH → **privesc par Linux Capability (`cap_setuid` sur python)**.
>
> Payloads défangés : reverse shell en `/dev/tcp/<tun0>/...`. Remettre de vraies valeurs pour rejouer.

- **Flags :** user + root obtenus (non publiés).
- **IP box :** change à chaque reset/restart. **Mon tun0 :** `10.10.x.x`.
- **Techniques :** recon `-Pn` (ICMP filtré) · IDOR (`/data/<id>`, `/download/<id>`) · analyse pcap Wireshark (FTP en clair) · réutilisation de creds → SSH · Linux Capabilities (`getcap` → `cap_setuid` sur `/usr/bin/python3.8`) → root.

---

## 1. Recon — deux leçons avant même le premier port

### 1.1 L'hôte « seems down » → `-Pn`
```bash
nmap 10.129.x.x                 # → "Host seems down"
nmap -Pn 10.129.x.x             # → host up, on scanne
```
`nmap` fait d'abord un ping ICMP pour décider si l'hôte est vivant. Beaucoup de cibles **bloquent l'ICMP** → nmap conclut « down » à tort. `-Pn` = « considère l'hôte up, saute le ping » et scanne quand même. Réflexe : un « host seems down » ne veut PAS dire éteint — d'abord `-Pn`.

### 1.2 Piège : reset/restart = nouvelle IP
Après un restart, plus rien ne répondait — parce que je pinguais l'ANCIENNE IP. Le `Destination Host Unreachable` venait de la passerelle VPN elle-même, pas de la cible → signe que le serveur VPN n'a aucune route vers l'IP visée (fantôme). Après un reset/spawn : re-copier l'IP courante et laisser 1–3 min de boot.

### 1.3 Les ports
```bash
nmap -sV -sC -Pn <IP>
```
**21** FTP · **22** SSH · **80** HTTP (une appli web). Tout se joue sur le 80.

---

## 2. Foothold — IDOR sur le dashboard → pcap → creds FTP

### 2.1 L'appli
Un dashboard de « sécurité réseau » (Flask) : *Security Snapshot* (capture de trafic), *IP Config* (`ifconfig`), *Network Status* (`netstat`). Les pages `netstat`/`ifconfig` = du bruit (dumps de commandes). Le cœur est ailleurs.

### 2.2 L'IDOR — le numéro dans l'URL
La fonction de capture (`/capture`) enregistre un fichier `<id>.pcap` et redirige vers `/data/<id>` (ex. `/data/5`). Deux routes exposent ce fichier par un simple entier, sans aucun contrôle d'accès :
```
/data/<id>       → stats du pcap n°<id>
/download/<id>   → TÉLÉCHARGE le pcap n°<id>
```
La question qui ouvre la box : « c'est quoi le numéro dans l'URL… et si je le changeais ? » Ma capture était `/data/5` → j'ai testé `/data/0` (le tout premier pcap, généré par quelqu'un d'autre avant moi). `/download/0` me le livre.

C'est un **IDOR** (*Insecure Direct Object Reference*) = **A01 Broken Access Control** : l'objet est référencé directement par un id devinable, sans vérifier que j'ai le droit de le voir.

### 2.3 Wireshark → FTP en clair
J'ouvre `0.pcap` dans Wireshark. Le FTP ne chiffre rien → login/mot de passe en clair dans les paquets `USER`/`PASS` :
```
Follow → TCP Stream (ou filtre: ftp)
USER nathan
PASS <mot_de_passe_en_clair>
```
Leçon : protocoles en clair (FTP, HTTP, Telnet) = tout transite lisible. Une simple capture = des creds.

### 2.4 User flag
Les creds sont réutilisés pour SSH :
```bash
ssh nathan@<IP>
cat ~/user.txt
```
Réutilisation de creds (fil rouge récurrent) : les mêmes creds FTP marchent en SSH.

---

## 3. Le chemin qui a échoué (et pourquoi il m'a donné la clé du bon)

Je le garde exprès : l'échec n'était pas une perte de temps, il m'a montré le vecteur.

L'appli tourne dans `/var/www/html/app.py`. En la lisant, je vois la route `/capture` faire :
```python
command = f"""python3 -c 'import os; os.setuid(0); os.system("timeout 5 tcpdump ...")'"""
```
Le code appelle `os.setuid(0)` — donc il devient root. Mon idée : modifier `app.py` pour injecter un reverse shell dans une route, en espérant que le service tourne en root. Deux murs :
1. J'ai failli écrire `os.system(bash -i >& ...)` **sans quotes** → ce n'est pas du Python valide (SyntaxError). `os.system()` attend une **chaîne**.
2. Le vrai blocage : pour que mon code tourne, il faut recharger le service (gunicorn ne relit pas `app.py` tout seul). Or `nathan` n'est pas sudoer (`sudo -l` le confirme) et ne peut pas redémarrer gunicorn → problème de l'œuf et de la poule.

Mais en lisant `app.py` pour ce plan raté, j'ai retenu le vrai indice : *pourquoi un simple user arrive-t-il à faire `os.setuid(0)` ?* Normalement `setuid(0)` exige déjà d'être root. Ce python a donc un super-pouvoir spécial → direction `getcap`. Un exploit qui rate n'est pas la fin — c'est un indice ; lis ce qu'il t'a montré au passage.

---

## 4. Privesc — Linux Capability `cap_setuid` sur python

### 4.1 Débusquer (linpeas)
Transfert de linpeas (`python3 -m http.server 8000` côté Kali → `wget` côté cible). La section capabilities crache le trésor :
```
Files with capabilities:
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```
On peut le trouver directement à la main :
```bash
getcap -r / 2>/dev/null
```

### 4.2 Comprendre — pourquoi c'est root
Les Linux Capabilities découpent les pouvoirs de root en petits morceaux qu'on peut coller à un binaire sans le mettre SUID.
- `cap_setuid` = ce binaire peut appeler `setuid()` vers n'importe quel UID (y compris 0 = root) sans être root au départ.
- `+eip` = capability effective / héritable / permise → active immédiatement.

Donc `python3.8` peut légitimement se transformer en root. Et j'avais déjà lu le mode d'emploi dans `app.py` (le `os.setuid(0)` de la route `/capture`).

### 4.3 Le coup de grâce
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id                     # → uid=0(root)
cat /root/root.txt
```
Détail : le shell affiche `uid=0(root) gid=1001(nathan)` — j'ai pris l'UID root (`setuid`) mais pas le GID (pas de `setgid`). Suffisant pour lire `root.txt` et être root effectif. Pour un GID root aussi : ajouter `os.setgid(0)` avant. Pas besoin de toucher à la page web : le vecteur propre était le `getcap`.

---

## 5. Leçons-clés

- **Un exploit qui rate = un indice.** Le plan « modifier `app.py` » était bloqué, mais la lecture du code a livré le vecteur (`os.setuid(0)` → *pourquoi ?* → capabilities).
- **Linux Capabilities = SUID en plus fin.** `getcap -r / 2>/dev/null`. `cap_setuid` sur un interpréteur (python/perl/ruby) = root trivial : `setuid(0)` puis un shell.
- **IDOR / A01** : un objet référencé par un entier devinable sans contrôle d'accès = je lis les données des autres. « C'est quoi le numéro dans l'URL ? »
- **Protocoles en clair (FTP)** : une capture réseau = des creds. Wireshark → *Follow TCP Stream*.
- **Réutilisation de creds** : FTP → SSH.
- **Recon** : `Host seems down` → `-Pn` (ICMP filtré ≠ éteint). Reset/restart = nouvelle IP.
- **`os.system()` attend une chaîne** : un reverse shell s'y met entre quotes.

---

## 6. Défense (réflexe purple)

- **IDOR / Broken Access Control** : ne jamais exposer un objet par un id direct sans vérifier le droit d'accès de l'appelant. Parade : session liée au fichier, ownership vérifié côté serveur (`check_object_permissions`-style), ids non devinables (UUID), isolation fail-closed testée.
- **Moindre privilège / capabilities** : donner `cap_setuid` à un interpréteur générique = catastrophe (n'importe quel script devient root). Isoler le besoin réel (binaire dédié minimal, `cap_net_raw` sur `tcpdump` uniquement — pas `cap_setuid` sur python). Auditer : `getcap -r / 2>/dev/null`.
- **Ne pas faire tourner un service web en root** (ni lui prêter des pouvoirs root). Le `os.setuid(0)` dans le code applicatif = anti-pattern.
- **Chiffrer les protocoles** : FTP → SFTP/FTPS ; jamais de creds sur un canal en clair. TLS partout.
