# htb-writeups

Writeups de machines **retirées** (HackTheBox Starting Point / retired) et de labs publics (PortSwigger Web Security Academy). Notes personnelles d'apprentissage, en français, rédigées en condition solo (sans guide quand c'est indiqué).

Chaque machine suit la même trame : recon → foothold → post-exploitation → élévation de privilèges → leçons → défense (réflexe purple-team).

## Writeups

| Machine | Plateforme | Thème principal |
|---|---|---|
| [Three & Vaccine](three-vaccine.md) | HTB Starting Point (T1/T2) | vhost + bucket S3 → webshell ; FTP → zip → SQLi PostgreSQL → `sudo vi` (GTFOBins) |
| [Oopsie & Archetype](oopsie-archetype.md) | HTB Starting Point (T2) | cookie forgé + PATH hijacking (SUID) ; SMB anonyme → MSSQL `xp_cmdshell` → cradle PowerShell → psexec |
| [Unified](unified.md) | HTB Starting Point (T2) | Log4Shell + contournement `trustURLCodebase` (rogue-jndi) ; MongoDB sans auth (write) |
| [Cap](cap.md) | HTB (retired, Easy) | IDOR → pcap (FTP en clair) → Linux Capability `cap_setuid` |
| [Désérialisation (fondations)](deserialisation-portswigger.md) | PortSwigger | désérialisation PHP & Java (ysoserial / Apache Commons) |

## Conventions

- **Flags retirés** : aucun flag (user/root) n'est publié.
- **Payloads défangés** : `·` = caractère à retirer, `hxxp` = `http` ; IP/ports en placeholders (`<IP>`, `<tun0>`). Remettre de vraies valeurs pour rejouer.
- **Machines actives exclues** : par respect des CGU HackTheBox, seules des machines retirées / Starting Point / labs publics figurent ici.
- **Dépôt évolutif** : d'autres machines, aujourd'hui actives et donc non publiables, viendront s'ajouter au fil du temps — dès leur mise en retraite par HackTheBox.

## Règle légale

N'attaquer QUE ses propres machines, un lab, ou une cible explicitement autorisée (TryHackMe, HackTheBox, PortSwigger). Ces notes sont destinées à l'apprentissage et au test autorisé uniquement.

## Licence

[CC BY 4.0](LICENSE) — réutilisation libre avec attribution.
