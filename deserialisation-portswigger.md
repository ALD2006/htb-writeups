# Fondations — Désérialisation (PortSwigger Web Security Academy)

> Détour de fondations pour démystifier la désérialisation de zéro, dans l'ordre PHP (lisible) → Java (binaire, ysoserial). But : transformer une théorie floue (POP chain → RCE) en geste concret.
>
> Payloads défangés : `·` = caractère à retirer, `hxxp` = http. Ici surtout des objets sérialisés PHP (inertes) + un gabarit ysoserial.

- **Plateforme :** PortSwigger Web Security Academy (compte gratuit + Burp Community).
- **Résultat :** 5/5 labs — 4 PHP + 1 Java (Apache Commons / ysoserial).
- **Méthode :** lire l'article AVANT → faire le lab → reformuler avec mes mots (pas copier la solution). Comprendre > copier.

---

## 0. Le modèle mental (à graver, il traverse tous les langages)

> Reconstruire un objet, ce n'est pas inerte — ça déclenche du code.

L'attaquant n'injecte pas du code ; il injecte un objet (ou un graphe d'objets) bien formé, et c'est le langage lui-même qui, en le reconstruisant, appelle automatiquement certaines méthodes magiques (`__wakeup`/`__destruct` en PHP, `readObject` en Java). Bug LOGIQUE, pas mémoire (le durcissement mémoire — canari/ASLR — n'y peut rien).

Deux règles-filles essentielles :
1. **On ne peut pas inventer une classe.** Pour reconstruire l'objet, le serveur doit connaître la classe → son code doit déjà exister sur la cible (classpath). D'où **gadget** = une classe légitime déjà là, qu'on détourne. On contrôle la DONNÉE (les champs), jamais le CODE.
2. **La désérialisation NE rappelle PAS le constructeur.** Elle restaure les champs en direct depuis le blob → c'est ce qui permet de contourner la logique d'un `__construct`.

---

## 1. Les 4 barreaux PHP (format lisible : on VOIT l'objet)

Rappel de lecture du format sérialisé PHP : chaque jeton annonce type + taille.
`O:4:"User":2:{...}` = Objet classe "User" (nom long de 4) à 2 propriétés · `s:6:"wiener"` = string longueur 6 · `b:0` = booléen false · `i:0` = entier 0. Propriétés par paires `nom;valeur;`.

| # | Lab | Mécanique | Leçon |
|---|---|---|---|
| 1 | Modifying serialized objects | flip `admin` : `b:0` → `b:1` | le serveur croit le blob sur parole |
| 2 | Modifying serialized data types | `access_token` string → entier `i:0` + `username`→`administrator` | **type juggling** `==` : en PHP `0 == "chaîne non-numérique"` → true ; `===` l'aurait tué. On change le TYPE, pas que la valeur |
| 3 | Using application functionality | `avatar_link` → `/home/carlos/morale.txt` puis "Delete account" | on détourne une fonctionnalité légitime via un champ contrôlé — pas encore un vrai gadget |
| 4 | Arbitrary object injection | injecter un objet `CustomTemplate` (pas `User`) dont `__destruct` fait `unlink($this->lock_file_path)` | 1er vrai gadget : détonateur + sink + champ contrôlé |

### Pièges PHP rencontrés
- **Le compteur de longueur mord 3 fois** : toute string modifiée → recompter le `s:<len>` ou PHP recrache l'objet. Astuce = compter par segments (`/home/`=6, `carlos/`=7, `morale.txt`=10 → 23).
- **Chemin absolu** : `home/carlos/...` (relatif) ≠ `/home/carlos/...` (absolu) — le `/` initial change tout et la longueur.
- **Lab 4 — la clé** : `__construct` mettrait `lock_file_path = ... . ".lock"`, mais la deser ne l'appelle pas → on écrit `lock_file_path` direct sur la cible voulue, sans suffixe `.lock`.
- **Divulgation de source** : commentaire HTML `<!-- ... /libs/CustomTemplate.php ... -->` → lire la source (pas l'exécuter) via la copie de sauvegarde `fichier.php~`.
- **Propriété `private`** : se sérialise avec des octets nuls (`\0Classe\0champ`) — ici le nom simple a suffi.

---

## 2. Le keystone — Java / Apache Commons / ysoserial

Lab : « Exploiting Java deserialization with Apache Commons ». Format Java = binaire (`AC ED 00 05`) → impossible à taper à la main → ysoserial forge la chaîne.

### La gadget chain « N maillons »
`readObject` ne supprime rien lui-même → `PriorityQueue` → `TransformingComparator` → `ChainedTransformer` → … → `TemplatesImpl` (charge du bytecode) → `Runtime.exec()`. C'est la vraie POP chain (poupée russe), en Java.

> Pourquoi l'énoncé précise « charge Apache Commons Collections » : ça dit que les classes-gadgets sont sur le classpath → la chaîne `CommonsCollections4` trouvera ses maillons. Même règle qu'au lab 4 (la classe doit exister), mais à l'échelle d'une lib. Si c'était XStream chargé, il faudrait un gadget XStream.

### Le flux
```bash
# Défangé — syntaxe exacte prise de la page du lab.
java <--add-opens...> -jar ysoserial-all.jar CommonsCollections4 '<cmd>' | base64 -w 0
#   → objet binaire → base64 UNE ligne → cookie "session" (ou param) → recharge → readObject → Runtime.exec
```

### Les 5 cicatrices utiles (le vrai butin du jour)
| Piège | Leçon gravée |
|---|---|
| `java.lang.IllegalAccessError` (module `java.xml`) | JDK moderne verrouille les internes → `--add-opens=java.xml/...=ALL-UNNAMED` (×4) pour qu'ysoserial accède à `TemplatesImpl` |
| 1 octet retourné dans mon blob (`com/sun` → `com.sun`) | on ne recopie JAMAIS un blob sérialisé à la main — 1 caractère = gadget mort, échec silencieux côté serveur |
| « la page a l'air pareille » | lire le STATUT HTTP, pas le rendu : 302/500 = objet traité (chaîne a tiré) ; 200 normal = pas désérialisé |
| `curl -b 'rO0...'` → `302 /login`, aucun cookie | `curl -b` sans `=` littéral = nom de FICHIER → il faut `session=<blob>`. (Un blob url-encodé n'a plus de `=` → curl le prend pour un fichier.) |
| base64 brut cassé dans le cookie | le serveur url-décode le cookie → un `+` devient espace → base64 mort → url-encoder (`+`→`%2B`, `/`→`%2F`, `=`→`%3D`) |
| sortie base64 sur plusieurs lignes | cookie corrompu → `base64 -w 0` (une ligne) dès la génération, jamais nettoyer à la main |

---

## 3. Leçons-mères de la séance
- **Deser = reconstruire un objet déclenche du code** ; on contrôle la donnée, pas le code ; le gadget est une classe déjà présente.
- **La deser ne rappelle pas le constructeur** (restaure les champs direct).
- **Debugger, c'est lire les signaux** : statut HTTP (302/500), erreurs de module Java, format du cookie — pas le rendu de la page.
- **On ne recopie pas un blob binaire** — on le génère propre à la source (`-w 0`).
- **Jugement de périmètre** : « créer son propre gadget chain » et « PHAR » (niche PHP) ont été écartés volontairement — hors-périmètre du but du jour. Deux objectifs à la fois = zéro objectif.

> Pont purple : la racine de TOUTES ces failles = désérialiser une donnée non fiable. Parade de fond : ne jamais désérialiser d'entrée non fiable ; si inévitable (file d'attente, cache sérialisé) → liste blanche de classes (`ObjectInputFilter` / `ValidatingObjectInputStream`) obligatoire.
