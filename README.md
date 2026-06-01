# Analyse d’app APK Android — Rapport de TP

---

## À quoi sert ce TP

Les applications mobiles sont distribuées sous forme de paquets `.apk`. Même sans les exécuter, on peut déjà apprendre beaucoup en disséquant le contenu du fichier. Ce rapport retrace l’ensemble de la démarche suivie : préparation d’un environnement contrôlé, décompilation du bytecode Java, puis consignation de chaque constat lié à la sécurité.

Pas d’émulateur. Pas de terminal sur appareil. Analyse statique uniquement.

---

## Outils utilisés

| Outil | Rôle |
|------|------|
| PowerShell | Inspection de fichiers, calcul de hachage, lecture ZIP |
| JADX GUI | Décompilation d’APK et analyse du manifeste |
| dex2jar | Conversion du Dalvik vers un JAR Java |
| JD-GUI | Exploration du code source Java à partir du JAR converti |

---

## Étape 1 — Construire l’environnement du TP

J’ai commencé par créer un dossier dédié dans `C:\APK-Analysis` et y déposer l’APK. Travailler dans un répertoire isolé permet de garder les artefacts forensiques séparés du reste du système : c’est une habitude simple, mais importante.

**Vérifier que le fichier correspond bien à ce qu’il annonce**

Un APK est un fichier ZIP avec une extension différente. La vérification la plus rapide consiste à examiner les octets magiques au début (offset 0). Un ZIP valide commence toujours par `50 4B` en hexadécimal, ce qui correspond à `PK` en ASCII — la signature laissée par Phil Katz lors de la création du format.

J’ai lancé un dump hexadécimal via PowerShell et confirmé que l’en-tête était conforme. Capture ci-dessous :

<img width="1200" height="279" alt="Screenshot 2026-03-04 152123" src="https://github.com/user-attachments/assets/4c683637-3b42-46e0-986b-d54d6c1012e8" />

**Accéder au contenu sans extraire**

En s’appuyant directement sur l’API `System.IO.Compression.ZipFile` dans PowerShell, j’ai listé les 20 premières entrées sans toucher au disque.

```
AndroidManifest.xml
META-INF/CERT.RSA
META-INF/CERT.SF
META-INF/MANIFEST.MF
classes.dex
res/layout/activity_main.xml
res/menu/menu_main.xml
res/mipmap-*/ic_launcher.png  (plusieurs densités)
resources.arsc
```

**Calcul du hachage**

Avant d’aller plus loin, j’ai “figé” une empreinte SHA-256. Ainsi, si quoi que ce soit change pendant le TP, le hachage permettra de le détecter.

```
SHA-256: 1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21
```

<img width="1727" height="636" alt="Screenshot 2026-03-04 153134" src="https://github.com/user-attachments/assets/a7fa60b4-dcd5-4cd3-9c7c-a798815aebfa" />

---

## Étape 2 — Vérifier l’acquisition de l’APK

Petit contrôle de bon sens avant de continuer. Le fichier se trouvait dans `C:\APK-Analysis`, daté du 3/4/2026, et faisait exactement 66 Ko (66,651 octets).

Source : OWASP Mobile Security Testing Guide — UnCrackable Level 1. Il s’agit d’une application volontairement vulnérable, conçue pour l’entraînement à la sécurité.

<img width="1379" height="552" alt="Screenshot 2026-03-04 151740" src="https://github.com/user-attachments/assets/171a216a-ab28-47cb-a78a-9e0775c6e698" />

---

## Étape 3 — Décrypter le manifeste

Le `AndroidManifest.xml` est le premier fichier que je consulte systématiquement. C’est la “carte d’identité” de l’application : nom de package, SDK ciblés, composants déclarés, permissions, et indicateurs de sécurité. C’est aussi le document dont Android a besoin avant même de lancer l’application.

J’ai ouvert l’APK dans l’interface JADX et navigué directement vers le manifeste.

**Identité du package**

```xml
package="owasp.mstg.uncrackable1"
android:versionName="1.0"
android:minSdkVersion="19"
android:targetSdkVersion="28"
```

Donc l’app supporte des versions à partir d’Android 4.4 KitKat et adopte le comportement “cible” d’Android 9 Pie.

**Permissions**

Aucune. Pas une seule balise `<uses-permission>` n’apparaît. L’app ne demande ni caméra, ni localisation, ni contacts, ni stockage — rien. C’est plutôt atypique, mais pas forcément suspect : pour un défi d’entraînement, ça peut correspondre au scénario.

**Composants et surface d’attaque**

Un seul `Activity` est déclarée :

```
sg.vantagepoint.uncrackable1.MainActivity
```

Elle contient un `<intent-filter>` avec `android.intent.action.MAIN` et `android.intent.category.LAUNCHER`. En conséquence, Android considère cette Activity comme “implicitement exportée”, ce qui signifie que d’autres applications peuvent lui envoyer des intents directement.

**Drapeaux de sécurité à surveiller**

- `android:debuggable` — non défini → ✅ plutôt bon
- `android:usesCleartextTraffic` — non défini → ✅ plutôt bon  
- `android:allowBackup="true"` — **présent** → ⚠️ risque

C’est le paramètre `allowBackup` qui ressort. Avec `allowBackup` activé, n’importe quel utilisateur ayant un accès ADB peut extraire le dossier de données privées de l’app sans avoir besoin d’être root.

```bash
adb backup -noapk owasp.mstg.uncrackable1
```

Pour un TP, c’est acceptable. En production, cela devient un vecteur de fuite de données.

<img width="1321" height="739" alt="Screenshot 2026-03-04 153629" src="https://github.com/user-attachments/assets/fad9229f-ed0a-495e-9c91-6ae231e8adb2" />

---

## Étape 4 — Rechercher des secrets codés en dur

Il arrive que des chaînes sensibles soient “bâtonnées” dans le binaire : clés API, tokens, URL internes, identifiants de test. Grâce à la recherche texte de JADX, on inspecte simultanément classes, méthodes, champs, ressources et commentaires.

**Recherche #1 — "http"**

Trois occurrences, toutes liées à la même chose.

```
http://schemas.android.com/apk/res/android
```

Elles apparaissent dans `AndroidManifest.xml`, `activity_main.xml` et `menu_main.xml`. C’est simplement l’URI standard d’espace de noms XML Android — ni une URL d’un service, ni une fuite. Chaque projet Android inclut cette chaîne par défaut.

Niveau de risque : **aucun**.

<img width="977" height="608" alt="Screenshot 2026-03-06 160317" src="https://github.com/user-attachments/assets/36c20060-dc56-4cc7-8614-68ff87c87525" />

Aucun endpoint sensible, aucune clé, aucun token n’a été repéré dans cet APK.

---

## Étape 5 — Extraire et convertir le bytecode DEX

Android compile le Java en format Dalvik Executable (`.dex`), et non en bytecode JVM standard. Pour utiliser des décompilateurs Java classiques comme JD-GUI, il faut d’abord transformer le DEX.

**Extraire `classes.dex`**

J’ai créé un répertoire de sortie puis utilisé l’API ZIP de PowerShell pour ne récupérer que le fichier DEX depuis l’APK.

```powershell
mkdir dex_out
$zip = [System.IO.Compression.ZipFile]::OpenRead("C:\APK-Analysis\UnCrackable-Level1.apk")
$zip.Entries | Where-Object { $_.Name -like "classes*.dex" } | ForEach-Object {
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "C:\APK-Analysis\dex_out\$($_.Name)", $true)
}
$zip.Dispose()
```

Résultat : `classes.dex` (5,528 octets) a été placé dans `dex_out`.

<img width="951" height="291" alt="Screenshot 2026-03-06 160552" src="https://github.com/user-attachments/assets/2392be05-c8fa-4edb-9ba3-9b700ecf5748" />

<img width="1053" height="349" alt="Screenshot 2026-03-06 160623" src="https://github.com/user-attachments/assets/ac649ecd-687a-41cb-bbde-3f307a92aaea" />

<img width="1346" height="480" alt="Screenshot 2026-03-06 160922" src="https://github.com/user-attachments/assets/f1b9a852-7016-46dd-bdb9-8bb25ac60eb3" />

**Exécuter dex2jar**

```powershell
cd C:\APK-Analysis\dex2jar
.\d2j-dex2jar.bat "C:\APK-Analysis\dex_out\classes.dex" -o "C:\APK-Analysis\app.jar"
```

Sortie : `classes.dex -> C:\APK-Analysis\app.jar` — conversion réussie.

<img width="1049" height="89" alt="Screenshot 2026-03-06 161358" src="https://github.com/user-attachments/assets/2f6445e8-2808-4cc0-80a4-bff7a28061fe" />

---

## Étape 6 — JADX contre JD-GUI : quel outil choisir ?

Les deux outils reconstituent du code source Java à partir de bytecode compilé. Mais ils ne se valent pas.

**Pourquoi JADX est particulièrement efficace**

JADX lit les APK directement. Il décode les XML binaires, reconstruit les références de ressources, tente de désobfusquer quand c’est possible, et affiche tout (manifest, ressources, code) dans un navigateur unique. Pour l’analyse Android, c’est généralement le meilleur point de départ.

**Rôle de JD-GUI**

JD-GUI est un décompilateur Java polyvalent. Il ne sait rien des formats spécifiques à Android. Donnez-lui un JAR : il vous affiche des classes, et rien de plus. Les variables restent éventuellement renommées, les identifiants de ressources demeurent sous forme d’entiers, et on perd le contexte.

**Quand passer par dex2jar + JD-GUI**

Parfois, JADX échoue. Les APK fortement protégés (chargeurs de classes personnalisés, configurations multi-dex avec fusion non standard, obfuscation agressive) peuvent entraîner un échec partiel ou total. Dans ce cas, dex2jar arrive souvent quand même à convertir le DEX, et JD-GUI peut fournir un aperçu (même incomplet) de la source.

**Conclusion**

Commencer par JADX, à chaque fois. Basculer vers le pipeline dex2jar → JD-GUI quand JADX bloque.

---

## Étape 7 — Synthèse de l’évaluation de sécurité

### Profil de l’application

| Champ | Valeur |
|-------|--------|
| Package | `owasp.mstg.uncrackable1` |
| Version | 1.0 |
| Plage SDK | 19 – 28 |
| Permissions | Aucune |
| Trafic réseau | N/A (aucun appel réseau détecté) |
| Composants exportés | MainActivity (implicite) |

### Tableau des vulnérabilités

| # | Constat | Sévérité | Emplacement |
|---|---------|----------|-------------|
| 1 | `android:allowBackup="true"` permet l’extraction via ADB | Medium | `AndroidManifest.xml` |
| 2 | Vérifications anti-debug (`isDebuggerConnected`) | Info | Source Java (MainActivity) |
| 3 | MainActivity implicitement exportée via intent-filter | Low | `AndroidManifest.xml` |

### Détails des constats

**[MEDIUM] Backup activé**

N’importe qui disposant d’un câble USB et du mode développeur activé peut vider le répertoire `/data/data/` de l’application. Pour une app stockant des tokens, des sessions ou des identifiants en cache local, c’est un vrai chemin d’attaque. Correctif : `android:allowBackup="false"`.

**[INFO] Logique anti-debug**

L’application détecte si un debugger est attaché à l’exécution. C’est une mesure de protection, pas un défaut. Elle indique que le développeur a anticipé l’analyse runtime et a mis en place des garde-fous — ce qui correspond précisément à l’esprit d’un crackme.

**[LOW] Point d’entrée exporté**

`MainActivity` est accessible via des intents externes parce qu’elle gère `MAIN/LAUNCHER`. C’est le comportement standard d’une activité de lancement. Aucune manipulation de données en provenance d’intents entrants n’a été identifiée, donc le risque pratique reste faible.

### Recommandations

1. Positionner `android:allowBackup="false"` avant toute mise en production
2. Vérifier les extras d’intent interprétés par `MainActivity` pour écarter les risques d’injection
3. La configuration actuelle est saine (pas de permissions, pas de cleartext traffic, pas de flag debug) — conserver cet état

---

## Étape 8 — Nettoyage

Une fois l’analyse terminée, les fichiers intermédiaires ont été supprimés.

```powershell
Remove-Item -Recurse -Force .\dex_out
Remove-Item .\UnCrackable-Level1.apk
```

Le `app.jar` converti a été archivé dans `\results` pour référence ultérieure. Aucune donnée sensible n’a été manipulée : l’objectif de ce TP est une application de formation publique.

---

*TP terminé. Tous les constats sont consignés. Environnement nettoyé.*

