# SupprAD : audit des fichiers supprimés et créés

**AuditSuppressions.ps1** est un script PowerShell avec interface graphique. Il indique, sur un ou plusieurs serveurs de fichiers Windows, **qui a supprimé ou créé quel fichier ou dossier, et quand**.

Il lit directement le journal Sécurité des serveurs. Il n'y a rien à installer, ni agent ni base de données.

## Fonctionnalités

- **Suppressions** : utilisateur, date, fichier ou dossier supprimé.
- **Créations** : fichiers et dossiers créés, avec leur nom final. Un « Nouveau dossier » renommé juste après apparaît sous son vrai nom.
- **Renommages et déplacements** (en option).
- **Plusieurs serveurs** dans une même recherche, depuis le serveur lui-même ou depuis un autre poste.
- **Période** au choix, avec des raccourcis 24 h, 7 jours et 30 jours.
- **Filtres instantanés** par utilisateur et par nom ou chemin. La recherche porte sur une partie du nom : `2027` trouve « Ma ligne 2027.xlsx ».
- **Masquage du bruit** : fichiers temporaires d'Office, Thumbs.db, desktop.ini et comptes machine.
- **Export CSV**, et copie du chemin complet par double-clic sur une ligne.
- **Rapide**, même sur un journal de plusieurs Go : la lecture part des événements les plus récents et s'arrête au début de la période.

## Prérequis

- Windows Server 2012 R2 ou plus récent, avec PowerShell 4.0 ou plus récent.
- Un compte administrateur (la lecture du journal Sécurité l'exige).
- L'audit configuré sur le serveur (voir ci-dessous). Sans audit, aucun événement n'est enregistré.

## Lancement

Dans un PowerShell ouvert **en administrateur** :

```powershell
powershell -ExecutionPolicy Bypass -STA -File .\AuditSuppressions.ps1
```

Le champ « Serveurs » contient par défaut le serveur local. Pour en interroger plusieurs, séparez leurs noms par des virgules.

### Interroger un serveur à distance

Sur le serveur interrogé, il faut :
- la règle de pare-feu **« Gestion à distance du journal des événements »** activée ;
- l'accès au **partage administratif** du disque (`\\SERVEUR\D$`, par exemple). L'outil s'en sert pour vérifier les créations.

## Configuration du serveur

### 1. Stratégie d'audit

Dans une GPO appliquée aux serveurs de fichiers (pour un contrôleur de domaine, la *Default Domain Controllers Policy*), allez dans :

`Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Configuration avancée de la stratégie d'audit > Accès aux objets`

- **Auditer le système de fichiers** : Succès.
- **Auditer le partage de fichiers détaillé** : à désactiver, avec « Configurer » coché, et Succès et Échec décochés. Cet audit produit un événement 5145 pour chaque accès réseau. Il peut occuper la moitié du journal sans servir à retrouver une suppression.

Vérification :

```powershell
gpupdate /force
auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030},{0CCE9244-69AE-11D9-BED3-505054503030}"
```

Résultat attendu : « Système de fichiers » à Réussite, « Partage de fichiers détaillé » à Pas d'audit.

### 2. Audit sur les dossiers (SACL)

Sur chaque dossier à surveiller, ouvrez Propriétés > Sécurité > Avancé > Audit, puis ajoutez une règle :
- **Principal** : Tout le monde.
- **Type** : Succès.
- **S'applique à** : ce dossier, les sous-dossiers et les fichiers.
- **Autorisations avancées** : Création de fichiers/écriture de données, Création de dossiers/ajout de données, Suppression de sous-dossiers et de fichiers, Suppression.

Vous pouvez aussi passer par PowerShell. Ce script modifie seulement l'audit et ne touche pas aux permissions :

```powershell
$path   = 'D:\Partages\Commun'
$acl    = (Get-Item $path).GetAccessControl('Audit')
$tous   = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'   # Tout le monde
$droits = [System.Security.AccessControl.FileSystemRights]'CreateFiles, CreateDirectories, Delete, DeleteSubdirectoriesAndFiles'
$regle  = New-Object System.Security.AccessControl.FileSystemAuditRule $tous, $droits, 'ContainerInherit, ObjectInherit', 'None', 'Success'
$acl.AddAuditRule($regle)
(Get-Item $path).SetAccessControl($acl)
```

Sur un gros dossier, l'application à tous les fichiers peut prendre longtemps.

Vérification sur un sous-dossier :

```powershell
(Get-Acl 'D:\Partages\Commun\Un\Sous-dossier' -Audit).Audit | Format-Table IdentityReference, FileSystemRights, IsInherited
```

### 3. Taille du journal Sécurité

La taille par défaut ne garde souvent que quelques jours d'historique. Pour passer à 10 Go :

```powershell
wevtutil sl Security /ms:10737418240
[math]::Round((Get-WinEvent -ListLog Security).MaximumSizeInBytes/1GB)   # doit afficher 10
```

Si une GPO définit déjà la taille du journal Sécurité, elle écrase cette commande. Dans ce cas, réglez la taille dans la GPO elle-même :

`Modèles d'administration > Composants Windows > Service Journal des événements > Sécurité > Spécifier la taille maximale du fichier journal (Ko)`

Le paramètre classique « Taille maximale du journal de sécurité » est limité à 4 Go.

Deux semaines plus tard, vérifiez la durée couverte :

```powershell
(Get-WinEvent -LogName Security -MaxEvents 1 -Oldest).TimeCreated
```

## Fonctionnement

| Action | Événements utilisés |
|---|---|
| Suppression | 4663 avec le droit DELETE (0x10000), confirmé par un 4660 « objet supprimé » sur le même processus et le même handle |
| Renommage ou déplacement | 4663 DELETE sans 4660 |
| Création | 4663 en écriture ou ajout (0x2, 0x4), confirmé par la date de création NTFS de l'élément sur le disque (±5 s) |

Windows ne distingue pas une création d'une simple modification. C'est pourquoi l'outil vérifie sur le disque que l'élément est bien né au moment de l'événement.

## Limites

- **Un élément créé puis supprimé n'apparaît plus comme créé**, puisqu'il n'est plus sur le disque pour le vérifier. Il apparaît seulement en « Supprimé ».
- L'historique dépend de la taille du journal Sécurité. Une fois le journal plein, les événements les plus anciens sont écrasés.
- Seuls les dossiers qui portent une règle d'audit sont suivis.

---

Fait par [mc-media.com](https://www.mc-media.com)
