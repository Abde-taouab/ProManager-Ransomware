# ProManager - Ransomware Pédagogique

Ce projet est un ransomware pédagogique développé dans le cadre d'un TP sur la cybersécurité. Il permet de comprendre les mécanismes fondamentaux des logiciels de rançon (ransomware) et d'apprendre les bases du chiffrement AES-256 CBC, des sockets TCP et de la manipulation de fichiers en C.

## ⚠️ Avertissement

Ce projet est strictement éducatif. Toute utilisation malveillante de ce code est interdite et contraire à l'éthique. Il a été conçu pour fonctionner uniquement en local dans un environnement contrôlé et isolé !

##  Composants du projet

Le système se compose de trois programmes principaux :

1. **`ransomware`** - Un agent dormant qui surveille la création d'un dossier "Projet", attend un délai, puis chiffre son contenu
2. **`serveur_pardon`** - Un serveur qui stocke les clés de chiffrement et les renvoie si l'utilisateur présente des excuses acceptables
3. **`client_decrypt`** - Un client qui se connecte au serveur pour récupérer la clé de déchiffrement et restaurer les fichiers

## 🛠️ Fonctionnement

### Le processus complet

1. L'utilisateur lance le `ransomware` qui tourne en arrière-plan
2. L'utilisateur crée un dossier "Projet" et y place ses fichiers
3. Si le projet n'est pas validé après 1 heure (60 sec pour le cas de test), le `ransomware` :
   - Génère une clé AES-256 et un vecteur d'initialisation (IV)
   - Chiffre tous les fichiers (.txt, .c, .md, html, etc.) et ajoute l'extension .enc
   - Supprime les fichiers originaux
   - Crée un fichier RANÇON.html interactif avec des instructions (en cas de failure , crée le fichier des instructions classique)
   - Envoie la clé et l'IV au serveur
4. L'utilisateur lance `client_decrypt` pour se connecter au serveur
5. L'utilisateur présente ses excuses (minimum 20 caractères)
6. Si acceptées, le serveur envoie la clé et l'IV au client
7. Le client déchiffre les fichiers et restaure les originaux

## 🌟 Fonctionnalités avancées

### 1. Interface Visuelle Animée pour le Ransomware
- **Logo ASCII art** au démarrage du chiffrement
- **Interface colorée** avec codes ANSI pour une meilleure lisibilité
- **Barre de progression dynamique** lors du chiffrement
- **Animation** pendant le processus de chiffrement
- **Affichage en temps réel** des fichiers en cours de traitement

### 2. Message de Rançon HTML Interactif
- **Page HTML moderne** avec effets visuels (au lieu d'un simple fichier texte)
- **Animations CSS** pour une expérience visuelle impressionnante
- **Effets de pulsation** et transitions pour attirer l'attention
- **Ouverture automatique** dans le navigateur par défaut
- **Version texte de secours** fournie en parallèle

### 3. Système de Logs Détaillés
- **Journalisation complète** de toutes les actions dans un fichier dédié
- **Différents niveaux de logs** (ERROR, WARNING, INFO, DEBUG)
- **Horodatage** précis de chaque événement
- **Traçabilité** complète du processus de chiffrement/déchiffrement

### 4. Robustesse et Sécurité
- **Sauvegarde locale de secours** des clés en cas de défaillance du serveur
- **Vérification des chemins dynamique** pour s'adapter à différents environnements
- **Gestion avancée des erreurs** pour une expérience utilisateur fluide
- **Communication client-serveur renforcée** pour éviter les pertes de données

## 📁 Structure des fichiers

```
TP/
├── ransomware.c       # Code source de l'agent dormant
├── client_decrypt.c   # Code source du client de déchiffrement
├── serveur_pardon.c   # Code source du serveur d'administration
├── ransomware         # Exécutable compilé de l'agent
├── client_decrypt     # Exécutable compilé du client
├── serveur_pardon     # Exécutable compilé du serveur
└── ransomware_logs.txt # Fichier de journalisation (créé automatiquement)
```

## 📁 Compilation et utilisation

### Compilation

```bash
gcc -o ransomware ransomware.c -lcrypto
gcc -o serveur_pardon serveur_pardon.c
gcc -o client_decrypt client_decrypt.c -lcrypto
```

### Lancement des programmes

1. **Démarrer le serveur** :
   ```bash
   ./serveur_pardon
   ```

2. **Lancer l'agent** :
   ```bash
   ./ransomware 
   ```

3. **Créer un dossier "Projet (manuellement et ajouter les fichiers de test)"** :
   ```bash
   mkdir -p TP/Projet
   ```


4. **Après chiffrement, lancer le client** :
   ```bash
   ./client_decrypt
   ```

## 🔍 Détails techniques

### Technique de chiffrement
- **Algorithme**: AES-256-CBC via la bibliothèque OpenSSL
- **Clé**: 32 octets générés aléatoirement
- **IV**: 16 octets générés aléatoirement
- **Stockage**: Transmission au serveur + sauvegarde locale de secours

### Communication réseau
- **Protocole**: TCP sur localhost (127.0.0.1)
- **Port**: 4242
- **Modes**: STORE (ransomware → serveur) et RETRIEVE (client → serveur)

### Journalisation
- **Niveaux**: ERROR, WARNING, INFO, DEBUG
- **Format**: [Timestamp] [Niveau] [Composant] Message
- **Localisation**: TP/ransomware_logs.txt

## 🧑‍💻 Auteur

Abdetaouab et Kader

---

*Ce projet est uniquement à but éducatif dans le cadre d'un TP sur la cybersécurité.*
