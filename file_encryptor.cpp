#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>

// Generate a random filename
std::string generateRandomFilename(int length = 12) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=";
    std::string result;
    unsigned char buf[length];
    
    RAND_bytes(buf, length);
    
    for (int i = 0; i < length; i++) {
        result += charset[buf[i] % (sizeof(charset) - 1)];
    }
    
    return result + ".enc";
}

// Function to encrypt file with embedded original filename
bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Read input file
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open input file: " << inputFile << std::endl;
        return false;
    }
    
    // Get original filename from path
    std::string originalFilename = inputFile;
    size_t lastSlash = originalFilename.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        originalFilename = originalFilename.substr(lastSlash + 1);
    }
    
    // Read file content
    std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    // Create output file
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot create output file: " << outputFile << std::endl;
        return false;
    }
    
    // Generate salt
    unsigned char salt[8];
    RAND_bytes(salt, 8);
    
    // Write magic number and salt to output
    outFile.write("Salted__", 8);
    outFile.write(reinterpret_cast<const char*>(salt), 8);
    
    // Generate key and IV
    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   reinterpret_cast<const unsigned char*>(password.c_str()), 
                   password.length(), 1, key, iv);
    
    // Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    // Prepare data to encrypt: original filename + separator + file content
    std::vector<unsigned char> dataToEncrypt;
    
    // First add the length of the filename as 4 bytes
    uint32_t filenameLength = originalFilename.length();
    dataToEncrypt.push_back((filenameLength >> 24) & 0xFF);
    dataToEncrypt.push_back((filenameLength >> 16) & 0xFF);
    dataToEncrypt.push_back((filenameLength >> 8) & 0xFF);
    dataToEncrypt.push_back(filenameLength & 0xFF);
    
    // Then add the filename
    dataToEncrypt.insert(dataToEncrypt.end(), originalFilename.begin(), originalFilename.end());
    
    // Finally add the file content
    dataToEncrypt.insert(dataToEncrypt.end(), fileContent.begin(), fileContent.end());
    
    // Encrypt data
    std::vector<unsigned char> ciphertext(dataToEncrypt.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0, outLen2 = 0;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1, dataToEncrypt.data(), dataToEncrypt.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2);
    
    // Write encrypted data to output file
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), outLen1 + outLen2);
    outFile.close();
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Function to decrypt file and restore original filename
bool decryptFile(const std::string &inputFile, std::string &outputFile, const std::string &password) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Open input file
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open input file: " << inputFile << std::endl;
        return false;
    }
    
    // Read salt
    char saltHeader[8];
    unsigned char salt[8];
    inFile.read(saltHeader, 8);
    inFile.read(reinterpret_cast<char*>(salt), 8);
    
    // Check salt header
    if (strncmp(saltHeader, "Salted__", 8) != 0) {
        std::cerr << "File is not in the correct encrypted format" << std::endl;
        return false;
    }
    
    // Read encrypted data
    std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    // Generate key and IV
    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   reinterpret_cast<const unsigned char*>(password.c_str()), 
                   password.length(), 1, key, iv);
    
    // Create decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    // Decrypt data
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0, outLen2 = 0;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1, ciphertext.data(), ciphertext.size());
    
    // Try to finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        std::cerr << "Decryption failed - wrong password or corrupted file" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Extract original filename from decrypted data
    if (outLen1 + outLen2 < 4) {
        std::cerr << "Decrypted data is too short" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Extract filename length (first 4 bytes)
    uint32_t filenameLength = 
        (plaintext[0] << 24) | 
        (plaintext[1] << 16) | 
        (plaintext[2] << 8) | 
        plaintext[3];
    
    if (outLen1 + outLen2 < 4 + filenameLength) {
        std::cerr << "Decrypted data is too short to contain the original filename" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Extract the original filename
    std::string originalFilename(
        reinterpret_cast<char*>(plaintext.data() + 4), 
        filenameLength
    );
    
    // Set output path to the original filename in the current directory
    size_t lastSlash = outputFile.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        outputFile = outputFile.substr(0, lastSlash + 1) + originalFilename;
    } else {
        outputFile = originalFilename;
    }
    
    // Create output file
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot create output file: " << outputFile << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Write file content (skipping the filename length and filename)
    outFile.write(
        reinterpret_cast<const char*>(plaintext.data() + 4 + filenameLength), 
        outLen1 + outLen2 - 4 - filenameLength
    );
    outFile.close();
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Callback when encrypt button is clicked
static void on_encrypt_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *grid = GTK_WIDGET(data);
    
    // Get file chooser widget
    GtkWidget *fileChooser = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 0));
    const char *inputFile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fileChooser));
    
    // Get password entry widget
    GtkWidget *passwordEntry = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 1));
    const char *password = gtk_entry_get_text(GTK_ENTRY(passwordEntry));
    
    // Get status label
    GtkWidget *statusLabel = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 3));
    
    // Check for file and password
    if (!inputFile) {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Please select a file to encrypt.");
        return;
    }
    
    if (!password || strlen(password) == 0) {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Please enter a password.");
        return;
    }
    
    // Generate random filename in the same directory as the input file
    std::string inputDir = std::string(inputFile);
    size_t lastSlash = inputDir.find_last_of("/\\");
    std::string outputFile;
    
    if (lastSlash != std::string::npos) {
        outputFile = inputDir.substr(0, lastSlash + 1) + generateRandomFilename();
    } else {
        outputFile = generateRandomFilename();
    }
    
    // Call the encryptFile function
    if (encryptFile(inputFile, outputFile, password)) {
        std::string message = "File encrypted successfully!\nSaved as: " + outputFile;
        gtk_label_set_text(GTK_LABEL(statusLabel), message.c_str());
    } else {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Encryption failed!");
    }
}

// Callback when decrypt button is clicked
static void on_decrypt_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *grid = GTK_WIDGET(data);
    
    // Get file chooser widget
    GtkWidget *fileChooser = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 0));
    const char *inputFile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fileChooser));
    
    // Get password entry widget
    GtkWidget *passwordEntry = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 1));
    const char *password = gtk_entry_get_text(GTK_ENTRY(passwordEntry));
    
    // Get status label
    GtkWidget *statusLabel = GTK_WIDGET(gtk_grid_get_child_at(GTK_GRID(grid), 0, 3));
    
    // Check for file and password
    if (!inputFile) {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Please select a file to decrypt.");
        return;
    }
    
    if (!password || strlen(password) == 0) {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Please enter a password.");
        return;
    }
    
    // Start with a temporary output path (will be updated by decryptFile)
    std::string outputFile = std::string(inputFile);
    
    // Call the decryptFile function
    if (decryptFile(inputFile, outputFile, password)) {
        std::string message = "File decrypted successfully!\nSaved as: " + outputFile;
        gtk_label_set_text(GTK_LABEL(statusLabel), message.c_str());
    } else {
        gtk_label_set_text(GTK_LABEL(statusLabel), "Decryption failed! Check password.");
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    
    // Initialize OpenSSL random number generator
    RAND_poll();

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "File Encryptor (Random Names)");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 200);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Create a grid with more spacing
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 15);
    gtk_container_add(GTK_CONTAINER(window), grid);

    // File chooser button
    GtkWidget *fileChooser = gtk_file_chooser_button_new("Select File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_grid_attach(GTK_GRID(grid), fileChooser, 0, 0, 2, 1);

    // Password entry
    GtkWidget *passwordEntry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(passwordEntry), "Enter Password");
    gtk_entry_set_visibility(GTK_ENTRY(passwordEntry), FALSE);  // Hide password
    gtk_grid_attach(GTK_GRID(grid), passwordEntry, 0, 1, 2, 1);

    // Encrypt button
    GtkWidget *encryptButton = gtk_button_new_with_label("Encrypt (Random Name)");
    gtk_grid_attach(GTK_GRID(grid), encryptButton, 0, 2, 1, 1);

    // Decrypt button
    GtkWidget *decryptButton = gtk_button_new_with_label("Decrypt (Original Name)");
    gtk_grid_attach(GTK_GRID(grid), decryptButton, 1, 2, 1, 1);

    // Status label
    GtkWidget *statusLabel = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(statusLabel), TRUE);
    gtk_grid_attach(GTK_GRID(grid), statusLabel, 0, 3, 2, 1);

    // Connect signals
    g_signal_connect(encryptButton, "clicked", G_CALLBACK(on_encrypt_clicked), grid);
    g_signal_connect(decryptButton, "clicked", G_CALLBACK(on_decrypt_clicked), grid);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
