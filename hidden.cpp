#include <gtk/gtk.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SECRET_TRIGGER "unlock123"

static void on_encrypt_clicked(GtkWidget *widget, gpointer data);
static void on_decrypt_clicked(GtkWidget *widget, gpointer data);
static void on_back_clicked(GtkWidget *widget, gpointer data);

GtkWidget *stack;
GtkWidget *text_view;
GtkWidget *file_chooser;
GtkWidget *password_entry;
GtkWidget *status_label;

std::string generateRandomFilename(int length = 12) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    unsigned char buf[length];
    
    RAND_bytes(buf, length);
    
    for (int i = 0; i < length; i++) {
        result += charset[buf[i] % (sizeof(charset) - 1)];
    }
    
    return result + ".enc";
}

bool encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &password) {
    OpenSSL_add_all_algorithms();
    
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open input file: " << inputFile << std::endl;
        return false;
    }
    
    std::string originalFilename = inputFile;
    size_t lastSlash = originalFilename.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        originalFilename = originalFilename.substr(lastSlash + 1);
    }
    
    std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot create output file: " << outputFile << std::endl;
        return false;
    }
    
    unsigned char salt[8];
    RAND_bytes(salt, 8);
    
    outFile.write("Salted__", 8);
    outFile.write(reinterpret_cast<const char*>(salt), 8);
    
    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   reinterpret_cast<const unsigned char*>(password.c_str()), 
                   password.length(), 1, key, iv);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    std::vector<unsigned char> dataToEncrypt;
    
    uint32_t filenameLength = originalFilename.length();
    dataToEncrypt.push_back((filenameLength >> 24) & 0xFF);
    dataToEncrypt.push_back((filenameLength >> 16) & 0xFF);
    dataToEncrypt.push_back((filenameLength >> 8) & 0xFF);
    dataToEncrypt.push_back(filenameLength & 0xFF);
    
    dataToEncrypt.insert(dataToEncrypt.end(), originalFilename.begin(), originalFilename.end());
    
    dataToEncrypt.insert(dataToEncrypt.end(), fileContent.begin(), fileContent.end());
    
    std::vector<unsigned char> ciphertext(dataToEncrypt.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0, outLen2 = 0;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1, dataToEncrypt.data(), dataToEncrypt.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2);
    
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), outLen1 + outLen2);
    outFile.close();
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decryptFile(const std::string &inputFile, std::string &outputFile, const std::string &password) {
    OpenSSL_add_all_algorithms();
    
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Cannot open input file: " << inputFile << std::endl;
        return false;
    }
    
    char saltHeader[8];
    unsigned char salt[8];
    inFile.read(saltHeader, 8);
    inFile.read(reinterpret_cast<char*>(salt), 8);
    
    if (strncmp(saltHeader, "Salted__", 8) != 0) {
        std::cerr << "File is not in the correct encrypted format" << std::endl;
        return false;
    }
    
    std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, 
                   reinterpret_cast<const unsigned char*>(password.c_str()), 
                   password.length(), 1, key, iv);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen1 = 0, outLen2 = 0;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1, ciphertext.data(), ciphertext.size());
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        std::cerr << "Decryption failed - wrong password or corrupted file" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    if (outLen1 + outLen2 < 4) {
        std::cerr << "Decrypted data is too short" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
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
    
    std::string originalFilename(
        reinterpret_cast<char*>(plaintext.data() + 4), 
        filenameLength
    );
    
    size_t lastSlash = outputFile.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        outputFile = outputFile.substr(0, lastSlash + 1) + originalFilename;
    } else {
        outputFile = originalFilename;
    }
    
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Cannot create output file: " << outputFile << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    outFile.write(
        reinterpret_cast<const char*>(plaintext.data() + 4 + filenameLength), 
        outLen1 + outLen2 - 4 - filenameLength
    );
    outFile.close();
    
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void check_trigger(GtkTextBuffer *buffer, gpointer user_data) {
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buffer, &start, &end);
    
    gchar *text = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
    
    if (g_strstr_len(text, -1, SECRET_TRIGGER)) {
        GtkTextIter trigger_start, trigger_end;
        gchar *temp_text = g_strdup(text);
        gchar *trigger_pos = g_strstr_len(temp_text, -1, SECRET_TRIGGER);
        if (trigger_pos) {
            glong offset = trigger_pos - temp_text;
            
            gtk_text_buffer_get_iter_at_offset(buffer, &trigger_start, offset);
            gtk_text_buffer_get_iter_at_offset(buffer, &trigger_end, offset + strlen(SECRET_TRIGGER));
            
            gtk_text_buffer_delete(buffer, &trigger_start, &trigger_end);
        }
        g_free(temp_text);
        
        gtk_stack_set_visible_child_name(GTK_STACK(stack), "encrypt_page");
    }
    
    g_free(text);
}

static void on_encrypt_clicked(GtkWidget *widget, gpointer data) {
    const char *inputFile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
    const char *password = gtk_entry_get_text(GTK_ENTRY(password_entry));
    
    if (!inputFile) {
        gtk_label_set_text(GTK_LABEL(status_label), "Please select a file to encrypt.");
        return;
    }
    
    if (!password || strlen(password) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Please enter a password.");
        return;
    }
    
    std::string inputDir = std::string(inputFile);
    size_t lastSlash = inputDir.find_last_of("/\\");
    std::string outputFile;
    
    if (lastSlash != std::string::npos) {
        outputFile = inputDir.substr(0, lastSlash + 1) + generateRandomFilename();
    } else {
        outputFile = generateRandomFilename();
    }
    
    if (encryptFile(inputFile, outputFile, password)) {
        std::string message = "File encrypted successfully!\nSaved as: " + outputFile;
        gtk_label_set_text(GTK_LABEL(status_label), message.c_str());
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Encryption failed!");
    }
}

static void on_decrypt_clicked(GtkWidget *widget, gpointer data) {
    const char *inputFile = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser));
    const char *password = gtk_entry_get_text(GTK_ENTRY(password_entry));
    
    if (!inputFile) {
        gtk_label_set_text(GTK_LABEL(status_label), "Please select a file to decrypt.");
        return;
    }
    
    if (!password || strlen(password) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Please enter a password.");
        return;
    }
    
    std::string outputFile = std::string(inputFile);
    
    if (decryptFile(inputFile, outputFile, password)) {
        std::string message = "File decrypted successfully!\nSaved as: " + outputFile;
        gtk_label_set_text(GTK_LABEL(status_label), message.c_str());
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Decryption failed! Check password.");
    }
}

static void on_back_clicked(GtkWidget *widget, gpointer data) {
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "notepad_page");
    
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(file_chooser), NULL);
    gtk_entry_set_text(GTK_ENTRY(password_entry), "");
    gtk_label_set_text(GTK_LABEL(status_label), "");
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    
    OpenSSL_add_all_algorithms();
    RAND_poll();
    
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Simple Notepad");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 400);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    stack = gtk_stack_new();
    gtk_container_add(GTK_CONTAINER(window), stack);
    
    GtkWidget *notepad_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_stack_add_named(GTK_STACK(stack), notepad_page, "notepad_page");
    
    text_view = gtk_text_view_new();
    GtkWidget *scrolled_window = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scrolled_window), text_view);
    gtk_box_pack_start(GTK_BOX(notepad_page), scrolled_window, TRUE, TRUE, 0);
    
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    g_signal_connect(buffer, "changed", G_CALLBACK(check_trigger), NULL);
    
    GtkWidget *encrypt_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(encrypt_page), 15);
    gtk_stack_add_named(GTK_STACK(stack), encrypt_page, "encrypt_page");
    
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_pack_start(GTK_BOX(encrypt_page), grid, TRUE, TRUE, 0);
    
    file_chooser = gtk_file_chooser_button_new("Select File", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_grid_attach(GTK_GRID(grid), file_chooser, 0, 0, 2, 1);
    
    password_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Enter Password");
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);  // Hide password
    gtk_grid_attach(GTK_GRID(grid), password_entry, 0, 1, 2, 1);
    
    GtkWidget *encrypt_button = gtk_button_new_with_label("Encrypt (Random Name)");
    gtk_grid_attach(GTK_GRID(grid), encrypt_button, 0, 2, 1, 1);
    g_signal_connect(encrypt_button, "clicked", G_CALLBACK(on_encrypt_clicked), NULL);
    
    GtkWidget *decrypt_button = gtk_button_new_with_label("Decrypt (Original Name)");
    gtk_grid_attach(GTK_GRID(grid), decrypt_button, 1, 2, 1, 1);
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(on_decrypt_clicked), NULL);
    
    status_label = gtk_label_new("");
    gtk_label_set_line_wrap(GTK_LABEL(status_label), TRUE);
    gtk_grid_attach(GTK_GRID(grid), status_label, 0, 3, 2, 1);
    
    GtkWidget *back_button = gtk_button_new_with_label("Back to Notepad");
    gtk_grid_attach(GTK_GRID(grid), back_button, 0, 4, 2, 1);
    g_signal_connect(back_button, "clicked", G_CALLBACK(on_back_clicked), NULL);
    
    gtk_stack_set_visible_child_name(GTK_STACK(stack), "notepad_page");
    
    gtk_widget_show_all(window);
    gtk_main();
    
    return 0;
}
