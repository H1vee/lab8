#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#define PORT 54000

// ======== Токен =========
bool encryptToFile(const std::string& data, const std::string& outputPath) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    const char* password = "SuperSecretKey123";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        return false;

    CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    DWORD dataSize = data.size();
    DWORD bufferSize = dataSize + 16;
    BYTE* buffer = new BYTE[bufferSize];
    memcpy(buffer, data.c_str(), dataSize);

    CryptEncrypt(hKey, 0, TRUE, 0, buffer, &dataSize, bufferSize);

    std::ofstream outFile(outputPath, std::ios::binary);
    outFile.write((char*)buffer, dataSize);
    outFile.close();

    delete[] buffer;
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return true;
}

bool decryptFile(const std::string& inputPath, std::string& output) {
    HANDLE hFile = CreateFileA(inputPath.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead;

    ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;

    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    const char* password = "SuperSecretKey123";

    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)password, strlen(password), 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    DWORD dataLen = fileSize;
    CryptDecrypt(hKey, 0, TRUE, 0, buffer, &dataLen);

    output.assign((char*)buffer, dataLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    delete[] buffer;

    return true;
}

// ======== Сервер =========
void runServer() {
    WSADATA wsaData;
    SOCKET listening, clientSocket;
    sockaddr_in serverHint, client;
    int clientSize = sizeof(client);

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    listening = socket(AF_INET, SOCK_STREAM, 0);

    serverHint.sin_family = AF_INET;
    serverHint.sin_port = htons(PORT);
    serverHint.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(listening, (sockaddr*)&serverHint, sizeof(serverHint));
    listen(listening, SOMAXCONN);

    std::cout << "[Server] Waiting for connection...\n";

    clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

    char buf[4096];
    ZeroMemory(buf, 4096);

    int bytesReceived = recv(clientSocket, buf, 4096, 0);
    if (bytesReceived > 0) {
        std::string received(buf, 0, bytesReceived);
        size_t delimiterPos = received.find(':');
        std::string id = received.substr(0, delimiterPos);
        std::string password = received.substr(delimiterPos + 1);

        std::ifstream file("server_db.txt");
        std::string line;
        bool success = false;
        while (std::getline(file, line)) {
            size_t spacePos = line.find(' ');
            std::string dbId = line.substr(0, spacePos);
            std::string dbPassword = line.substr(spacePos + 1);
            if (dbId == id && dbPassword == password) {
                success = true;
                break;
            }
        }

        if (success) {
            send(clientSocket, "Authentication Successful", 26, 0);
        } else {
            send(clientSocket, "Authentication Failed", 21, 0);
        }
    }

    closesocket(clientSocket);
    WSACleanup();
}

// ======== Клієнт =========
void runClient() {
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in hint;
    std::string decryptedData;

    if (!decryptFile("user_credentials.dat", decryptedData)) {
        std::cerr << "[Client] Failed to read or decrypt user credentials.\n";
        return;
    }

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    sock = socket(AF_INET, SOCK_STREAM, 0);

    hint.sin_family = AF_INET;
    hint.sin_port = htons(PORT);
    hint.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (sockaddr*)&hint, sizeof(hint));

    send(sock, decryptedData.c_str(), decryptedData.size(), 0);

    char buf[4096];
    ZeroMemory(buf, 4096);
    int bytesReceived = recv(sock, buf, 4096, 0);

    if (bytesReceived > 0) {
        std::cout << "[Client] Server says: " << std::string(buf, 0, bytesReceived) << "\n";
    }

    closesocket(sock);
    WSACleanup();
}

// ======== Головне меню =========
int main() {
    int choice;
    do {
        std::cout << "\n=== Меню ===\n";
        std::cout << "1. Створити токен\n";
        std::cout << "2. Запустити сервер\n";
        std::cout << "3. Запустити клієнта\n";
        std::cout << "0. Вийти\n";
        std::cout << "Ваш вибір: ";
        std::cin >> choice;
        std::cin.ignore(); // прибрати Enter

        switch (choice) {
            case 1: {
                std::string id, password;
                std::cout << "Enter user ID: ";
                std::getline(std::cin, id);
                std::cout << "Enter user Password: ";
                std::getline(std::cin, password);
                std::string credentials = id + ":" + password;
                if (encryptToFile(credentials, "user_credentials.dat")) {
                    std::cout << "[Success] Token created and saved to 'user_credentials.dat'.\n";
                } else {
                    std::cout << "[Error] Failed to create token.\n";
                }
                break;
            }
            case 2:
                runServer();
                break;
            case 3:
                runClient();
                break;
            case 0:
                std::cout << "Вихід...\n";
                break;
            default:
                std::cout << "Невірний вибір!\n";
        }

    } while (choice != 0);

    return 0;
}
