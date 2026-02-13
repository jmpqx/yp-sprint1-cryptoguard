#include "crypto_guard_ctx.h"
#include <array>
#include <fstream>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <vector>

namespace CryptoGuard {
std::string OpenSSL_error::GetSSLErrorMessage_(unsigned long errCode) {
    if (errCode == 0) {
        return "Undefined";
    }

    std::vector<char> errMsgBuf(256);

    ERR_error_string_n(errCode, errMsgBuf.data(), errMsgBuf.size());

    return std::string(errMsgBuf.data());
}

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    using EvpCipherCtxPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    Impl();
    ~Impl();

    Impl(const Impl &) = delete;
    Impl &operator=(const Impl &) = delete;

    Impl(Impl &&) noexcept = default;
    Impl &operator=(Impl &&) noexcept = default;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    AesCipherParams CreateCipherParamsFromPassword_(std::string_view password);
};

CryptoGuardCtx::Impl::Impl() { OpenSSL_add_all_algorithms(); }

CryptoGuardCtx::Impl::~Impl() { EVP_cleanup(); }

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream) {
        throw std::runtime_error{"Invalid input stream"};
    }

    if (!outStream) {
        throw std::runtime_error{"Invalid output stream"};
    }

    auto ctx = EvpCipherCtxPtr{EVP_CIPHER_CTX_new()};
    if (!ctx) {
        throw std::runtime_error{"Failed to create EVP_CIPHER_CTX"};
    }

    auto params = CreateCipherParamsFromPassword_(password);
    params.encrypt = 1;

    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    const size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    int outLen = 0;

    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE) || inStream.gcount() > 0) {
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inStream.gcount()))) {
            throw OpenSSL_error{ERR_get_error()};
        }

        if (!outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen)) {
            throw std::runtime_error{"Failed to write encrypted data to output stream"};
        }
    }

    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    if (!outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen)) {
        throw std::runtime_error{"Failed to write final encrypted data to output stream"};
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream) {
        throw std::runtime_error{"Invalid input stream"};
    }

    if (!outStream) {
        throw std::runtime_error{"Invalid output stream"};
    }

    auto ctx = EvpCipherCtxPtr{EVP_CIPHER_CTX_new()};
    if (!ctx) {
        throw std::runtime_error{"Failed to create EVP_CIPHER_CTX"};
    }

    auto params = CreateCipherParamsFromPassword_(password);
    params.encrypt = 0;

    if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    const size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    int outLen = 0;

    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE) || inStream.gcount() > 0) {
        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inStream.gcount()))) {
            throw OpenSSL_error{ERR_get_error()};
        }

        if (!outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen)) {
            throw std::runtime_error{"Failed to write decrypted data to output stream"};
        }
    }

    if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    if (!outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen)) {
        throw std::runtime_error{"Failed to write final decrypted data to output stream"};
    }
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    if (!inStream) {
        throw std::runtime_error{"Invalid input stream"};
    }

    auto ctx = EvpMdCtxPtr{EVP_MD_CTX_new()};
    if (!ctx) {
        throw std::runtime_error{"Failed to create EVP_MD_CTX"};
    }

    if (!EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), nullptr)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    const size_t BUFFER_SIZE = 1024;
    std::vector<unsigned char> inBuf(BUFFER_SIZE);
    std::vector<unsigned char> mdValue(EVP_MAX_MD_SIZE);
    unsigned int mdLen = 0;

    while (inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE) || inStream.gcount() > 0) {
        if (!EVP_DigestUpdate(ctx.get(), inBuf.data(), static_cast<int>(inStream.gcount()))) {
            throw OpenSSL_error{ERR_get_error()};
        }
    }

    if (!EVP_DigestFinal_ex(ctx.get(), mdValue.data(), &mdLen)) {
        throw OpenSSL_error{ERR_get_error()};
    }

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < mdLen; ++i) {
        ss << std::setw(2) << static_cast<int>(mdValue[i]);
    }

    return ss.str();
}

AesCipherParams CryptoGuardCtx::Impl::CreateCipherParamsFromPassword_(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }
}  // namespace CryptoGuard
