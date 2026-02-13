#pragma once

#include <experimental/propagate_const>
#include <memory>
#include <string>

namespace CryptoGuard {
struct OpenSSL_error : std::runtime_error {
public:
    OpenSSL_error(const std::string &message) : std::runtime_error(message) {}
    OpenSSL_error(const char *message) : std::runtime_error(message) {}
    OpenSSL_error(unsigned long errCode) : std::runtime_error(GetSSLErrorMessage_(errCode)) {}

private:
    std::string GetSSLErrorMessage_(unsigned long errCode);
};

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
