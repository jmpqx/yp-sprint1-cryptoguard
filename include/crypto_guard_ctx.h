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
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::istream &inStream);

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
