#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iostream>

class CryptoGuardFixture : public ::testing::Test {
protected:
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string_view password = "test_password";
    std::string plainText = "Hello, Crypto!";

    std::string Encrypt(const std::string& input, std::string_view pwd) {
        std::istringstream inSS(input);
        std::iostream inStream(inSS.rdbuf());

        std::ostringstream outSS;
        std::iostream outStream(outSS.rdbuf());

        cryptoCtx.EncryptFile(inStream, outStream, pwd);
        return outSS.str();
    }

    std::string Decrypt(const std::string& input, std::string_view pwd) {
        std::istringstream inSS(input);
        std::iostream inStream(inSS.rdbuf());

        std::ostringstream outSS;
        std::iostream outStream(outSS.rdbuf());

        cryptoCtx.DecryptFile(inStream, outStream, pwd);
        return outSS.str();
    }
};

TEST_F(CryptoGuardFixture, EncryptDoesNotThrow) {
    EXPECT_NO_THROW(Encrypt(plainText, password));
}

TEST_F(CryptoGuardFixture, DecryptRestoresOriginal) {
    std::string encrypted = Encrypt(plainText, password);

    std::string decrypted;
    EXPECT_NO_THROW(decrypted = Decrypt(encrypted, password));
    EXPECT_EQ(decrypted, plainText);
}

TEST_F(CryptoGuardFixture, DecryptWithWrongPasswordThrows) {
    std::string encrypted = Encrypt(plainText, password);
    EXPECT_THROW(Decrypt(encrypted, "wrong_password"), std::runtime_error);
}

TEST(CryptoGuard, InvalidInputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::iostream inStream(inStringStream.rdbuf());
    inStream.setstate(std::ios::failbit);

    std::ostringstream outStringStream;
    std::iostream outStream(outStringStream.rdbuf());

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidInputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::iostream inStream(inStringStream.rdbuf());
    inStream.setstate(std::ios::failbit);

    std::ostringstream outStringStream;
    std::iostream outStream(outStringStream.rdbuf());

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidOutputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::iostream inStream(inStringStream.rdbuf());

    std::ostringstream outStringStream;
    std::iostream outStream(outStringStream.rdbuf());
    outStream.setstate(std::ios::failbit);

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidOutputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::iostream inStream(inStringStream.rdbuf());

    std::ostringstream outStringStream;
    std::iostream outStream(outStringStream.rdbuf());
    outStream.setstate(std::ios::failbit);

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.DecryptFile(inStream, outStream, password), std::runtime_error);
}
