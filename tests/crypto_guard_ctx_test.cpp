#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iostream>

class CryptoGuardFixture : public ::testing::Test {
protected:
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string_view password = "test_password";
    std::string plainText = "Hello, Crypto!";

    std::string Encrypt(const std::string &input, std::string_view pwd) {
        std::istringstream inSS(input);
        std::istream inStream(inSS.rdbuf());

        std::ostringstream outSS;
        std::ostream outStream(outSS.rdbuf());

        cryptoCtx.EncryptFile(inStream, outStream, pwd);
        return outSS.str();
    }

    std::string Decrypt(const std::string &input, std::string_view pwd) {
        std::istringstream inSS(input);
        std::istream inStream(inSS.rdbuf());

        std::ostringstream outSS;
        std::ostream outStream(outSS.rdbuf());

        cryptoCtx.DecryptFile(inStream, outStream, pwd);
        return outSS.str();
    }

    std::string CalculateChecksum(const std::string &input) {
        std::istringstream inSS(input);
        std::istream inStream(inSS.rdbuf());

        return cryptoCtx.CalculateChecksum(inStream);
    }
};

TEST_F(CryptoGuardFixture, EncryptDoesNotThrow) { EXPECT_NO_THROW(Encrypt(plainText, password)); }

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

TEST_F(CryptoGuardFixture, EncryptDecryptEmptyString) {
    std::string encrypted = Encrypt("", password);
    EXPECT_FALSE(encrypted.empty());

    std::string decrypted = Decrypt(encrypted, password);

    EXPECT_EQ(decrypted, "");
}

TEST_F(CryptoGuardFixture, ChecksumDoesNotThrow) { EXPECT_NO_THROW(CalculateChecksum(plainText)); }

TEST_F(CryptoGuardFixture, ChecksumEmptyString) {
    std::string checksum = CalculateChecksum("");

    EXPECT_EQ(checksum, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(CryptoGuardFixture, ChecksumAfterEncryptDecrypt) {
    std::string checksumBefore = CalculateChecksum(plainText);

    std::string encrypted = Encrypt(plainText, password);
    std::string decrypted = Decrypt(encrypted, password);

    std::string checksumAfter = CalculateChecksum(decrypted);

    EXPECT_EQ(checksumBefore, checksumAfter);
}

TEST_F(CryptoGuardFixture, DataExactlyBufferSize) {
    std::string data(1024, '*');
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, DataBufferSizePlusOne) {
    std::string data(65537, '*');
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, DataMultipleBufferSizes) {
    std::string data(65537 * 5, '*');
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, LargeData) {
    std::string data(65537 * 128, '*');
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, BinaryDataWithNullBytes) {
    using namespace std::string_literals;

    std::string data = "Hello\0World\0\x01\x02\xFF"s;
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, AllByteValues) {
    std::string data(256, '\0');
    for (int i = 0; i < 256; ++i) {
        data[i] = static_cast<char>(i);
    }
    std::string decrypted = Decrypt(Encrypt(data, password), password);

    EXPECT_EQ(decrypted, data);
}

TEST_F(CryptoGuardFixture, CorruptedCiphertextThrows) {
    std::string encrypted = Encrypt(plainText, password);
    encrypted[encrypted.size() / 2] ^= 0xFF;

    EXPECT_THROW(Decrypt(encrypted, password), std::exception);
}

TEST_F(CryptoGuardFixture, TruncatedCiphertextThrows) {
    std::string encrypted = Encrypt(plainText, password);
    std::string truncated = encrypted.substr(0, encrypted.size() / 2);

    EXPECT_THROW(Decrypt(truncated, password), std::exception);
}

TEST_F(CryptoGuardFixture, EmptyCiphertextDecryptThrows) { EXPECT_THROW(Decrypt("", password), std::exception); }

TEST(CryptoGuard, InvalidInputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::istream inStream(inStringStream.rdbuf());
    inStream.setstate(std::ios::failbit);

    std::ostringstream outStringStream;
    std::ostream outStream(outStringStream.rdbuf());

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidInputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::istream inStream(inStringStream.rdbuf());
    inStream.setstate(std::ios::failbit);

    std::ostringstream outStringStream;
    std::ostream outStream(outStringStream.rdbuf());

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidOutputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::istream inStream(inStringStream.rdbuf());

    std::ostringstream outStringStream;
    std::ostream outStream(outStringStream.rdbuf());
    outStream.setstate(std::ios::failbit);

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, InvalidOutputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::istream inStream(inStringStream.rdbuf());

    std::ostringstream outStringStream;
    std::ostream outStream(outStringStream.rdbuf());
    outStream.setstate(std::ios::failbit);

    std::string_view password = "test_password";

    EXPECT_THROW(cryptoCtx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuard, ChecksumSimple1) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("Hello, Crypto!");
    std::istream inStream(inStringStream.rdbuf());

    std::string checksum;

    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inStream));
    EXPECT_EQ(checksum, "de0640f1dc17ca1b01fb9eba3019ed07c12e2af4ae990ecb36aa669898a9fd40");
}

TEST(CryptoGuard, ChecksumSimple2) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("This is my first crypto experience!");
    std::istream inStream(inStringStream.rdbuf());

    std::string checksum;

    EXPECT_NO_THROW(checksum = cryptoCtx.CalculateChecksum(inStream));
    EXPECT_EQ(checksum, "dba9bc690d47bb9bf269c1d8d6a077cf7f810c2bd74bf420117f97a47a18da5a");
}

TEST(CryptoGuard, ChecksumInvalidInputStream) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::istringstream inStringStream("");
    std::istream inStream(inStringStream.rdbuf());
    inStream.setstate(std::ios::failbit);

    EXPECT_THROW(cryptoCtx.CalculateChecksum(inStream), std::runtime_error);
}

TEST(CryptoGuard, MoveConstructor) {
    CryptoGuard::CryptoGuardCtx ctx1;
    CryptoGuard::CryptoGuardCtx ctx2{std::move(ctx1)};

    std::istringstream inSS("This is my first crypto experience!");
    std::istream inStream(inSS.rdbuf());

    std::ostringstream outSS;
    std::ostream outStream(outSS.rdbuf());

    EXPECT_NO_THROW(ctx2.EncryptFile(inStream, outStream, "password"));
}

TEST(CryptoGuard, MoveOperator) {
    CryptoGuard::CryptoGuardCtx ctx1;
    CryptoGuard::CryptoGuardCtx ctx2 = std::move(ctx1);

    std::istringstream inSS("This is my first crypto experience!");
    std::istream inStream(inSS.rdbuf());

    std::ostringstream outSS;
    std::ostream outStream(outSS.rdbuf());

    EXPECT_NO_THROW(ctx2.EncryptFile(inStream, outStream, "password"));
}
