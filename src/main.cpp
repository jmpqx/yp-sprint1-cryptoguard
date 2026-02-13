#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto inFile = std::ifstream{options.GetInputFile()};
            auto inStream = std::iostream{inFile.rdbuf()};

            auto outFile = std::ofstream{options.GetOutputFile(), std::ios::binary};
            auto outStream = std::iostream{outFile.rdbuf()};

            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            auto inFile = std::ifstream{options.GetInputFile(), std::ios::binary};
            auto inStream = std::iostream{inFile.rdbuf()};

            auto outFile = std::ofstream{options.GetOutputFile()};
            auto outStream = std::iostream{outFile.rdbuf()};

            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            auto inFile = std::ifstream{options.GetInputFile()};
            auto inStream = std::iostream{inFile.rdbuf()};

            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inStream));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const CryptoGuard::OpenSSL_error &e) {
        std::print(std::cerr, "OpenSSL error: {}\n", e.what());
        return 1;
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}