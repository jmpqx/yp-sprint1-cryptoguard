#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return data_.command_; }
    std::string GetInputFile() const { return data_.inputFile_; }
    std::string GetOutputFile() const { return data_.outputFile_; }
    std::string GetPassword() const { return data_.password_; }

private:
    void ValidateCommands_(const boost::program_options::variables_map &vm);
    COMMAND_TYPE FromStrToCommandType_(const std::string &commandStr) const;

    const static inline std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    struct Data_ {
        COMMAND_TYPE command_;
        std::string inputFile_;
        std::string outputFile_;
        std::string password_;
        boost::program_options::options_description desc_;
    } data_;
};

}  // namespace CryptoGuard
