#include "cmd_options.h"
#include <exception>
#include <iostream>
#include <fstream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : data_() {
    // clang-format off
    data_.desc_.add_options()
        ("help", "Produce help message")
        ("command", boost::program_options::value<std::string>()->required(), "Command to execute (encrypt, decrypt, checksum)")
        ("input,i", boost::program_options::value<std::string>(&data_.inputFile_)->required(), "Input file path")
        ("output,o", boost::program_options::value<std::string>(&data_.outputFile_), "Output file path")
        ("password,p", boost::program_options::value<std::string>(&data_.password_), "Password for encryption/decryption");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    using namespace boost::program_options;

    variables_map vm;

    try {
        store(parse_command_line(argc, argv, data_.desc_), vm);

        if (vm.count("help")) {
            std::cout << data_.desc_ << std::endl;
            return;
        }

        notify(vm);

        ValidateCommands_(vm);
    } catch (const std::exception &e) {
        std::cerr << "Error parsing command line: " << e.what() << std::endl;
        std::cerr << data_.desc_ << std::endl;
        throw;
    }
}

void ProgramOptions::ValidateCommands_(const boost::program_options::variables_map &vm) {
    if (vm.count("command")) {
        data_.command_ = FromStrToCommandType_(vm["command"].as<std::string>());
    }

    if (vm.count("input")) {
        std::ifstream infile(data_.inputFile_);
        if (!infile) {
            throw std::runtime_error{"Input file does not exist: " + data_.inputFile_};
        }
    }

    if (vm.count("output")) {
        std::ofstream outfile(data_.outputFile_, std::ios::binary);
        if (!outfile) {
            throw std::runtime_error{"Cannot write to output file: " + data_.outputFile_};
        }
    }
}

ProgramOptions::COMMAND_TYPE ProgramOptions::FromStrToCommandType_(const std::string &commandStr) const {
    auto it = commandMapping_.find(commandStr);
    if (it == commandMapping_.end()) {
        throw std::runtime_error{"Unsupported command: " + commandStr};
    }

    return it->second;
}

}  // namespace CryptoGuard
