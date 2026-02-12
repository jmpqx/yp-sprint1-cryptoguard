#include <cmd_options.h>
#include <gtest/gtest.h>
#include <fstream>

TEST(ProgramOptions, ParseValidArguments) {
    const char *argv[] = {"CryptoGuard", "--command",  "encrypt",    "--input",   "../input.txt",
                          "--output",    "output.txt", "--password", "Password!1"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "../input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "Password!1");
}

TEST(ProgramOptions, ParseMissingInputFileRequiredArgument) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::exception);
}

TEST(ProgramOptions, ParseMissingCommandRequiredArgument) {
    const char *argv[] = {"CryptoGuard", "--input", "input.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::exception);
}

TEST(ProgramOptions, ParseInvalidCommand) {
    const char *argv[] = {"CryptoGuard", "--command", "invalid_command", "--input", "input.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::exception);
}

TEST(ProgramOptions, ParseNonExistentInputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt", "--input", "non_existent_file.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::exception);
}

TEST(ProgramOptions, ParseUnwritableOutputFile) {
    const char *argv[] = {"CryptoGuard", "--command", "encrypt", "--input", "input.txt", "--output", "/unwritable_file.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    CryptoGuard::ProgramOptions options;
    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::exception);
}
