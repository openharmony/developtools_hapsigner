/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <memory>
#include <gtest/gtest.h>
#include <fstream>
#include "file_utils.h"

namespace OHOS {
namespace SignatureTools {
/*
* 测试套件,固定写法
*/
class FileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    };
    static void TearDownTestCase()
    {
    };
    void SetUp()
    {
    };
    void TearDown()
    {
    };
};

const int THREAD_NUMS = 8;
const size_t MAX_FILE_SIZE = 1024 * 1024 * 10;
const size_t BUFFER_SIZE = 1024 * 128;

void CreateTestFile()
{
    (void)mkdir("tmp", 0777);
    srand((unsigned)time(NULL));

    for (int i = 1; i <= THREAD_NUMS; i++) {
        std::string fileName = "tmp/tmp-" + std::to_string(i) + ".txt";
        std::ofstream file(fileName, std::ios::binary);
        if (!file.is_open()) {
            printf("open file: %s failed.\n", fileName.c_str());
            continue;
        }

        char buffer[BUFFER_SIZE];
        size_t remaining = MAX_FILE_SIZE;
        while (remaining > 0) {
            size_t min = std::min(BUFFER_SIZE, remaining);
            for (size_t j = 0; j < min; j++) {
            //generates a printable ASCII character (32 through 126)
            // The ASCII code for ' ' is 32, so this generates characters between 32 and 126
                buffer[j] = ' ' + (char)(rand() % 95);
            }

            file.write(buffer, min);
            if (!file.good()) {
                printf("write file: %s failed.\n", fileName.c_str());
                break;
            }

            remaining -= min;
        }
        printf("File %s has been created with %zu bytes.\n", fileName.c_str(), MAX_FILE_SIZE);
    }
}

int Worker(const std::string& inputFile, const std::string& outputFile, int length)
{
    std::ifstream input(inputFile, std::ios::binary);
    std::ofstream output(outputFile, std::ios::binary);
    if (!input) {
        printf("open file: %s failed.\n", inputFile.c_str());
        return -1;
    }
    if (!output) {
        printf("open file: %s failed.\n", outputFile.c_str());
        return -1;
    }

    int res = FileUtils::WriteInputToOutPut(input, output, length);

    std::thread::id id = std::this_thread::get_id();
    printf("thread: %u completed: %s -> %s res: %d\n", *(uint32_t*)&id, inputFile.c_str(),
           outputFile.c_str(), res);

    output.close();
    input.close();
    return res;
}

/**
 * @tc.name: WriteByteToOutFile001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteByteToOutFile001, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get output stream object, outfile"
    std::vector<int8_t> bytes;
    std::ofstream output("./utilstmp/signed-linux.out", std::ios::binary);
    bool flag = FileUtils::WriteByteToOutFile(bytes, output);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: WriteByteToOutFile002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteByteToOutFile002, testing::ext::TestSize.Level1)
{
    // outfile path is right
    std::vector<int8_t> bytes;
    std::ofstream output("./utils/signed-linux.out", std::ios::binary);
    bool flag = FileUtils::WriteByteToOutFile(bytes, output);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: Write
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, Write, testing::ext::TestSize.Level1)
{
    // go to branch "Failed get output stream"
    std::string str;
    std::string fileName = "./utilsxxx/signed-linux.out";
    int result = FileUtils::Write(str, fileName);
    EXPECT_EQ(result, -103);
}

/**
 * @tc.name: Read001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, Read001, testing::ext::TestSize.Level1)
{
    // go to branch "io error"
    std::string outstr;
    std::ifstream input("./utilsxxx/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::Read(input, outstr);
    EXPECT_NE(result, -104);
}

/**
 * @tc.name: Read002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, Read002, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::Read(input, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadFile001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadFile001, testing::ext::TestSize.Level1)
{
    // go to branch "open error"
    std::string outstr;
    std::string fileName = "./utilsxxx/unsigned-linux.out";
    int result = FileUtils::ReadFile(fileName, outstr);
    EXPECT_NE(result, -104);
}

/**
 * @tc.name: ReadFile002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadFile002, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string outstr;
    std::string fileName = "./utils/unsigned-linux.out";
    int result = FileUtils::ReadFile(fileName, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadFileByOffsetAndLength001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadFileByOffsetAndLength001, testing::ext::TestSize.Level1)
{
    // go to branch "Size cannot be greater than Integer max value"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadFileByOffsetAndLength(input, 0, 2147483648, outstr);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ReadFileByOffsetAndLength002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadFileByOffsetAndLength002, testing::ext::TestSize.Level1)
{
    // go to branch "Error readInputByOffsetAndLength"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadFileByOffsetAndLength(input, -1, 32, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadFileByOffsetAndLength003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadFileByOffsetAndLength003, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadFileByOffsetAndLength(input, 0, 32, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadInputByOffsetAndLength001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByOffsetAndLength001, testing::ext::TestSize.Level1)
{
    // go to branch "Size cannot be greater than Integer max value"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadInputByOffsetAndLength(input, 0, 2147483648, outstr);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ReadInputByOffsetAndLength002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByOffsetAndLength002, testing::ext::TestSize.Level1)
{
    // go to branch "Error seek"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linuxxx.out", std::ios::binary);
    int result = FileUtils::ReadInputByOffsetAndLength(input, 0, 32, outstr);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ReadInputByOffsetAndLength003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByOffsetAndLength003, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string outstr;
    std::ifstream input("./utils/unsigned-linuxxx.out", std::ios::binary);
    int result = FileUtils::ReadInputByOffsetAndLength(input, 0, 32, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: ReadInputByLength001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByLength001, testing::ext::TestSize.Level1)
{
    // go to branch "Size cannot be greater than Integer max value"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadInputByLength(input, 2147483648, outstr);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ReadInputByLength002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByLength002, testing::ext::TestSize.Level1)
{
    // go to branch "Error input"
    std::string outstr;
    std::ifstream input("./utils/unsigned-linuxxx.out", std::ios::binary);
    int result = FileUtils::ReadInputByLength(input, 32, outstr);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: ReadInputByLength003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, ReadInputByLength003, testing::ext::TestSize.Level1)
{
    std::string outstr;
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    int result = FileUtils::ReadInputByLength(input, 32, outstr);
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: AppendWriteFileByOffsetToFile005
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileByOffsetToFile005, testing::ext::TestSize.Level1)
{
    // go to branch "input failed"
    std::ifstream input("./utils/unsigned-linuxxx.out", std::ios::binary);
    std::ofstream output("./utils/signed-linux.out", std::ios::binary);
    bool result = FileUtils::AppendWriteFileByOffsetToFile(input, output, 0, 32);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteFileByOffsetToFile006
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileByOffsetToFile006, testing::ext::TestSize.Level1)
{
    // go to branch "Failed get out stream"
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    std::ofstream output("./utilsxxx/signed-linux.out", std::ios::binary);
    bool result = FileUtils::AppendWriteFileByOffsetToFile(input, output, 0, 32);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteFileByOffsetToFile007
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileByOffsetToFile007, testing::ext::TestSize.Level1)
{
    // go to branch "Failed seekg"
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    std::ofstream output("./utils/signed-linux.out", std::ios::binary);
    bool result = FileUtils::AppendWriteFileByOffsetToFile(input, output, -1, 32);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteFileByOffsetToFile008
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileByOffsetToFile008, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::ifstream input("./utils/unsigned-linux.out", std::ios::binary);
    std::ofstream output("./utils/signed-linux.out", std::ios::binary);
    bool result = FileUtils::AppendWriteFileByOffsetToFile(input, output, 0, 32);
    EXPECT_NE(result, true);
}

/**
 * @tc.name: AppendWriteFileToFile001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileToFile001, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get input stream object"
    std::string inputFile = "./utils/unsigned-linuxxx.out";
    std::string outputFile = "./utils/signed-linux.out";
    bool result = FileUtils::AppendWriteFileToFile(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteFileToFile002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileToFile002, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get output stream object"
    std::string inputFile = "./utils/unsigned-linux.out";
    std::string outputFile = "./utilsxxx/signed-linux.out";
    bool result = FileUtils::AppendWriteFileToFile(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteFileToFile003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteFileToFile003, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string inputFile = "./utils/unsigned-linux.out";
    std::string outputFile = "./utilsxxx/signed-linux.out";
    bool result = FileUtils::AppendWriteFileToFile(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: AppendWriteByteToFile
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, AppendWriteByteToFile, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to write data to output stream"
    std::string bytes;
    std::string outputFile = "./utilsxxx/signed-linux.out";
    bool result = FileUtils::AppendWriteByteToFile(bytes, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteInputToOutPut001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteInputToOutPut001, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get input stream object"
    std::string inputFile = "./utils/unsigned-linuxxx.out";
    std::string outputFile = "./utils/signed-linux.out";
    bool result = FileUtils::WriteInputToOutPut(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteInputToOutPut002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteInputToOutPut002, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get output stream object"
    std::string inputFile = "./utils/unsigned-linux.out";
    std::string outputFile = "./utilsxxx/signed-linux.out";
    bool result = FileUtils::WriteInputToOutPut(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteInputToOutPut003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteInputToOutPut003, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::string inputFile = "./utils/unsigned-linux.out";
    std::string outputFile = "./utils/signed-linux.out";
    bool result = FileUtils::WriteInputToOutPut(inputFile, outputFile);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteByteToOutFile003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteByteToOutFile003, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get output stream object"
    std::string bytes;
    std::ofstream output("./utilsxxx/signed-linux.out", std::ios::binary);
    bool result = FileUtils::WriteByteToOutFile(bytes, output);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteByteToOutFile004
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteByteToOutFile004, testing::ext::TestSize.Level1)
{
    // go to branch "Failed to get output stream object"
    std::vector<int8_t> bytes;
    std::ofstream output("./utilsxxx/signed-linux.out", std::ios::binary);
    bool result = FileUtils::WriteByteToOutFile(bytes, output);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: WriteByteToOutFile005
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteByteToOutFile005, testing::ext::TestSize.Level1)
{
    // go to all branch
    std::vector<int8_t> bytes;
    std::ofstream output("./utils/signed-linux.out", std::ios::binary);
    bool result = FileUtils::WriteByteToOutFile(bytes, output);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: IsRunnableFile001
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, IsRunnableFile001, testing::ext::TestSize.Level1)
{
    // go to branch "name.empty()"
    std::string fileName;
    bool result = FileUtils::IsRunnableFile(fileName);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: IsRunnableFile002
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, IsRunnableFile002, testing::ext::TestSize.Level1)
{
    // go to branch ".an"
    std::string fileName = "test.an";
    bool result = FileUtils::IsRunnableFile(fileName);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: IsRunnableFile003
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, IsRunnableFile003, testing::ext::TestSize.Level1)
{
    // go to branch ".so"
    std::string fileName = "test.so";
    bool result = FileUtils::IsRunnableFile(fileName);
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: DelDir
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, DelDir, testing::ext::TestSize.Level1)
{
    std::string fileName = "./utils/testdeldir";
    FileUtils::DelDir(fileName);

    // create dir and file again
    std::filesystem::path dir_path(fileName);
    std::filesystem::create_directories(dir_path);

    std::filesystem::path file_path = dir_path / "example.txt";
    std::ofstream file(file_path);
    EXPECT_EQ(true, 1);
}

/**
 * @tc.name: WriteInputToOutPut
 * @tc.desc: Test function interface for SUCCESS.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: SR000H63TL
 */
HWTEST_F(FileUtilsTest, WriteInputToOutPutTest001, testing::ext::TestSize.Level1)
{
    CreateTestFile();

    std::vector<std::thread> threads;

    for (int i = 1; i <= THREAD_NUMS; ++i) {
        std::string inputFile = "tmp/tmp-" + std::to_string(i) + ".txt";
        std::string outputFile = "tmp/tmp-" + std::to_string(i) + "-copy.txt";
        auto length = std::filesystem::file_size(inputFile);

        threads.emplace_back(Worker, inputFile, outputFile, length);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    printf("All threads completed.\n");
}
} // namespace SignatureTools
} // namespace OHOS