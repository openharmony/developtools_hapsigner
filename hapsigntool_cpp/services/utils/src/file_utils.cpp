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
#include <iostream>
#include <filesystem>
#include <fstream>
#include <climits>

#include "string_utils.h"
#include "signature_tools_errno.h"
#include "file_utils.h"

namespace OHOS {
namespace SignatureTools {
namespace fs = std::filesystem;

const int FileUtils::NUM_TWO = 2;
const int FileUtils::NUM_THREE = 3;
const int FileUtils::NUM_FOUR = 4;

const std::unordered_map<std::string, std::regex> FileUtils::SUFFIX_REGEX_MAP = {
{std::string("so"), std::regex("\\.so(\\.[0-9]*){0,3}$")}};

bool FileUtils::IsEmpty(std::string cs)
{
    if (cs.length() == 0) {
        return true;
    }
    return false;
}

bool FileUtils::IsSpaceEnough(const std::string &filePath, const int64_t requiredSpace)
{
    uint64_t freeSpace = 0;
    struct statfs diskStatfs;
    int ret = statfs(filePath.c_str(), &diskStatfs);
    if (ret >= 0) {
        freeSpace = (uint64_t)diskStatfs.f_bsize * (uint64_t)diskStatfs.f_bavail;
    } else {
        SIGNATURE_TOOLS_LOGE("statfs fail, error code = %{public}d", ret);
    }
    return freeSpace >= static_cast<uint64_t>(requiredSpace);
}

std::string FileUtils::GetSuffix(std::string filePath)
{
    if (filePath.empty()) {
        return "";
    }
    size_t last_dot_position = filePath.rfind(".");
    bool positionFlag = (last_dot_position == std::string::npos) || (last_dot_position == filePath.size() - 1);
    if (positionFlag) {
        return "";
    }
    return filePath.substr(last_dot_position + 1);
}

bool FileUtils::ValidFileType(const std::string& filePath, std::initializer_list<std::string> types)
{
    std::string suffix = GetSuffix(filePath);
    bool flag = suffix.empty() || (StringUtils::ContainsCase(types, suffix) == false);
    if (flag) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "Not support file: " + filePath);
        return false;
    }
    return true;
}

int FileUtils::Write(const std::string& content, const std::string& output)
{
    std::ofstream outFile(output, std::ios::binary);
    bool flag = (outFile.rdstate() != 0);
    if (flag) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open output file: " + output + " failed");
        return IO_ERROR;
    }
    outFile.write(&content[0], content.size());
    if (outFile.rdstate() != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "Failed to write data to output stream.");
        return IO_ERROR;
    }
    return RET_OK;
}

int FileUtils::Read(std::ifstream& input, std::string& ret)
{
    ret.clear();
    if (input.rdstate() != 0) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "invalid input stream");
        return IO_ERROR;
    }
    ret.clear();
    std::string buffer(FileUtils::FILE_BUFFER_BLOCK, 0);
    while (input) {
        input.read(&buffer[0], buffer.size());
        ret.append(&buffer[0], input.gcount());
    }
    return RET_OK;
}

int FileUtils::ReadFile(const std::string& path, std::string& ret)
{
    std::ifstream file(path, std::ios::binary);
    bool flag = (file.rdstate() != 0);
    if (flag) {
        PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "open input file: " + path + " failed");
        return IO_ERROR;
    }
    if (Read(file, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("read error!");
        return IO_ERROR;
    }
    return RET_OK;
}

int FileUtils::ReadFileByOffsetAndLength(std::ifstream& file, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return RET_FAILED;
    }
    if (ReadInputByOffsetAndLength(file, offset, length, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("Error readInputByOffsetAndLength");
        return IO_ERROR;
    }
    return RET_OK;
}

int FileUtils::ReadInputByOffsetAndLength(std::ifstream& input, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return -1;
    }
    input.seekg(offset);
    if (ReadInputByLength(input, length, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("Error readInputByLength");
        return -1;
    }
    return RET_OK;
}

int FileUtils::ReadInputByLength(std::ifstream& input, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Size cannot be greater than Integer max value: %zu", length);
        return -1;
    }
    if (input.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Error input");
        return -1;
    }
    ret.clear();
    std::string buffer(FILE_BUFFER_BLOCK, 0);
    size_t hasReadLen = 0;
    while (hasReadLen < length && input) {
        int readLen = static_cast<int>(std::min(length - hasReadLen, (size_t)FILE_BUFFER_BLOCK));
        input.read(&buffer[0], readLen);
        bool flag = (input.gcount() != readLen);
        if (flag) {
            SIGNATURE_TOOLS_LOGE("read %zu bytes data less than %zu", hasReadLen, length);
            return -1;
        }
        ret.append(&buffer[0], readLen);
        hasReadLen += input.gcount();
    }
    if (hasReadLen != length) {
        SIGNATURE_TOOLS_LOGE("read %zu bytes data less than %zu", hasReadLen, length);
        return -1;
    }
    return RET_OK;
}

bool FileUtils::AppendWriteFileByOffsetToFile(std::ifstream& input, std::ofstream& out, size_t offset, size_t size)
{
    if (input.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("input failed.");
        return false;
    }
    if (out.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed get out stream");
        return false;
    }
    input.seekg(offset);
    if (WriteInputToOutPut(input, out, size) < 0) {
        SIGNATURE_TOOLS_LOGE("Error: writeInputToOutPut");
        return false;
    }
    return true;
}

bool FileUtils::AppendWriteFileToFile(const std::string& inputFile, const std::string& outputFile)
{
    std::ifstream input(inputFile, std::ios::binary);
    std::ofstream output(outputFile, std::ios::binary | std::ios::app);
    bool flag = (0 != input.rdstate());
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get input stream object!");
        return false;
    }
    flag = (0 != output.rdstate());
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get output stream object!");
        return false;
    }
    char* buffer = new char[FILE_BUFFER_BLOCK];
    while (!input.eof()) {
        input.read(buffer, FILE_BUFFER_BLOCK);

        if (input.fail() && !input.eof()) {
            SIGNATURE_TOOLS_LOGE("error occurred while reading data");
            delete[]buffer;
            return false;
        }
        std::streamsize readLen = input.gcount();
        if (readLen > 0) {
            output.write(buffer, readLen);
        }
        if (!output) {
            SIGNATURE_TOOLS_LOGE("error occurred while writing data");
            delete[]buffer;
            return false;
        }
    }
    delete[]buffer;
    return true;
}

bool FileUtils::AppendWriteByteToFile(const std::string& bytes, const std::string& outputFile)
{
    std::ofstream output(outputFile, std::ios::binary | std::ios::app);
    bool flag = (WriteByteToOutFile(bytes, output) == false);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to write data to output stream, outfile: %s", outputFile.c_str());
        return false;
    }
    return true;
}

int FileUtils::WriteInputToOutPut(std::ifstream& input, std::ofstream& output, size_t length)
{
    static Uscript::ThreadPool readPool(1);
    static Uscript::ThreadPool writePool(1);
    std::future<void> readTask;
    std::vector<std::future<void>> writeTasks;
    int result = RET_OK;
    auto writeFunc = [&result] (std::ofstream& outStream, char* data, int dataSize) {
        outStream.write(data, dataSize);
        if (!outStream.good()) {
            result = IO_ERROR;
            delete[] data;
            return;
        }
        delete[] data;
        };
    auto readFunc = [&output, &writeFunc, &writeTasks, &result] (std::ifstream& in, int dataSize) {
        while (in) {
            char* buf = new (std::nothrow)char[FILE_BUFFER_BLOCK];
            if (buf == NULL) {
                result = RET_FAILED;
                return;
            }
            int min = std::min(dataSize, FILE_BUFFER_BLOCK);
            in.read(buf, min);
            dataSize -= in.gcount();
            writeTasks.push_back(writePool.Enqueue(writeFunc, std::ref(output), buf, min));
            if (dataSize <= 0) {
                break;
            }
        }
        // After the file is written, datasize must be 0, so the if condition will never hold
        if (dataSize != 0) {
            SIGNATURE_TOOLS_LOGE("write error!");
            result = IO_ERROR;
            return;
        }
        };
    readTask = readPool.Enqueue(readFunc, std::ref(input), length);
    readTask.wait();
    for (std::future<void>& task : writeTasks) {
        task.wait();
    }
    return result;
}

bool FileUtils::WriteInputToOutPut(const std::string& input, const std::string& output)
{
    std::ifstream in(input, std::ios::binary);
    std::ofstream out(output, std::ios::binary);
    bool flag = (in.rdstate() != 0);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get input stream object!");
        return false;
    }
    flag = (out.rdstate() != 0);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to get output stream object!");
        return false;
    }
    char* buffer = new char[FILE_BUFFER_BLOCK];
    while (!in.eof()) {
        in.read(buffer, FILE_BUFFER_BLOCK);

        if (in.fail() && !in.eof()) {
            SIGNATURE_TOOLS_LOGE("error occurred while reading data");
            delete[]buffer;
            return false;
        }

        std::streamsize readLen = in.gcount();
        if (readLen > 0) {
            out.write(buffer, readLen);
        }

        if (!out) {
            SIGNATURE_TOOLS_LOGE("error occurred while writing data");
            delete[]buffer;
            return false;
        }
    }
    delete[]buffer;
    return true;
}

bool FileUtils::WriteByteToOutFile(const std::string& bytes, const std::string& outFile)
{
    std::ofstream ops(outFile, std::ios::binary);
    bool flag = (WriteByteToOutFile(bytes, ops) == false);
    if (flag) {
        SIGNATURE_TOOLS_LOGE("Failed to write data to ops, outfile: %s", outFile.c_str());
        return false;
    }
    return true;
}

bool FileUtils::WriteByteToOutFile(const std::string& bytes, std::ofstream& outFile)
{
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to get output stream object, outfile");
        return false;
    }
    outFile.write(&bytes[0], bytes.size());
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to write data to ops, outfile ");
        return false;
    }
    outFile.flush();
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Flush error");
        return false;
    }
    return true;
}

bool FileUtils::WriteByteToOutFile(const std::vector<int8_t>& bytes, std::ofstream& outFile)
{
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to get output stream object, outfile");
        return false;
    }
    outFile.write((char*)&bytes[0], bytes.size());
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to write data to ops, outfile ");
        return false;
    }
    outFile.flush();
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Flush error");
        return false;
    }
    return true;
}

bool FileUtils::IsRunnableFile(const std::string& name)
{
    if (name.empty()) {
        return false;
    }
    bool flag = (name.size() >= NUM_THREE) && (name[name.size() - NUM_THREE] == '.')
        && (name[name.size() - NUM_TWO] == 'a')
        && (name[name.size() - 1] == 'n');
    if (flag) {
        return true;
    }
    flag = (name.size() >= NUM_FOUR) && (name[name.size() - NUM_FOUR] == '.')
        && (name[name.size() - NUM_THREE] == 'a')
        && (name[name.size() - NUM_TWO] == 'b') && (name[name.size() - 1] == 'c');
    if (flag) {
        return true;
    }
    for (const auto& val : SUFFIX_REGEX_MAP) {
        const std::regex& pattern(val.second);
        if (std::regex_search(name, pattern)) {
            return true;
        }
    }
    return false;
}

bool FileUtils::IsValidFile(std::string file)
{
    std::filesystem::path filePath = file;
    bool flag = std::filesystem::exists(filePath);
    if (!flag) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, file + " is not exists");
        return false;
    }
    flag = std::filesystem::is_directory(filePath);
    if (flag) {
        PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, file + " is a directory not file");
        return false;
    }
    return true;
}

int64_t FileUtils::GetFileLen(const std::string& file)
{
    std::filesystem::path filePath = file;
    bool flag = std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath);
    if (flag) {
        return std::filesystem::file_size(filePath);
    }
    return -1;
}

void FileUtils::DelDir(const std::string& file)
{
    std::filesystem::path filePath = file;
    bool flag = std::filesystem::is_directory(filePath);
    if (flag) {
        for (auto& p : std::filesystem::recursive_directory_iterator(filePath)) {
            DelDir(p.path());
        }
    }
    std::filesystem::remove(file);
    return;
}

} // namespace SignatureTools
} // namespace OHOS