/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include "file_utils.h"
#include "string_utils.h"
#include <fstream>
#include <climits>
#include "signature_tools_errno.h"
#include <iostream>
#include <filesystem>
#define NUM_TWO 2
#define NUM_THREE 3
#define NUM_FOUR 4
using namespace OHOS::SignatureTools;
namespace fs = std::filesystem;

const std::unordered_map<std::string, std::regex> FileUtils::SUFFIX_REGEX_MAP = {
{std::string("so"), std::regex("\\.so(\\.[0-9]*){0,3}$")} };

bool FileUtils::IsEmpty(std::string cs)
{
    if (cs.length() == 0 || cs.empty()) {
        return true;
    }
    return false;
}

std::string FileUtils::GetSuffix(std::string filePath)
{
    if (filePath.empty()) {
        return "";
    }
    size_t last_dot_position = filePath.rfind(".");
    if (last_dot_position == std::string::npos || last_dot_position == filePath.size() - 1) {
        return "";
    }
    return filePath.substr(last_dot_position + 1);
}

bool FileUtils::ValidFileType(const std::string& filePath, std::initializer_list<std::string> types)
{
    std::string suffix = GetSuffix(filePath);
    if (suffix.empty() || StringUtils::ContainsCase(types, suffix) == false) {
        CMD_ERROR_MSG("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "Not support file: " + filePath);
        return false;
    }
    return true;
}

int FileUtils::Write(const std::string& content, const std::string& output)
{
    std::ofstream outFile(output, std::ios::binary);
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed get output stream!\n");
        return WRITE_FILE_ERROR;
    }
    outFile.write(&content[0], content.size());
    if (outFile.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("Failed to write data to output stream.");
        return WRITE_FILE_ERROR;
    }
    return 0;
}

int FileUtils::Read(std::ifstream& input, std::string& ret)
{
    ret.clear();
    if (input.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("io error!");
        return READ_FILE_ERROR;
    }
    ret.clear();
    std::string buffer(FileUtils::FILE_BUFFER_BLOCK, 0);
    while (input) {
        input.read(&buffer[0], buffer.size());
        ret.append(&buffer[0], input.gcount());
    }
    return 0;
}

int FileUtils::ReadFile(const std::string& path, std::string& ret)
{
    std::ifstream file(path, std::ios::binary);
    if (file.rdstate() != 0) {
        SIGNATURE_TOOLS_LOGE("open %{public}s error\n", path.c_str());
        return READ_FILE_ERROR;
    }
    if (Read(file, ret) < 0) {
        SIGNATURE_TOOLS_LOGE("read error!");
        return READ_FILE_ERROR;
    }
    return 0;
}

int FileUtils::ReadFileByOffsetAndLength(std::ifstream& file, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        printf("Size cannot be greater than Integer max value: %zu\n", length);
        return -1;
    }
    if (ReadInputByOffsetAndLength(file, offset, length, ret) < 0) {
        printf("Error readInputByOffsetAndLength\n");
        return -1;
    }
    return 0;
}

int FileUtils::ReadInputByOffsetAndLength(std::ifstream& input, size_t offset, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        printf("Size cannot be greater than Integer max value: %zu\n", length);
        return -1;
    }
    input.seekg(offset);
    if (input.rdstate() != 0) {
        printf("Error seek\n");
        return -1;
    }
    if (ReadInputByLength(input, length, ret) < 0) {
        printf("Error readInputByLength\n");
        return -1;
    }
    return 0;
}

int FileUtils::ReadInputByLength(std::ifstream& input, size_t length, std::string& ret)
{
    if (length > INT_MAX) {
        printf("Size cannot be greater than Integer max value: %zu\n", length);
        return -1;
    }
    if (input.rdstate() != 0) {
        printf("Error input\n");
        return -1;
    }
    ret.clear();
    std::string buffer(FILE_BUFFER_BLOCK, 0);
    size_t hasReadLen = 0;
    while (hasReadLen < length && input) {
        int readLen = static_cast<int>(std::min(length - hasReadLen, (size_t)FILE_BUFFER_BLOCK));
        input.read(&buffer[0], readLen);
        if (input.gcount() != readLen) {
            printf("read %zu bytes data less than %zu\n", hasReadLen, length);
            return -1;
        }
        ret.append(&buffer[0], readLen);
        hasReadLen += input.gcount();
    }
    if (hasReadLen != length) {
        printf("read %zu bytes data less than %zu\n", hasReadLen, length);
        return -1;
    }
    return 0;
}

bool FileUtils::AppendWriteFileByOffsetToFile(const std::string& inFile, std::ofstream& out, long  offset, long size)
{
    if (out.rdstate() != 0) {
        printf("Failed get out stream\n");
        return false;
    }
    std::ifstream input(inFile, std::ios::binary);
    if (input.rdstate() != 0) {
        printf("Failed open %s\n", inFile.c_str());
        return false;
    }
    input.seekg(offset);
    if (input.rdstate() != 0) {
        printf("Failed seekg\n");
        return false;
    }
    if (WriteInputToOutPut(input, out, size) < 0) {
        printf("Error: writeInputToOutPut\n");
        return false;
    }
    return true;
}

bool FileUtils::AppendWriteFileByOffsetToFile(std::ifstream& input, std::ofstream& out, long offset, long size)
{
    if (input.rdstate() != 0) {
        printf("input failed.\n");
        return false;
    }
    if (out.rdstate() != 0) {
        printf("Failed get out stream\n");
        return false;
    }
    input.seekg(offset);
    if (input.rdstate() != 0) {
        printf("Failed seekg\n");
        return false;
    }
    if (WriteInputToOutPut(input, out, size) < 0) {
        printf("Error: writeInputToOutPut\n");
        return false;
    }
    return true;
}

bool FileUtils::AppendWriteFileToFile(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream input(inputFile, std::ios::binary);
    std::ofstream output(outputFile, std::ios::binary | std::ios::app);

    if (0 != input.rdstate()) {
        printf("Failed to get input stream object!\n");
        return false;
    }
    if (0 != output.rdstate()) {
        printf("Failed to get output stream object!\n");
        return false;
    }

    char* buffer = new char[FILE_BUFFER_BLOCK]; // ÿ������1M
    while (!input.eof()) {
        input.read(buffer, FILE_BUFFER_BLOCK);

        if (input.fail() && !input.eof()) {
            printf("error occurred while reading data\n");
            delete[]buffer;
            return false;
        }

        std::streamsize readLen = input.gcount();// ���ش��������һ�ζ�ȡ���ֽ���
        if (readLen > 0) {
            output.write(buffer, readLen);
        }

        if (!output) {
            printf("error occurred while writing data\n");
            delete[]buffer;
            return false;
        }
    }
    delete[]buffer;
    return true;
}

bool FileUtils::AppendWriteByteToFile(const std::string& bytes, const std::string& outputFile) {
    std::ofstream output(outputFile, std::ios::binary | std::ios::app);

    if (WriteByteToOutFile(bytes, output) == false) {
        printf("Failed to write data to output stream, outfile: %s\n", outputFile.c_str());
        return false;
    }
    return true;
}

int FileUtils::WriteInputToOutPut(std::ifstream& input, std::ofstream& output, long length)
{
    char* buffer = new char[FILE_BUFFER_BLOCK];
    long hasReadLen = 0L;
    while (hasReadLen < length && !input.eof()) {
        int readLen = std::min(static_cast<long>(FILE_BUFFER_BLOCK), length - hasReadLen);
        input.read(buffer, readLen);
        if (input.fail() && !input.eof()) {
            printf("error occurred while reading data\n");
            delete[] buffer;
            return -1;
        }
        if (input.gcount() > 0) {
            output.write(buffer, input.gcount());
        }
        if (!output) {
            printf("error occurred while writing data\n");
            delete[] buffer;
            return -1;
        }
        hasReadLen += input.gcount();
    }
    delete[] buffer;
    return 0;
}

bool FileUtils::WriteInputToOutPut(const std::string &input, const std::string &output) {
    std::ifstream in(input, std::ios::binary);
    std::ofstream out(output, std::ios::binary);

    if (in.rdstate() != 0) {
        printf("Failed to get input stream object!\n");
        return false;
    }

    if (out.rdstate() != 0) {
        printf("Failed to get output stream object!\n");
        return false;
    }
   
    char *buffer = new char[FILE_BUFFER_BLOCK]; // ÿ������1M
    while (!in.eof()) {
        in.read(buffer, FILE_BUFFER_BLOCK);

        if (in.fail() && !in.eof()) {
            printf("error occurred while reading data\n");
            delete[]buffer;
            return false;
        }

        std::streamsize readLen = in.gcount();
        if (readLen > 0) {
            out.write(buffer, readLen);
        }

        if (!out) {
            printf("error occurred while writing data\n");
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
    if (WriteByteToOutFile(bytes, ops) == false) {
        printf("Failed to write data to ops, outfile: %s\n", outFile.c_str());
        return false;
    }
    return true;
}

bool FileUtils::WriteByteToOutFile(const std::string& bytes, std::ofstream& outFile)
{
    if (outFile.rdstate() != 0) {
        printf("Failed to get output stream object, outfile\n");
        return false;
    }
    outFile.write(&bytes[0], bytes.size());
    if (outFile.rdstate() != 0) {
        printf("Failed to write data to ops, outfile \n");
        return false;
    }
    outFile.flush();
    if (outFile.rdstate() != 0) {
        printf("Flush error\n");
        return false;
    }
    return true;
}
bool FileUtils::WriteByteToOutFile(const std::vector<int8_t> &bytes, std::ofstream& outFile)
{
    if (outFile.rdstate() != 0) {
        printf("Failed to get output stream object, outfile\n");
        return false;
    }
    outFile.write((char *)&bytes[0], bytes.size());
    if (outFile.rdstate() != 0) {
        printf("Failed to write data to ops, outfile \n");
        return false;
    }
    outFile.flush();
    if (outFile.rdstate() != 0) {
        printf("Flush error\n");
        return false;
    }
    return true;
}
bool FileUtils::IsRunnableFile(const std::string& name)
{
    if (name.empty()) {
        return false;
    }
    if (name.size() >= NUM_THREE && name[name.size() - NUM_THREE] == '.' && name[name.size() - NUM_TWO] == 'a'
        && name[name.size() - 1] == 'n') {
        return true;
    }
    if (name.size() >= NUM_FOUR && name[name.size() - NUM_FOUR] == '.' && name[name.size() - NUM_THREE] == 'a'
        && name[name.size() - NUM_TWO] == 'b' && name[name.size() - 1] == 'c') {
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
    if (!std::filesystem::exists(filePath)) {
        printf("File does not exist !\n");
        return false;
    }
    if (std::filesystem::is_directory(filePath)) {
        printf("It is a directory  %s\n", file.c_str());
        return false;
    }
    return true;
}

int64_t FileUtils::GetFileLen(const std::string &file) {
    std::filesystem::path filePath = file;
    if (std::filesystem::exists(filePath) && std::filesystem::is_regular_file(filePath)) {
        return std::filesystem::file_size(filePath);
    }
    return -1;
}

void FileUtils::DelDir(const std::string& file) {
    std::filesystem::path filePath = file;
    
    // ��������Ŀ¼
    if (std::filesystem::is_directory(filePath)) {
        for (auto &p : std::filesystem::recursive_directory_iterator(filePath)) {
            DelDir(p.path());
        }
    }

    std::filesystem::remove(file);
    return;
}