#include "sign_block_data.h"
using namespace OHOS::SignatureTools;
SignBlockData::SignBlockData(std::vector<int8_t> &signData, char type)
{
    this->signData = signData;
    this->type = type;
    this->len = signData.size();
    this->isByte = true;
}

SignBlockData::SignBlockData(std::string &signFile, char type)
{
    this->signFile = signFile;
    this->type = type;
    this->len = FileUtils::GetFileLen(signFile);
    this->isByte = false;
}

char SignBlockData::getType()
{
    return type;
}

void SignBlockData::setType(char type)
{
    this->type = type;
}

std::vector<int8_t> SignBlockData::getBlockHead()
{
    return blockHead;
}

void SignBlockData::setBlockHead(std::vector<int8_t> &blockHead)
{
    this->blockHead = blockHead;
}

std::vector<int8_t> SignBlockData::getSignData()
{
    return signData;
}

void SignBlockData::setSignData(std::vector<int8_t> &signData)
{
    this->signData = signData;
}

std::string SignBlockData::getSignFile()
{
    return signFile;
}

void SignBlockData::setSignFile(std::string signFile)
{
    this->signFile = signFile;
}

long SignBlockData::getLen()
{
    return len;
}

bool SignBlockData::getByte()
{
    return isByte;
}

void SignBlockData::setLen(long len)
{
    this->len = len;
}

void SignBlockData::setByte(bool isByte)
{
    this->isByte = isByte;
}