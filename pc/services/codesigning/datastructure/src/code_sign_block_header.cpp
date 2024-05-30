#include "code_sign_block_header.h"
using namespace OHOS::SignatureTools;
CodeSignBlockHeader::CodeSignBlockHeader()
{
    this->magic = MAGIC_NUM;
    this->version = CODE_SIGNING_VERSION;
    this->reserved = std::vector<int8_t>(RESERVED_BYTE_ARRAY_LENGTH);
}
CodeSignBlockHeader::CodeSignBlockHeader(Builder* builder)
{
    this->magic = builder->magic;
    this->version = builder->version;
    this->blockSize = builder->blockSize;
    this->segmentNum = builder->segmentNum;
    this->flags = builder->flags;
    this->reserved = builder->reserved;
}
CodeSignBlockHeader::~CodeSignBlockHeader()
{
}
void CodeSignBlockHeader::setSegmentNum(int num)
{
    this->segmentNum = num;
}
int CodeSignBlockHeader::getSegmentNum()
{
    return segmentNum;
}
void CodeSignBlockHeader::setBlockSize(long long size)
{
    this->blockSize = static_cast<int>(size);
}
int CodeSignBlockHeader::getBlockSize()
{
    return blockSize;
}
void CodeSignBlockHeader::setFlags(int flags)
{
    this->flags = flags;
}
std::vector<int8_t> CodeSignBlockHeader::toByteArray()
{
    ByteBuffer bf(size());
    bf.PutInt64(magic);
    bf.PutInt32(version);
    bf.PutInt32(blockSize);
    bf.PutInt32(segmentNum);
    bf.PutInt32(flags);
    bf.PutData((const char*)reserved.data(), reserved.size());
    std::vector<int8_t> ret(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetPosition());
    return ret;
}
CodeSignBlockHeader* CodeSignBlockHeader::fromByteArray(std::vector<signed char>& bytes)
{
    if (bytes.size() != size()) {
        SIGNATURE_TOOLS_LOGE("Invalid size of CodeSignBlockHeader.\n");
        return nullptr;
    }
    ByteBuffer bf(bytes.size());
    bf.PutData((const char*)bytes.data(), bytes.size());
    bf.Flip();
    long long inMagic;
    bf.GetInt64(inMagic);
    if (inMagic != MAGIC_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid magic num of CodeSignBlockHeader.\n");
        return nullptr;
    }
    int inVersion;
    bf.GetInt32(inVersion);
    if (inVersion != CODE_SIGNING_VERSION) {
        SIGNATURE_TOOLS_LOGE("Invalid version of CodeSignBlockHeader.\n");
        return nullptr;
    }
    int inBlockSize;
    bf.GetInt32(inBlockSize);
    int inSegmentNum;
    bf.GetInt32(inSegmentNum);
    if (inSegmentNum != SEGMENT_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid segmentNum of CodeSignBlockHeader.\n");
        return nullptr;
    }
    int inFlags;
    bf.GetInt32(inFlags);
    if (inFlags < 0 || inFlags >(FLAG_MERKLE_TREE_INLINED + FLAG_NATIVE_LIB_INCLUDED)) {
        SIGNATURE_TOOLS_LOGE("Invalid flags of CodeSignBlockHeader.\n");
        return nullptr;
    }
    std::vector<signed char> inReserved(RESERVED_BYTE_ARRAY_LENGTH);
    bf.GetByte(inReserved.data(), RESERVED_BYTE_ARRAY_LENGTH);
    Builder* tempVar = new Builder();
    return tempVar->setMagic(inMagic)->setVersion(inVersion)->
        setBlockSize(inBlockSize)->setSegmentNum(inSegmentNum)->
        setFlags(inFlags)->setReserved(inReserved)->build();
}
int CodeSignBlockHeader::size()
{
    return MAGIC_BYTE_ARRAY_LENGTH + MAGIC_BYTE_LENGTH * MAGIC_BYTE_LENGTH + RESERVED_BYTE_ARRAY_LENGTH;
}
std::string CodeSignBlockHeader::toString()
{
    return std::string("CodeSignBlockHeader{magic: " + std::to_string(this->magic)
        + ", version: " + std::to_string(this->version)
        + ", blockSize: " + std::to_string(this->blockSize)
        + ", segmentNum: " + std::to_string(this->segmentNum)
        + ", flags: " + std::to_string(this->flags) + "}");
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setMagic(long long magic)
{
    this->magic = magic;
    return this;
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setVersion(int version)
{
    this->version = version;
    return this;
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setBlockSize(int blockSize)
{
    this->blockSize = blockSize;
    return this;
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setSegmentNum(int segmentNum)
{
    this->segmentNum = segmentNum;
    return this;
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setFlags(int flags)
{
    this->flags = flags;
    return this;
}
CodeSignBlockHeader::Builder* CodeSignBlockHeader::Builder::setReserved(std::vector<signed char>& reserved)
{
    this->reserved = reserved;
    return this;
}
CodeSignBlockHeader* CodeSignBlockHeader::Builder::build()
{
    return new CodeSignBlockHeader(this);
}