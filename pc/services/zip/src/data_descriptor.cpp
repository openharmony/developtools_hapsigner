#include "data_descriptor.h"
#include "unsigned_decimal_util.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

DataDescriptor *DataDescriptor::GetDataDescriptor(std::vector<char> &bytes)
{
    if (bytes.size() != DES_LENGTH) {
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }

    ByteBuffer bf(bytes.data(), bytes.size());

    DataDescriptor *data = new DataDescriptor();
    int signValue;
    bf.GetInt32(signValue);
    if (signValue != SIGNATURE) {
        delete data;
        SIGNATURE_TOOLS_LOGE("read Data Descriptor failed");
        return nullptr;
    }
    int crc2Value;
    bf.GetInt32(crc2Value);
    data->SetCrc32(crc2Value);
    data->SetCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));
    data->SetUnCompressedSize(UnsignedDecimalUtil::GetUnsignedInt(bf));

    return data;
}

std::vector<char> DataDescriptor::ToBytes()
{
    ByteBuffer bf(DES_LENGTH);

    bf.PutInt32(SIGNATURE);
    bf.PutInt32(crc32);
    UnsignedDecimalUtil::SetUnsignedInt(bf, compressedSize);
    UnsignedDecimalUtil::SetUnsignedInt(bf, unCompressedSize);

    std::vector<char> retVec(bf.GetBufferPtr(), bf.GetBufferPtr() + bf.GetCapacity());
    return retVec;
}

int DataDescriptor::GetDesLength()
{
    return DES_LENGTH;
}

int DataDescriptor::GetSIGNATURE()
{
    return SIGNATURE;
}

int DataDescriptor::GetCrc32()
{
    return crc32;
}

void DataDescriptor::SetCrc32(int crc32)
{
    this->crc32 = crc32;
}

uint64_t DataDescriptor::GetCompressedSize()
{
    return compressedSize;
}

void DataDescriptor::SetCompressedSize(uint64_t compressedSize)
{
    this->compressedSize = compressedSize;
}

uint64_t DataDescriptor::GetUnCompressedSize()
{
    return unCompressedSize;
}

void DataDescriptor::SetUnCompressedSize(uint64_t unCompressedSize)
{
    this->unCompressedSize = unCompressedSize;
}