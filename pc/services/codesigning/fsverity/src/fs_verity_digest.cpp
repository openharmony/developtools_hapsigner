#include "fs_verity_digest.h"
using namespace OHOS::SignatureTools;
const std::string FsVerityDigest::FSVERITY_DIGEST_MAGIC = "FSVerity";
const int FsVerityDigest::DIGEST_HEADER_SIZE = 12;
std::vector<int8_t> FsVerityDigest::GetFsVerityDigest(int8_t algoID, std::vector<int8_t>& digest)
{
    int size = DIGEST_HEADER_SIZE + digest.size();
    std::unique_ptr<ByteBuffer> buffer = std::make_unique<ByteBuffer>(ByteBuffer(size));
    buffer->PutData(FSVERITY_DIGEST_MAGIC.c_str(), (int32_t)FSVERITY_DIGEST_MAGIC.length());
    buffer->PutInt16(algoID);
    buffer->PutInt16((int16_t)digest.size());
    buffer->PutData((char*)digest.data(), digest.size());
    buffer->Flip();
    char* dataArr = new char[size];
    buffer->GetData(dataArr, size);
    std::vector<int8_t> ret(dataArr, dataArr + size);
    delete[] dataArr;
    return ret;
}