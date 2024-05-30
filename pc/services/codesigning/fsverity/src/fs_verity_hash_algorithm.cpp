#include "fs_verity_hash_algorithm.h"
using namespace OHOS::SignatureTools;
const FsVerityHashAlgorithm FsVerityHashAlgorithm::SHA256((char)1, "SHA-256", 256 / 8);
const FsVerityHashAlgorithm FsVerityHashAlgorithm::SHA512((char)2, "SHA-512", 512 / 8);
char FsVerityHashAlgorithm::GetId() const
{
    return id;
}
const std::string& FsVerityHashAlgorithm::GetHashAlgorithm() const
{
    return hashAlgorithm;
}
int FsVerityHashAlgorithm::GetOutputByteSize() const
{
    return outputByteSize;
}