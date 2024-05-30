#include "sign_hap.h"
#include "signature_tools_log.h"
#include "signature_algorithm.h"
#include "bc_pkcs7_generator.h"

#define PATH_SIZE 100

using namespace OHOS::SignatureTools;
bool SignHap::Sign(DataSource* contents[], int32_t len, SignerConfig& config,
    std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result)
{
    if (len != CONTENT_NUBER) {
        SIGNATURE_TOOLS_LOGE("contents len[%d] is error, most is [%d]", len, CONTENT_NUBER);
        return false;
    }
    //暂时只支持一个算法。
    std::vector<SignatureAlgorithmClass> algoClass = config.GetSignatureAlgorithms();
    if (algoClass.empty()) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get Signature Algorithms failed please check");
        return false;
    }
    SignatureAlgorithm algo = static_cast<SignatureAlgorithm>(algoClass[0].id);
    SIGNATURE_TOOLS_LOGI("[SignHap] Signature Algorithm  is %d", algo);
    int32_t nId = HapVerifyOpensslUtils::GetDigestAlgorithmId(algo);
    DigestParameter digestParam = HapSigningBlockUtils::GetDigestParameter(nId);
    ByteBuffer dig_context;
    std::vector<std::pair<int32_t, ByteBuffer>> nidAndcontentDigestsVec;
    //1:对应content和optionalBlock进行摘要
    if (!ComputeDigests(digestParam, contents, CONTENT_NUBER, optionalBlocks, dig_context)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] compute Digests failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("[SignHap] ComputeDigests %{public}d", dig_context.GetCapacity());
    //2:编码摘要信息
    ByteBuffer dig_message;
    std::pair<int32_t, ByteBuffer> nidAndcontentDigests = std::make_pair(algo, dig_context);
    nidAndcontentDigestsVec.push_back(nidAndcontentDigests);
    if (!EncodeListOfPairsToByteArray(digestParam, nidAndcontentDigestsVec, dig_message)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] encode ListOfPairs To ByteArray failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("[SignHap] EncodeListOfPairsToByteArray %{public}d", dig_message.GetCapacity());
    //3:对编码后的摘要信息进行加密。康兵
    std::shared_ptr<Pkcs7Generator> pkcs7Generator = std::make_shared<BCPkcs7Generator>();
    std::string dig_message_data(dig_message.GetBufferPtr(), dig_message.GetCapacity());
    std::string ret;
    if (pkcs7Generator->GenerateSignedData(dig_message_data, &config, ret) != 0) {
        SIGNATURE_TOOLS_LOGE("[SignHap] Generate Signed Data failed");
        return false;
    }
    std::vector<char> hapSignatureSchemeBlock(ret.begin(), ret.end());
    SIGNATURE_TOOLS_LOGI("[SignHap] GenerateSignedData %{public}lu", static_cast<unsigned long>(ret.size()));
    if (!GenerateHapSigningBlock(hapSignatureSchemeBlock, optionalBlocks, config.GetCompatibleVersion(), result)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] Generate HapSigning Block failed");
        return false;
    }
    SIGNATURE_TOOLS_LOGI("[SignHap] GenerateHapSigningBlock %{public}d", result.GetCapacity());
    return true;
}
bool SignHap::ComputeDigests(const DigestParameter& digestParam, DataSource* contents[], int32_t len,
    const std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result)
{
    ByteBuffer chunkDigest;
    if (!HapSigningBlockUtils::ComputeDigestsForEachChunk(digestParam, contents, len, chunkDigest)) {
        SIGNATURE_TOOLS_LOGE("Compute Content Digests failed");
        return false;
    }
    if (!HapSigningBlockUtils::ComputeDigestsWithOptionalBlock(digestParam, optionalBlocks, chunkDigest, result)) {
        SIGNATURE_TOOLS_LOGE("Compute Final Digests failed");
        return false;
    }
    return true;
}
bool SignHap::EncodeListOfPairsToByteArray(const DigestParameter& digestParam,
    const std::vector<std::pair<int32_t, ByteBuffer>>& nidAndcontentDigests, ByteBuffer& result)
{
    int encodeSize = 0;
    encodeSize += INT_SIZE + INT_SIZE;
    for (const auto& pair : nidAndcontentDigests) {
        if (pair.second.GetCapacity() != digestParam.digestOutputSizeBytes) {
            SIGNATURE_TOOLS_LOGE(" encode ListOfPairs To ByteArray dig or Summary Algorithm is mismatch");
            return false;
        }
        encodeSize += INT_SIZE + INT_SIZE + INT_SIZE + pair.second.GetCapacity();
    }
    result.SetCapacity(encodeSize);
    result.PutInt32(CONTENT_VERSION); // version
    result.PutInt32(BLOCK_NUMBER); // block number
    for (const auto& pair : nidAndcontentDigests) {
        auto second = pair.second;
        result.PutInt32(INT_SIZE + INT_SIZE + second.GetCapacity());
        result.PutInt32(pair.first);
        result.PutInt32(second.GetCapacity());
        result.Put(second);
    }
    return true;
}
bool SignHap::GenerateHapSigningBlock(std::vector<char>& hapSignatureSchemeBlock,
    std::vector<OptionalBlock>& optionalBlocks, int compatibleVersion, ByteBuffer& result)
{
    // FORMAT:
    // Proof-of-Rotation pairs(optional):
    // uint32:type
    // uint32:length
    // uint32:offset
    // Property pairs(optional):
    // uint32:type
    // uint32:length
    // uint32:offset
    // Profile capability pairs(optional):
    // uint32:type
    // uint32:length
    // uint32:offset
    // length bytes : app signing pairs
    // uint32:type
    // uint32:length
    // uint32:offset
    // repeated ID-value pairs(reserved extensions):
    // length bytes : Proof-of-Rotation values
    // length bytes : property values
    // length bytes : profile capability values
    // length bytes : signature schema values
    // uint64: size
    // uint128: magic
    // uint32: version
    long optionalBlockSize = 0L;
    for (const auto& elem : optionalBlocks) optionalBlockSize += elem.optionalBlockValue.GetCapacity();
    long resultSize = ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE + OPTIONAL_OFFSET_SIZE) * (optionalBlocks.size() + 1))
        + optionalBlockSize // optional pair
        + hapSignatureSchemeBlock.size() // App signing pairs
        + BLOCK_COUNT // block count
        + HapUtils::BLOCK_SIZE // size
        + BLOCK_MAGIC // magic
        + BLOCK_VERSION; // version
    if (resultSize > INT_MAX) {
        SIGNATURE_TOOLS_LOGE("Illegal Argument. HapSigningBlock out of range: %{public}ld", resultSize);
        return false;
    }
    result.SetCapacity((int)resultSize);
    std::unordered_map<int, int> typeAndOffsetMap;
    int currentOffset = ((OPTIONAL_TYPE_SIZE + OPTIONAL_LENGTH_SIZE
        + OPTIONAL_OFFSET_SIZE) * (optionalBlocks.size() + 1));
    int currentOffsetInBlockValue = 0;
    int blockValueSizes = (int)(optionalBlockSize + hapSignatureSchemeBlock.size());
    char* blockValues = new char[blockValueSizes];
    for (const auto& elem : optionalBlocks) {
        memcpy_s(blockValues + currentOffsetInBlockValue,
            blockValueSizes,
            elem.optionalBlockValue.GetBufferPtr(),
            elem.optionalBlockValue.GetCapacity());
        typeAndOffsetMap.insert({ elem.optionalType, currentOffset });
        currentOffset += elem.optionalBlockValue.GetCapacity();
        currentOffsetInBlockValue += elem.optionalBlockValue.GetCapacity();
    }
    memcpy_s(blockValues + currentOffsetInBlockValue,
        blockValueSizes,
        hapSignatureSchemeBlock.data(),
        hapSignatureSchemeBlock.size());
    typeAndOffsetMap.insert({ HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID, currentOffset });
    ExtractedResult(optionalBlocks, result, typeAndOffsetMap);
    result.PutInt32(HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID); // type
    result.PutInt32(hapSignatureSchemeBlock.size()); // length
    int offset = typeAndOffsetMap.at(HapUtils::HAP_SIGNATURE_SCHEME_V1_BLOCK_ID);
    result.PutInt32(offset); // offset
    result.PutData(blockValues, blockValueSizes);
    result.PutInt32(optionalBlocks.size() + 1); // Signing block count
    result.PutInt64(resultSize); // length of hap signing block
    std::vector<signed char> signingBlockMagic = HapUtils::GetHapSigningBlockMagic(compatibleVersion);
    result.PutData((const char*)signingBlockMagic.data(), signingBlockMagic.size()); // magic
    result.PutInt32(HapUtils::GetHapSigningBlockVersion(compatibleVersion)); // version
    delete[] blockValues;
    return true;
}
void SignHap::ExtractedResult(std::vector<OptionalBlock>& optionalBlocks, ByteBuffer& result,
    std::unordered_map<int, int>& typeAndOffsetMap)
{
    int offset;
    for (const auto& elem : optionalBlocks) {
        result.PutInt32(elem.optionalType);  // type
        result.PutInt32(elem.optionalBlockValue.GetCapacity());  // length
        offset = typeAndOffsetMap.at(elem.optionalType);
        result.PutInt32(offset);  // offset
    }
}