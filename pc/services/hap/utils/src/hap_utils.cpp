#include <fstream>
#include <algorithm>
#include <stdexcept>
#include "provision_verify.h"
#include "hap_utils.h"

using namespace OHOS::SignatureTools;

const std::vector<signed char> HapUtils::HAP_SIGNING_BLOCK_MAGIC_V2 =
    std::vector<signed char>{ 0x48, 0x41, 0x50, 0x20, 0x53, 0x69, 0x67, 0x20, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32 };
const std::vector<signed char> HapUtils::HAP_SIGNING_BLOCK_MAGIC_V3 =
    std::vector<signed char>{ 0x3c, 0x68, 0x61, 0x70, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x3e };
const std::string HapUtils::HEX_CHAR_ARRAY = "0123456789ABCDEF";
const std::string HapUtils::HAP_DEBUG_OWNER_ID = "DEBUG_LIB_ID";
std::set<int> HapUtils::HAP_SIGNATURE_OPTIONAL_BLOCK_IDS;
HapUtils::StaticConstructor::StaticConstructor()
{
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROOF_OF_ROTATION_BLOCK_ID);
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROFILE_BLOCK_ID);
    HAP_SIGNATURE_OPTIONAL_BLOCK_IDS.insert(HAP_PROPERTY_BLOCK_ID);
}

HapUtils::StaticConstructor HapUtils::staticConstructor;

HapUtils::HapUtils()
{
}

std::string HapUtils::getAppIdentifier(const std::string& profileContent)
{
    std::pair<std::string, std::string> resultPair = parseAppIdentifier(profileContent);

    std::string ownerID = resultPair.first;
    std::string profileType = resultPair.second;

    if (profileType == "debug") {
        return HAP_DEBUG_OWNER_ID;
    } else if (profileType == "release") {
        return ownerID;
    } else {
        return "";
    }
}

std::pair<std::string, std::string> HapUtils::parseAppIdentifier(const std::string& profileContent)
{
    std::string ownerID;
    std::string profileType;

    ProvisionInfo provisionInfo;
    ParseProfile(profileContent, provisionInfo);

    if (DEBUG == provisionInfo.type) {
        profileType = "debug";
    } else {
        profileType = "release";
    }

    // bundleInfo必存在
    BundleInfo bundleInfo = provisionInfo.bundleInfo;

    if (!bundleInfo.appIdentifier.empty()) {
        ownerID = bundleInfo.appIdentifier;
    }

    return std::pair(ownerID, profileType);
}

std::set<int> HapUtils::GetHapSignatureOptionalBlockIds()
{
    return HAP_SIGNATURE_OPTIONAL_BLOCK_IDS;
}

std::vector<signed char> HapUtils::GetHapSigningBlockMagic(int compatibleVersion)
{
    if (compatibleVersion >= MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3) {
        return HAP_SIGNING_BLOCK_MAGIC_V3;
    }
    return HAP_SIGNING_BLOCK_MAGIC_V2;
}

int HapUtils::GetHapSigningBlockVersion(int compatibleVersion)
{
    if (compatibleVersion >= MIN_COMPATIBLE_VERSION_FOR_SCHEMA_V3) {
        return HAP_SIGN_SCHEME_V3_BLOCK_VERSION;
    }
    return HAP_SIGN_SCHEME_V2_BLOCK_VERSION;
}

bool HapUtils::ReadFileToByteBuffer(const std::string& file, ByteBuffer& buffer)
{
    std::ifstream ifs(file, std::ios::binary);
    if (ifs.is_open()) {
        char* buf = new char[BUFFER_LENGTH];
        while (!ifs.eof()) {
            ifs.read(buf, BUFFER_LENGTH);
            buffer.SetCapacity(ifs.gcount());
            buffer.PutData(buf, ifs.gcount());
        }
        delete[] buf;
        ifs.close();
        return true;
    } else {
        SIGNATURE_TOOLS_LOGE("unable to open %{public}s", file.c_str());
        return false;
    }
}