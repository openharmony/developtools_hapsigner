/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "sign_info.h"
using namespace OHOS::SignatureTools;
/***** SignInfo类 ****/
const int32_t SignInfo::FLAG_MERKLE_TREE_INCLUDED = 0x1;
const int32_t SignInfo::MAX_EXTENSION_NUM = 1;
const int32_t SignInfo::SIGN_INFO_SIZE_WITHOUT_SIGNATURE = 60;
const int32_t SignInfo::SALT_BUFFER_LENGTH = 32;
const int32_t SignInfo::SIGNATURE_ALIGNMENT = 4;
SignInfo::SignInfo()
{
    this->saltSize = 0;
    this->sigSize = 0;
    this->flags = 0;
    this->dataSize = 0;
    this->salt = std::vector<int8_t>();
    this->extensionNum = 0;
    this->extensionOffset = 0;
    this->signature = std::vector<int8_t>();
    this->zeroPadding = std::vector<int8_t>();
}
SignInfo::SignInfo(int32_t saltSize,
    int32_t flags,
    int64_t dataSize,
    std::vector<int8_t> salt,
    std::vector<int8_t> sig)
{
    this->saltSize = saltSize;
    this->flags = flags;
    this->dataSize = dataSize;
    if (salt.empty()) {
        this->salt = std::vector<int8_t>(SALT_BUFFER_LENGTH, 0);
    } else {
        this->salt = salt;
    }
    this->signature = sig;
    this->sigSize = sig.empty() ? 0 : sig.size();
    // align for extension after signature
    this->zeroPadding = std::vector<int8_t>((SignInfo::SIGNATURE_ALIGNMENT
        - (this->sigSize % SignInfo::SIGNATURE_ALIGNMENT))
        % SignInfo::SIGNATURE_ALIGNMENT, 0);
    this->extensionNum = 0;
    this->extensionOffset = 0;
}
SignInfo::SignInfo(int32_t saltSize,
    int32_t sigSize,
    int32_t flags,
    int64_t dataSize,
    std::vector<int8_t> salt,
    int32_t extensionNum,
    int32_t extensionOffset,
    std::vector<int8_t> signature,
    std::vector<int8_t> zeroPadding,
    std::vector<MerkleTreeExtension*> extensionList)
{
    this->saltSize = saltSize;
    this->sigSize = sigSize;
    this->flags = flags;
    this->dataSize = dataSize;
    this->salt = salt;
    this->extensionNum = extensionNum;
    this->extensionOffset = extensionOffset;
    this->signature = signature;
    this->zeroPadding = zeroPadding;
    this->extensionList = extensionList;
}
SignInfo::SignInfo(const SignInfo& other)
{
    this->saltSize = other.saltSize;
    this->sigSize = other.sigSize;
    this->flags = other.flags;
    this->dataSize = other.dataSize;
    this->salt = other.salt;
    this->extensionNum = other.extensionNum;
    this->extensionOffset = other.extensionOffset;
    this->signature = other.signature;
    this->zeroPadding = other.zeroPadding;
    for (MerkleTreeExtension* ext : other.extensionList) {
        MerkleTreeExtension* extTmp = new MerkleTreeExtension(*(MerkleTreeExtension*)(ext));
        this->extensionList.push_back(extTmp);
    }
}
SignInfo& SignInfo::operator=(const SignInfo& other)
{
    if (this == &other) {
        return *this;
    }
    this->saltSize = other.saltSize;
    this->sigSize = other.sigSize;
    this->flags = other.flags;
    this->dataSize = other.dataSize;
    this->salt = other.salt;
    this->extensionNum = other.extensionNum;
    this->extensionOffset = other.extensionOffset;
    this->signature = other.signature;
    this->zeroPadding = other.zeroPadding;
    for (Extension* ext : other.extensionList) {
        MerkleTreeExtension* extTmp = new MerkleTreeExtension(*(MerkleTreeExtension*)(ext));
        this->extensionList.push_back(extTmp);
    }
    return *this;
}
SignInfo::~SignInfo()
{
    for (Extension* ext : this->extensionList) {
        if (ext) {
            delete ext;
            ext = nullptr;
        }
    }
}
int32_t SignInfo::getSize()
{
    int blockSize = SignInfo::SIGN_INFO_SIZE_WITHOUT_SIGNATURE + this->signature.size() + this->zeroPadding.size();
    for (Extension* ext : this->extensionList) {
        blockSize += ext->getSize();
    }
    return blockSize;
}
void SignInfo::addExtension(MerkleTreeExtension* extension)
{
    this->extensionOffset = this->getSize();
    this->extensionList.push_back(extension);
    this->extensionNum = this->extensionList.size();
}
Extension* SignInfo::getExtensionByType(int32_t type)
{
    for (Extension* ext : this->extensionList) {
        if (ext->isType(type)) {
            return ext;
        }
    }
    return nullptr;
}
int32_t SignInfo::getExtensionNum()
{
    return extensionNum;
}
std::vector<int8_t> SignInfo::getSignature()
{
    return signature;
}
int64_t SignInfo::getDataSize()
{
    return dataSize;
}
std::vector<int8_t> SignInfo::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(getSize()));
    std::vector<int8_t> empt(getSize());
    bf->PutData((char*)empt.data(), empt.size());
    bf->Clear();
    bf->PutInt32(this->saltSize);
    bf->PutInt32(this->sigSize);
    bf->PutInt32(this->flags);
    bf->PutInt64(this->dataSize);
    bf->PutData((char*)this->salt.data(), this->salt.size());
    bf->PutInt32(this->extensionNum);
    bf->PutInt32(this->extensionOffset);
    bf->PutData((char*)this->signature.data(), this->signature.size());
    bf->PutData((char*)this->zeroPadding.data(), this->zeroPadding.size());
    // put extension
    for (Extension* ext : this->extensionList) {
        bf->PutData((char*)ext->toByteArray().data(), ext->toByteArray().size());
    }
    bf->Flip();
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf.get()->GetCapacity());
    return ret;
}
std::vector<MerkleTreeExtension*> SignInfo::parseMerkleTreeExtension(ByteBuffer* bf, int32_t inExtensionNum)
{
    std::vector<MerkleTreeExtension*> inExtensionList;
    if (inExtensionNum == 1) {
        // parse merkle tree extension
        int32_t extensionType = 0;
        bf->GetInt32(extensionType);
        if (extensionType != MerkleTreeExtension::MERKLE_TREE_INLINED) {
            SIGNATURE_TOOLS_LOGE("Invalid extensionType of SignInfo");
            return inExtensionList;
        }
        int32_t extensionSize = 0;
        bf->GetInt32(extensionSize);
        if (extensionSize != MerkleTreeExtension::MERKLE_TREE_EXTENSION_DATA_SIZE) {
            SIGNATURE_TOOLS_LOGE("Invalid extensionSize of SignInfo");
            return inExtensionList;
        }
        std::vector<int8_t> merkleTreeExtension(MerkleTreeExtension::MERKLE_TREE_EXTENSION_DATA_SIZE, 0);
        bf->GetData((char*)merkleTreeExtension.data(), merkleTreeExtension.size());
        MerkleTreeExtension* pMerkleTreeExtension = MerkleTreeExtension::fromByteArray(merkleTreeExtension);
        if (pMerkleTreeExtension) {
            inExtensionList.push_back(pMerkleTreeExtension);
        }
    }
    return inExtensionList;
}
SignInfo SignInfo::fromByteArray(std::vector<int8_t> bytes)
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>(ByteBuffer(bytes.size()));
    bf->PutData((char*)bytes.data(), bytes.size());
    bf->Flip();
    int32_t inSaltSize = 0;
    bf->GetInt32(inSaltSize);
    if (inSaltSize < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid saltSize of SignInfo");
        return SignInfo();
    }
    int32_t inSigSize = 0;
    bf->GetInt32(inSigSize);
    if (inSigSize < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid sigSize of SignInfo");
        return SignInfo();
    }
    int32_t inFlags = 0;
    bf->GetInt32(inFlags);
    if (inFlags != 0 && inFlags != SignInfo::FLAG_MERKLE_TREE_INCLUDED) {
        SIGNATURE_TOOLS_LOGE("Invalid flags of SignInfo");
        return SignInfo();
    }
    long long inDataSize = 0;
    bf->GetInt64(inDataSize);
    if (inDataSize < 0) {
        SIGNATURE_TOOLS_LOGE("Invalid dataSize of SignInfo");
        return SignInfo();
    }
    std::vector<int8_t> inSalt(SignInfo::SALT_BUFFER_LENGTH, 0);
    bf->GetData((char*)inSalt.data(), SignInfo::SALT_BUFFER_LENGTH);
    int32_t inExtensionNum = 0;
    bf->GetInt32(inExtensionNum);
    if (inExtensionNum < 0 || inExtensionNum > SignInfo::MAX_EXTENSION_NUM) {
        SIGNATURE_TOOLS_LOGE("Invalid extensionNum of SignInfo");
        return SignInfo();
    }
    int32_t inExtensionOffset = 0;
    bf->GetInt32(inExtensionOffset);
    if (inExtensionOffset < 0 || inExtensionOffset % SignInfo::SIGNATURE_ALIGNMENT != 0) {
        SIGNATURE_TOOLS_LOGE("Invalid extensionOffset of SignInfo");
        return SignInfo();
    }
    std::vector<int8_t> inSignature(inSigSize, 0);
    bf->GetData((char*)inSignature.data(), inSigSize);
    std::vector<int8_t> inZeroPadding((SignInfo::SIGNATURE_ALIGNMENT - (inSigSize % SignInfo::SIGNATURE_ALIGNMENT))
        % SignInfo::SIGNATURE_ALIGNMENT, 0);
    bf->GetData((char*)inZeroPadding.data(), inZeroPadding.size());
    std::vector<MerkleTreeExtension*> inExtensionList = parseMerkleTreeExtension(bf.get(), inExtensionNum);
    return SignInfo(inSaltSize, inSigSize, inFlags, inDataSize, inSalt, inExtensionNum, inExtensionOffset,
        inSignature, inZeroPadding, inExtensionList);
}