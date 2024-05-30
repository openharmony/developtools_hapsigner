#include "code_sign_block.h"
#include "merkle_tree_extension.h"
using namespace OHOS::SignatureTools;
const long CodeSignBlock::PAGE_SIZE_4K = 4096;
const int CodeSignBlock::SEGMENT_HEADER_COUNT = 3;
CodeSignBlock::CodeSignBlock()
{
}
CodeSignBlock::~CodeSignBlock()
{
}
void CodeSignBlock::addOneMerkleTree(const std::string& key, std::vector<int8_t>& merkleTree)
{
    if (merkleTree.empty()) {
        merkleTreeMap.insert(std::make_pair(key, std::vector<int8_t>(0)));
    } else {
        merkleTreeMap.insert(std::make_pair(key, merkleTree));
    }
}
std::vector<int8_t> CodeSignBlock::getOneMerkleTreeByFileName(const std::string& key)
{
    return this->merkleTreeMap[key];
}
void CodeSignBlock::setCodeSignBlockFlag()
{
    int flags = CodeSignBlockHeader::FLAG_MERKLE_TREE_INLINED;
    if (this->nativeLibInfoSegment.getSectionNum() != 0) {
        flags += CodeSignBlockHeader::FLAG_NATIVE_LIB_INCLUDED;
    }
    this->codeSignBlockHeader.setFlags(flags);
}
void CodeSignBlock::setSegmentNum()
{
    this->codeSignBlockHeader.setSegmentNum(static_cast<int>(segmentHeaderList.size()));
}
void CodeSignBlock::addToSegmentList(SegmentHeader sh)
{
    this->segmentHeaderList.push_back(sh);
}
std::vector<SegmentHeader>& CodeSignBlock::getSegmentHeaderList()
{
    return segmentHeaderList;
}
void CodeSignBlock::setSegmentHeaders()
{
    // fs-verity info segment
    SegmentHeader tempVar(SegmentHeader::CSB_FSVERITY_INFO_SEG, FsVerityInfoSegment::FS_VERITY_INFO_SEGMENT_SIZE);
    segmentHeaderList.push_back(tempVar);
    // hap info segment
    SegmentHeader tempVar2(SegmentHeader::CSB_HAP_META_SEG, this->hapInfoSegment.getSize());
    segmentHeaderList.push_back(tempVar2);
    // native lib info segment
    SegmentHeader tempVar3(SegmentHeader::CSB_NATIVE_LIB_INFO_SEG, this->nativeLibInfoSegment.size());
    segmentHeaderList.push_back(tempVar3);
}
CodeSignBlockHeader& CodeSignBlock::getCodeSignBlockHeader()
{
    return codeSignBlockHeader;
}
void CodeSignBlock::setCodeSignBlockHeader(CodeSignBlockHeader& csbHeader)
{
    codeSignBlockHeader = csbHeader;
}
void CodeSignBlock::setFsVerityInfoSegment(FsVerityInfoSegment& fsVeritySeg)
{
    this->fsVerityInfoSegment = fsVeritySeg;
}
FsVerityInfoSegment& CodeSignBlock::getFsVerityInfoSegment()
{
    return fsVerityInfoSegment;
}
HapInfoSegment& CodeSignBlock::getHapInfoSegment()
{
    return hapInfoSegment;
}
void CodeSignBlock::setHapInfoSegment(HapInfoSegment& hapSeg)
{
    this->hapInfoSegment = hapSeg;
}
NativeLibInfoSegment& CodeSignBlock::getSoInfoSegment()
{
    return nativeLibInfoSegment;
}
void CodeSignBlock::setSoInfoSegment(NativeLibInfoSegment soSeg)
{
    this->nativeLibInfoSegment = soSeg;
}
std::vector<int8_t> CodeSignBlock::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(this->codeSignBlockHeader.getBlockSize()));
    bf->PutData((const char*)this->codeSignBlockHeader.toByteArray().data(),
                this->codeSignBlockHeader.toByteArray().size());
    for (auto sh : this->segmentHeaderList) {
        bf->PutData((char*)(sh.toByteArray().data()), sh.toByteArray().size());
    }
    bf->PutData((char*)this->zeroPadding.data(), this->zeroPadding.size());
    // Hap merkle tree
    bf->PutData((char*)merkleTreeMap["Hap"].data(), merkleTreeMap["Hap"].size());
    bf->PutData((char*)this->fsVerityInfoSegment.toByteArray().data(), this->fsVerityInfoSegment.toByteArray().size());
    bf->PutData((char*)this->hapInfoSegment.toByteArray().data(), this->hapInfoSegment.toByteArray().size());
    bf->PutData((char*)this->nativeLibInfoSegment.toByteArray().data(),
                this->nativeLibInfoSegment.toByteArray().size());
    std::vector<int8_t> ret(bf->GetBufferPtr(), bf->GetBufferPtr() + bf->GetPosition());
    return ret;
}
void CodeSignBlock::computeSegmentOffset()
{
    // 1) the first segment is placed after merkle tree
    int segmentOffset = CodeSignBlockHeader::size()
        + this->segmentHeaderList.size() * SegmentHeader::SEGMENT_HEADER_LENGTH
        + this->zeroPadding.size() + this->getOneMerkleTreeByFileName("Hap").size();
    for (int i = 0; i < segmentHeaderList.size(); i++) {
        segmentHeaderList[i].setSegmentOffset(static_cast<int32_t>(segmentOffset));
        segmentOffset += segmentHeaderList[i].getSegmentSize();
    }
}
long long CodeSignBlock::computeMerkleTreeOffset(long long codeSignBlockOffset)
{
    long long sizeWithoutMerkleTree = CodeSignBlockHeader::size()
        + SEGMENT_HEADER_COUNT * SegmentHeader::SEGMENT_HEADER_LENGTH;
    // add code sign block offset while computing align position for merkle tree
    long long residual = (codeSignBlockOffset + sizeWithoutMerkleTree) % PAGE_SIZE_4K;
    if (residual == 0) {
        this->zeroPadding = std::vector<int8_t>(0);
    } else {
        this->zeroPadding = std::vector<int8_t>(static_cast<int>(PAGE_SIZE_4K - residual));
    }
    return codeSignBlockOffset + sizeWithoutMerkleTree + zeroPadding.size();
}
std::vector<int8_t> CodeSignBlock::generateCodeSignBlockByte(long long fsvTreeOffset)
{
    // 1) compute overall block size without merkle tree
    int64_t csbSize = CodeSignBlockHeader::size()
        + static_cast<long long>(this->segmentHeaderList.size()) * SegmentHeader::SEGMENT_HEADER_LENGTH
        + this->zeroPadding.size()
        + this->getOneMerkleTreeByFileName("Hap").size()
        + this->fsVerityInfoSegment.size()
        + this->hapInfoSegment.getSize()
        + this->nativeLibInfoSegment.size();
    Extension* ext = this->hapInfoSegment.getSignInfo().getExtensionByType(MerkleTreeExtension::MERKLE_TREE_INLINED);
    if (ext != nullptr) {
        MerkleTreeExtension* merkleTreeExtension = (MerkleTreeExtension*)(ext);
        merkleTreeExtension->setMerkleTreeOffset(fsvTreeOffset);
    }
    this->codeSignBlockHeader.setBlockSize(csbSize);
    // 2) generate byte array of complete code sign block
    return toByteArray();
}
std::string CodeSignBlock::toString()
{
    return "";
}