#ifndef CODE_SIGN_BLOCK_H
#define CODE_SIGN_BLOCK_H
#include <string>
#include <unordered_map>
#include <vector>
#include <map>
#include "code_sign_block_header.h"
#include "segment_header.h"
#include "fs_verity_info_segment.h"
#include "hap_info_segment.h"
#include "native_lib_info_segment.h"
namespace OHOS {
    namespace SignatureTools {
        class CodeSignBlock {
        public:
            CodeSignBlock();
            virtual ~CodeSignBlock();
            void addOneMerkleTree(const std::string& key, std::vector<int8_t>& merkleTree);
            std::vector<int8_t> getOneMerkleTreeByFileName(const std::string& key);
            void setCodeSignBlockFlag();
            void setSegmentNum();
            void addToSegmentList(SegmentHeader sh);
            std::vector<SegmentHeader>& getSegmentHeaderList();
            void setSegmentHeaders();
            CodeSignBlockHeader& getCodeSignBlockHeader();
            void setCodeSignBlockHeader(CodeSignBlockHeader& csbHeader);
            void setFsVerityInfoSegment(FsVerityInfoSegment& fsVeritySeg);
            FsVerityInfoSegment& getFsVerityInfoSegment();
            HapInfoSegment& getHapInfoSegment();
            void setHapInfoSegment(HapInfoSegment& hapSeg);
            NativeLibInfoSegment& getSoInfoSegment();
            void setSoInfoSegment(NativeLibInfoSegment soSeg);
            std::vector<int8_t> toByteArray();
            void computeSegmentOffset();
            long long computeMerkleTreeOffset(long long codeSignBlockOffset);
            std::vector<int8_t> generateCodeSignBlockByte(long long fsvTreeOffset);
            std::string toString();
        public:
            static const long PAGE_SIZE_4K;
            static const int SEGMENT_HEADER_COUNT;
        private:
            CodeSignBlockHeader codeSignBlockHeader;
            std::vector<SegmentHeader> segmentHeaderList;
            FsVerityInfoSegment fsVerityInfoSegment;
            HapInfoSegment hapInfoSegment;
            NativeLibInfoSegment nativeLibInfoSegment;
            std::vector<int8_t> zeroPadding;
            std::map<std::string, std::vector<int8_t>> merkleTreeMap;
        };
    }
}
#endif
