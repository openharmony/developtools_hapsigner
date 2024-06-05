#ifndef SIGNERTOOLS_SIGN_BLOCK_DATA_H
#define SIGNERTOOLS_SIGN_BLOCK_DATA_H
#include <string>
#include <vector>
#include "file_utils.h"
namespace OHOS {
    namespace SignatureTools {
        class SignBlockData {
        public:
            SignBlockData(std::vector<int8_t>& signData, char type);
            SignBlockData(std::string &signFile, char type);
            char getType();
            void setType(char type);
            std::vector<int8_t> getBlockHead();
            void setBlockHead(std::vector<int8_t> &blockHead);
            std::vector<int8_t> getSignData();
            void setSignData(std::vector<int8_t> &signData);
            std::string getSignFile();
            void setSignFile(std::string signFile);
            long getLen();
            void setLen(long len);
            void setByte(bool isByte);
            bool getByte();

        private:
            char type;
            std::vector<int8_t> blockHead;
            std::vector<int8_t> signData;
            std::string signFile;
            long len;
            bool isByte;
        };
    }
}
#endif
