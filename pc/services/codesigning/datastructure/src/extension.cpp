#include "extension.h"
#include "byte_buffer.h"
using namespace OHOS::SignatureTools;
const int32_t Extension::EXTENSION_HEADER_SIZE = 8;
Extension::Extension()
{
    this->type = 0;
    this->size = 0;
}
Extension::Extension(int32_t type, int32_t size)
{
    this->type = type;
    this->size = size;
}
Extension::~Extension()
{
}
int32_t Extension::getSize()
{
    return Extension::EXTENSION_HEADER_SIZE;
}
bool Extension::isType(int32_t type)
{
    return this->type == type;
}
std::vector<int8_t> Extension::toByteArray()
{
    std::shared_ptr<ByteBuffer> bf = std::make_shared<ByteBuffer>
        (ByteBuffer(Extension::EXTENSION_HEADER_SIZE));
    bf->PutInt32(this->type);
    bf->PutInt32(this->size);
    bf->Flip();
    char dataArr[Extension::EXTENSION_HEADER_SIZE] = { 0 };
    bf->GetData(dataArr, Extension::EXTENSION_HEADER_SIZE);
    std::vector<int8_t> ret(dataArr, dataArr + Extension::EXTENSION_HEADER_SIZE);
    return ret;
}
std::string Extension::toString()
{
    std::string str = "Extension: type[" + std::to_string(this->type) + "], size[" + std::to_string(this->size) + "]";
    return str;
}