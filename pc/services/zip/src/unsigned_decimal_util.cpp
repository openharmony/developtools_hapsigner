#include <vector>
#include "unsigned_decimal_util.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

long long UnsignedDecimalUtil::GetUnsignedInt(ByteBuffer &bf)
{
    uint32_t value;
    bf.GetUInt32(value);
    return value & MAX_UNSIGNED_INT_VALUE;
}

int UnsignedDecimalUtil::GetUnsignedShort(ByteBuffer &bf)
{
    uint16_t value;
    bf.GetUInt16(value);
    return value & MAX_UNSIGNED_SHORT_VALUE;
}

void UnsignedDecimalUtil::SetUnsignedInt(ByteBuffer &bf, long long value)
{
    std::vector<signed char> bytes {
        static_cast<signed char>(value & 0xFF),
        static_cast<signed char>((value >> BIT_SIZE) & 0xFF),
        static_cast<signed char>((value >> DOUBLE_BIT_SIZE) & 0xFF),
        static_cast<signed char>((value >> TRIPLE_BIT_SIZE) & 0xFF)
    };
    bf.PutData((const char *)bytes.data(), bytes.size());
}

void UnsignedDecimalUtil::SetUnsignedShort(ByteBuffer &bf, int value)
{
    std::vector<signed char> bytes {
        static_cast<signed char>(value & 0xFF),
        static_cast<signed char>((value >> BIT_SIZE) & 0xFF)
    };
    bf.PutData((const char *)bytes.data(), bytes.size());
}
