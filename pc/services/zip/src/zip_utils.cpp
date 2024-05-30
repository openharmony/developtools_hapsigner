#include "zip_utils.h"
#include <algorithm>
#include <stdexcept>
#include <string>

using namespace OHOS::SignatureTools;

bool ZipUtils::SetCentralDirectoryOffset(ByteBuffer& eocd, long offset)
{
    if (!SetUInt32ToBuffer(eocd, eocd.GetPosition() + ZIP_CENTRAL_DIR_OFFSET_IN_EOCD, offset)) {
        SIGNATURE_TOOLS_LOGE("Set Central Directory Offset failed.");
        printf("Set Central Directory Offset Failed.\n");
        return false;
    }
    return true;
}

bool ZipUtils::SetUInt32ToBuffer(ByteBuffer& buffer, int offset, long value)
{
    SIGNATURE_TOOLS_LOGI("offset: %{public}d, value: %{public}ld, UINT32_MAX_VALUE: %{public}lu",
                         offset, value, UINT32_MAX_VALUE);
    if ((value < 0) || (value > UINT32_MAX_VALUE)) {
        SIGNATURE_TOOLS_LOGE("invalid_argument. uint32 value of out range: %{public}ld", value);
        return false;
    }
    buffer.PutInt32(offset, static_cast<int>(value));
    return true;
}