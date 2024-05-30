#include <string>
#include <stdexcept>
#include <mutex>
#include "random_access_file_zip_data_output.h"
#include "signature_tools_log.h"

using namespace OHOS::SignatureTools;

RandomAccessFileZipDataOutput::RandomAccessFileZipDataOutput(RandomAccessFile* file)
    : RandomAccessFileZipDataOutput(file, 0)
{
}

RandomAccessFileZipDataOutput::RandomAccessFileZipDataOutput(RandomAccessFile* file, long startPosition)
    : file(file)
{
    if (startPosition < 0) {
        SIGNATURE_TOOLS_LOGE("invalide start position: %{public}ld", startPosition);
        return;
    }
    this->position = startPosition;
}

bool RandomAccessFileZipDataOutput::Write(ByteBuffer& buffer)
{
    int length = buffer.GetCapacity();
    if (length == 0) {
        return false;
    }
    {
        std::mutex tmpMutex;
        std::scoped_lock lock(tmpMutex);
        if (file->WriteToFile(buffer, position, length) < 0) return false;
        position += length;
    }
    return true;
}
