#include "byte_buffer.h"
#include "signature_tools_log.h"
#include "securec.h"
#include <cstdio>
#include <algorithm>
#define EOK 0
namespace OHOS {
    namespace SignatureTools {
        const int32_t ByteBuffer::MAX_PRINT_LENGTH = 200;
        const int32_t ByteBuffer::HEX_PRINT_LENGTH = 3;
        template<typename T>
        std::shared_ptr<T> make_shared_array(size_t size)
        {
            T* buffer = new T[size];
            return std::shared_ptr<T>(buffer, [](T* p) {
                delete[] p;
                });
        }
        ByteBuffer::ByteBuffer() : buffer(nullptr), position(0), limit(0), capacity(0)
        {
        }
        ByteBuffer::ByteBuffer(int32_t bufferCapacity) : buffer(nullptr), position(0), limit(0), capacity(0)
        {
            Init(bufferCapacity);
        }
        ByteBuffer::ByteBuffer(const char* arr, int32_t length) : buffer(nullptr), position(0), limit(0), capacity(0)
        {
            Init(length);
            this->PutData(0, arr, length);
        }
        ByteBuffer::ByteBuffer(const ByteBuffer& other) : buffer(nullptr), position(0), limit(0), capacity(0)
        {
            Init(other.GetCapacity());
            if (buffer != nullptr && capacity > 0) {
                if (memcpy_s(buffer.get(), capacity, other.GetBufferPtr(), other.GetCapacity()) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                    return;
                }
                position = other.GetPosition();
                limit = other.GetLimit();
            }
        }
        ByteBuffer::~ByteBuffer()
        {
            buffer = nullptr;
        }
        void ByteBuffer::Init(int32_t bufferCapacity)
        {
            if (bufferCapacity > 0) {
                buffer = make_shared_array<char>(bufferCapacity);
                if (buffer != nullptr) {
                    memset_s(buffer.get(), bufferCapacity, 0, bufferCapacity);
                    limit = bufferCapacity;
                    capacity = bufferCapacity;
                }
            } else {
                SIGNATURE_TOOLS_LOGE("bufferCapacity %d is too small", bufferCapacity);
            }
        }
        ByteBuffer& ByteBuffer::operator=(const ByteBuffer& other)
        {
            if (&other == this) {
                return *this;
            }
            // std::unique_ptr reset()，will first release the original object and then point to the new object
            buffer = nullptr;
            Init(other.GetCapacity());
            if (buffer != nullptr && other.GetBufferPtr() != nullptr && capacity > 0) {
                if (memcpy_s(buffer.get(), capacity, other.GetBufferPtr(), other.GetCapacity()) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                    return *this;
                }
                position = other.GetPosition();
                limit = other.GetLimit();
            }
            return *this;
        }
        bool ByteBuffer::CheckInputForGettingData(int32_t index, int32_t dataLen)
        {
            if (buffer == nullptr) {
                SIGNATURE_TOOLS_LOGE("buffer is nullptr");
                return false;
            }
            if (index < 0) {
                SIGNATURE_TOOLS_LOGE("invalid index %d", index);
                return false;
            }
            long long getDataLast = static_cast<long long>(position) + static_cast<long long>(index) +
                static_cast<long long>(dataLen);
            if (getDataLast > static_cast<long long>(limit)) {
                SIGNATURE_TOOLS_LOGE("position %d, index  %d, limit %d", position, index, limit);
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetInt64(long long& value)
        {
            if (!GetInt64(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetInt64 failed");
                return false;
            }
            position += sizeof(long long);
            return true;
        }
        bool ByteBuffer::GetInt64(int32_t index, long long& value)
        {
            if (!CheckInputForGettingData(index, sizeof(long long))) {
                SIGNATURE_TOOLS_LOGE("Failed to get Int64");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(long long)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        int32_t ByteBuffer::GetCapacity() const
        {
            return capacity;
        }
        const char* ByteBuffer::GetBufferPtr() const
        {
            return buffer.get();
        }
        bool ByteBuffer::GetInt32(int32_t& value)
        {
            if (!GetInt32(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetInt32 failed");
                return false;
            }
            position += sizeof(int32_t);
            return true;
        }
        bool ByteBuffer::GetInt32(int32_t index, int32_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(int32_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get Int32");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(int32_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetUInt32(int32_t index, uint32_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(uint32_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get UInt32");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(uint32_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetUInt32(uint32_t& value)
        {
            if (!GetUInt32(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetUInt32 failed");
                return false;
            }
            position += sizeof(uint32_t);
            return true;
        }
        bool ByteBuffer::GetUInt16(uint16_t& value)
        {
            if (!GetUInt16(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetUInt16 failed");
                return false;
            }
            position += sizeof(uint16_t);
            return true;
        }
        bool ByteBuffer::GetUInt16(int32_t index, uint16_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(uint16_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get UInt16");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(uint16_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetInt16(int16_t& value)
        {
            if (!GetInt16(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetInt16 failed");
                return false;
            }
            position += sizeof(int16_t);
            return true;
        }
        bool ByteBuffer::GetInt16(int32_t index, int16_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(int16_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get Int16");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(int16_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetUInt8(uint8_t& value)
        {
            if (!GetUInt8(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetUInt8 failed");
                return false;
            }
            position += sizeof(uint8_t);
            return true;
        }
        bool ByteBuffer::GetUInt8(int32_t index, uint8_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(uint8_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get UInt8");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(uint8_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        bool ByteBuffer::GetInt8(int8_t& value)
        {
            if (!GetInt8(0, value)) {
                SIGNATURE_TOOLS_LOGE("GetInt8 failed");
                return false;
            }
            position += sizeof(int8_t);
            return true;
        }
        bool ByteBuffer::GetInt8(int32_t index, int8_t& value)
        {
            if (!CheckInputForGettingData(index, sizeof(int8_t))) {
                SIGNATURE_TOOLS_LOGE("Failed to get Int8");
                return false;
            }
            if (memcpy_s(&value, sizeof(value), (buffer.get() + position + index), sizeof(int8_t)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return false;
            }
            return true;
        }
        void ByteBuffer::PutInt64(int64_t value)
        {
            if (limit - position >= static_cast<int64_t>(sizeof(value))) {
                if (memcpy_s(buffer.get() + position, limit - position, &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += sizeof(value);
                }
            }
        }
        void ByteBuffer::PutInt32(int32_t offset, int32_t value)
        {
            if (buffer != nullptr && offset >= 0 && limit - offset >= static_cast<int32_t>(sizeof(value))) {
                if (memcpy_s((buffer.get() + offset), (limit - offset), &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                }
            }
        }
        void ByteBuffer::PutInt16(int32_t offset, int16_t value)
        {
            if (buffer != nullptr && offset >= 0 && limit - offset >= static_cast<int16_t>(sizeof(value))) {
                if (memcpy_s((buffer.get() + offset), (limit - offset), &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                }
            }
        }
        void ByteBuffer::PutByte(int32_t offset, char value)
        {
            if (buffer != nullptr && offset >= 0 && limit - offset >= static_cast<int32_t>(sizeof(value))) {
                if (memcpy_s((buffer.get() + offset), (limit - offset), (&value), sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                }
            }
        }
        void ByteBuffer::PutData(int32_t offset, const char data[], int32_t len)
        {
            if (buffer != nullptr && data != nullptr && offset >= 0 && len > 0 && (limit - offset) >= len) {
                if (memcpy_s((buffer.get() + offset), (limit - offset), data, len) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                }
            }
        }
        void ByteBuffer::PutData(int32_t offset, const char data[], int32_t len, int32_t type)
        {
            static int offset_add = 0;
            if (buffer != nullptr && data != nullptr && offset >= 0 && len > 0 && (limit - offset) >= len) {
                if (memcpy_s((buffer.get() + offset_add), (limit - offset_add), data, len) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                }
                offset_add += offset;
            }
        }
        void ByteBuffer::PutInt32(int32_t value)
        {
            if (limit - position >= static_cast<int32_t>(sizeof(value))) {
                if (memcpy_s(buffer.get() + position, limit - position, &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += sizeof(value);
                }
            }
        }
        void ByteBuffer::PutInt16(int16_t value)
        {
            if (limit - position >= static_cast<int16_t>(sizeof(value))) {
                if (memcpy_s(buffer.get() + position, limit - position, &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += sizeof(value);
                }
            }
        }
        void ByteBuffer::PutUInt8(uint8_t value)
        {
            if (limit - position >= static_cast<int8_t>(sizeof(value))) {
                if (memcpy_s(buffer.get() + position, limit - position, &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += sizeof(value);
                }
            }
        }
        void ByteBuffer::ClearData()
        {
            if (buffer != nullptr && position < capacity) {
                memset_s(buffer.get() + position, capacity - position, 0, capacity - position);
            }
        }
        void ByteBuffer::PutByte(char value)
        {
            if (buffer != nullptr && limit - position >= static_cast<char>(sizeof(value))) {
                if (memcpy_s(buffer.get() + position, limit - position, &value, sizeof(value)) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += sizeof(value);
                }
            }
        }
        void ByteBuffer::Put(const ByteBuffer& byteBuffer)
        {
            this->PutData(byteBuffer.GetBufferPtr(), byteBuffer.Remaining());
        }
        void ByteBuffer::PutData(const char data[], int32_t len)
        {
            if (buffer != nullptr && data != nullptr && len > 0 && (limit - position) >= len) {
                if (memcpy_s((buffer.get() + position), (limit - position), data, len) != EOK) {
                    SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                } else {
                    position += len;
                }
            }
        }
        void ByteBuffer::GetByte(int8_t data[], int32_t len)
        {
            if (0 == memcpy_s(data, len, buffer.get() + position, len)) {
                position = position + len;
            }
        }
        std::string ByteBuffer::GetData(int32_t len)
        {
            std::unique_ptr<char[]> pData = std::make_unique<char[]>(len);
            if (0 == memcpy_s(pData.get(), len, buffer.get() + position, len)) {
                position = position + len;
            }
            return std::string(pData.get());
        }
        void ByteBuffer::GetData(char data[], int32_t len)
        {
            if (0 == memcpy_s(data, len, buffer.get() + position, len)) {
                position = position + len;
            }
        }
        void ByteBuffer::GetData(int32_t offset, char data[], int32_t len)
        {
            if (0 == memcpy_s(data, len, buffer.get() + offset, len)) {
                position = position + len;
            }
        }
        void ByteBuffer::SetPosition(int32_t pos)
        {
            if (pos >= 0 && pos <= limit) {
                position = pos;
            }
        }
        ByteBuffer& ByteBuffer::slice_for_codesigning()
        {
            if (position >= capacity || limit > capacity || position >= limit || buffer == nullptr) {
                SIGNATURE_TOOLS_LOGE("position %d capacity %d limit %d error", position, capacity, limit);
                return *this;
            }
            int32_t rem = (position <= limit ? limit - position : 0);

            position = 0;
            capacity = rem;
            limit = rem;
            return *this;
        }
        ByteBuffer& ByteBuffer::Slice()
        {
            if (position >= capacity || limit > capacity || position >= limit || buffer == nullptr) {
                SIGNATURE_TOOLS_LOGE("position %{public}d capacity %{public}d limit %{public}d error",
                    position, capacity, limit);
                return *this;
            }
            int32_t newCapacity = limit - position;
            char* newBuffer = new char[newCapacity];
            if (memcpy_s(newBuffer, newCapacity, (buffer.get() + position), (limit - position)) != EOK) {
                SIGNATURE_TOOLS_LOGE("memcpy_s failed");
                return *this;
            }
            buffer.reset(newBuffer);
            position = 0;
            capacity = newCapacity;
            limit = capacity;
            return *this;
        }
        bool ByteBuffer::ReverseSliceBuffer(int startPos, int endPos, ByteBuffer& ret)
        {
            char* blockPtr = this->buffer.get();
            int blockCapacity = this->capacity;
            int length = endPos - startPos;
            if ((startPos + blockPtr > blockPtr + blockCapacity || startPos + blockPtr < blockPtr) ||
                (endPos + blockPtr > blockPtr + blockCapacity || endPos + blockPtr < blockPtr)) {
                SIGNATURE_TOOLS_LOGE("invalid parameter\n");
                return false;
            }
            ret.Clear();
            ret.SetCapacity(length);
            ret.PutData(blockPtr + startPos, length);
            ret.SetPosition(0);
            std::reverse(ret.buffer.get(), ret.buffer.get() + ret.capacity);
            return true;
        }
        ByteBuffer* ByteBuffer::Duplicate()
        {
            //std::unique_ptr<ByteBuffer> newBuffer = std::make_unique<ByteBuffer>(capacity);
            //std::unique_ptr<char[]> newData = std::make_unique<char[]>(capacity);
            ByteBuffer* newBuffer = new ByteBuffer();
            newBuffer->buffer = this->buffer;
            newBuffer->limit = this->limit;
            newBuffer->capacity = this->capacity;
            newBuffer->position = this->position;
            return newBuffer;
        }
        int32_t ByteBuffer::GetPosition() const
        {
            return position;
        }
        int32_t ByteBuffer::GetLimit() const
        {
            return limit;
        }
        void ByteBuffer::SetLimit(int32_t lim)
        {
            if (lim <= capacity && lim >= position) {
                limit = lim;
            }
        }
        int32_t ByteBuffer::Remaining() const
        {
            return position < limit ? limit - position : 0;
        }
        bool ByteBuffer::HasRemaining() const
        {
            return position < limit;
        }
        void ByteBuffer::Clear()
        {
            position = 0;
            limit = capacity;
        }
        ByteBuffer& ByteBuffer::Flip()
        {
            limit = position;
            position = 0;
            return *this;
        }
        ByteBuffer& ByteBuffer::Compact()
        {
            do {
                if (position >= limit) {
                    position = 0;
                    break;
                }
                for (uint32_t i = 0; i < limit - position; i++) {
                    buffer.get()[i] = buffer.get()[position + i];
                }
                position = limit - position;
            } while (0);
            limit = capacity;
            return *this;
        }
        bool ByteBuffer::IsEqual(const ByteBuffer& other)
        {
            if (&other == this) {
                return true;
            }
            if (capacity != other.GetCapacity() || other.GetBufferPtr() == nullptr || buffer == nullptr) {
                SIGNATURE_TOOLS_LOGE("invalid input");
                return false;
            }
            const char* otherBuffer = other.GetBufferPtr();
            for (int32_t i = 0; i < capacity; i++) {
                if (buffer.get()[i] != otherBuffer[i]) {
                    SIGNATURE_TOOLS_LOGE("diff value[%d]: %x %x",
                        i, buffer.get()[i], otherBuffer[i]);
                    return false;
                }
            }
            return true;
        }
        bool ByteBuffer::IsEqual(const std::string& other)
        {
            if (capacity != static_cast<int32_t>(other.size()) || buffer == nullptr) {
                SIGNATURE_TOOLS_LOGE("invalid input");
                return false;
            }
            for (int32_t i = 0; i < capacity; i++) {
                if (buffer.get()[i] != other[i]) {
                    SIGNATURE_TOOLS_LOGE("diff value[%d]: %x %x",
                        i, buffer.get()[i], other[i]);
                    return false;
                }
            }
            return true;
        }
        void ByteBuffer::Rewind()
        {
        }
        ByteBuffer& ByteBuffer::RewindHap()
        {
            position = 0;
            return *this;
        }
        void ByteBuffer::SetCapacity(int32_t cap)
        {
            if (buffer != nullptr) {
                buffer = nullptr;
                position = 0;
                limit = 0;
                capacity = 0;
            }
            Init(cap);
        }
    } // namespace SignatureTools
} // namespace OHOS