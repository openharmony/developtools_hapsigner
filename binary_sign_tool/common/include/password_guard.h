/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef PASSWORD_GUARD_H
#define PASSWORD_GUARD_H

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <string>
#include <securec.h>
#include <termios.h>
#include <unistd.h>

namespace OHOS {
namespace SignatureTools {
class PasswordGuard {
public:
    PasswordGuard() : data(nullptr), len(0), capacity(0)
    {}

    PasswordGuard(const PasswordGuard &) = delete;

    PasswordGuard &operator=(const PasswordGuard &) = delete;

    PasswordGuard(PasswordGuard &&other) noexcept : data(other.data), len(other.len), capacity(other.capacity)
    {
        other.data = nullptr;
        other.len = 0;
        other.capacity = 0;
    }

    PasswordGuard &operator=(PasswordGuard &&other) noexcept
    {
        if (this != &other) {
            clear();
            data = other.data;
            len = other.len;
            capacity = other.capacity;
            other.data = nullptr;
            other.len = 0;
            other.capacity = 0;
        }
        return *this;
    }

    ~PasswordGuard()
    {
        clear();
    }

    char *get() const
    {
        return data;
    }

    size_t length() const
    {
        return len;
    }

    void clear()
    {
        if (data) {
            memset_s(data, capacity, '\0', capacity);
            delete[] data;
            data = nullptr;
            len = 0;
            capacity = 0;
        }
    }

    operator bool() const
    {
        return data != nullptr;
    }

    bool getPasswordFromUser(const std::string &prompt = "Enter password: ")
    {
        clear();
        if (!extend()) {
            return false;
        }

        struct termios oldt;
        struct termios newt;
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
            return false;
        }

        std::cout << prompt << std::flush;
        char ch;
        while ((ch = getchar()) != '\n' && ch != '\r') {
            if (ch == '\b' || ch == ASCII_DEL) {
                if (len > 0) {
                    len--;
                    std::cout << "\b \b" << std::flush;
                }
            } else {
                if ((len >= capacity - 1) && !extend()) {
                    return false;
                }
                data[len++] = ch;
                std::cout << '*' << std::flush;
            }
        }
        std::cout << std::endl;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
            return false;
        }
        data[len] = '\0';  // null-terminate
        return true;
    }

    const static int ASCII_DEL = 127;
private:
    bool extend()
    {
        const size_t INITIAL_DATA_LENGTH = 256;
        if (!data) {
            capacity = INITIAL_DATA_LENGTH;
            data = new char[capacity];
        } else {
            size_t new_capacity = capacity * 2;
            char *buffer = new char[new_capacity];
            if (memcpy_s(buffer, new_capacity, data, len) != 0) {
                delete[] buffer;
                return false;
            }
            memset_s(data, capacity, '\0', capacity);
            delete[] data;
            data = buffer;
            capacity = new_capacity;
        }
        return true;
    }
    char *data;
    size_t len;
    size_t capacity;
};
}  // namespace SignatureTools
}  // namespace OHOS
#endif  // PASSWORD_GUARD_H