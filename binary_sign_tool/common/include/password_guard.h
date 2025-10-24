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
    PasswordGuard() : data(nullptr), len(0)
    {}

    PasswordGuard(const PasswordGuard &) = delete;

    PasswordGuard &operator=(const PasswordGuard &) = delete;

    PasswordGuard(PasswordGuard &&other) noexcept : data(other.data), len(other.len)
    {
        other.data = nullptr;
        other.len = 0;
    }

    PasswordGuard &operator=(PasswordGuard &&other) noexcept
    {
        if (this != &other) {
            clear();
            data = other.data;
            len = other.len;
            other.data = nullptr;
            other.len = 0;
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
            std::fill_n(data, len, '\0');
            delete[] data;
            data = nullptr;
            len = 0;
        }
    }

    operator bool() const
    {
        return data != nullptr;
    }

    bool getPasswordFromUser(const std::string &prompt = "Enter password: ")
    {
        const size_t MAX_PASS_LEN = 256;
        char password[MAX_PASS_LEN];
        size_t len = 0;

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
            if (ch == '\b' || ch == 127) {
                if (len > 0) {
                    len--;
                    std::cout << "\b" << "\b" << std::flush;
                }
            } else {
                if (len < MAX_PASS_LEN - 1) {
                    password[len++] = ch;
                    std::cout << '*' << std::flush;
                }
            }
        }
        std::cout << std::endl;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
            return false;
        }

        data = new char[len + 1];
        if (memcpy_s(data, len, password, len) != 0) {
            return false;
        }
        data[len] = '\0';  // null-terminate
        // clear
        if (memset_s(password, sizeof(password), 0, sizeof(password)) != 0) {
            return false;
        }
        return true;
    }

private:
    char *data;
    size_t len;
};
}  // namespace SignatureTools
}  // namespace OHOS
#endif  // PASSWORD_GUARD_H