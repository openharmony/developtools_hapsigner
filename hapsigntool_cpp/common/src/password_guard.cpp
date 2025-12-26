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

#include "password_guard.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <securec.h>
#include <termios.h>
#include <unistd.h>

namespace OHOS {
namespace SignatureTools {

PasswordGuard::PasswordGuard() : data(nullptr), len(0), capacity(0)
{}

PasswordGuard::~PasswordGuard()
{
    clear();
}

char* PasswordGuard::get() const
{
    return data;
}

size_t PasswordGuard::size() const
{
    return len;
}

char* PasswordGuard::getPwdStr() const
{
    if (data == nullptr || len == 0) {
        return nullptr;
    }
    char* newData = new char[len + 1];
    std::copy(data, data + len + 1, newData);
    return newData;
}

void PasswordGuard::clear()
{
    if (data) {
        (void)memset_s(data, capacity, 0, capacity);
        delete[] data;
        data = nullptr;
        len = 0;
        capacity = 0;
    }
}

bool PasswordGuard::isEmpty()
{
    if (data == nullptr || len == 0) {
        return true;
    }
    return false;
}

bool PasswordGuard::getPasswordFromUser(const std::string &prompt)
{
    clear();
    if (!extend()) {
        return false;
    }

    struct termios oldt;
    struct termios newt;
    if (tcgetattr(STDIN_FILENO, &oldt) !=0) {
        return false;
    }
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        return false;
    }

    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
    std::cout << prompt << std::flush;
    bool ret = input(pfd);
    std::cout << std::endl;
    if (!ret) {
        clear();
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return false;
    }
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
        clear();
        return false;
    }
    return true;
}

bool PasswordGuard::input(pollfd pfd)
{
    char ch;
    while (true) {
        int result = poll(&pfd, 1, 30 * 1000);
        if (result == 0) {
            /* timeout */
            break;
        } else if (result == -1 || read(STDIN_FILENO, &ch, 1) != 1) {
            /* poll error */
            return false;
        }
        if (ch == '\b' || ch == ASCII_DEL) {
            if (len > 0) {
                len--;
                std::cout << "\b \b" << std::flush;
            }
        } else if (ch == '\n' || ch == '\r') {
            break;
        } else {
            if ((len >= capacity - 1) && !extend()) {
                return false;
            }
            data[len++] = ch;
            std::cout << '*' << std::flush;
        }
    }
    data[len] = '\0';  // null-terminate
    return true;
}

bool PasswordGuard::extend()
{
    const size_t INITIAL_DATA_LENGTH = 256;
    if (!data) {
        capacity = INITIAL_DATA_LENGTH;
        data = new char[capacity];
    } else {
        size_t newCapacity = capacity * 2;
        char *buffer = new char[newCapacity];
        if (memcpy_s(buffer, newCapacity, data, len) != EOK) {
            delete[] buffer;
            return false;
        }
        (void)memset_s(data, capacity, 0, capacity);
        delete[] data;
        data = buffer;
        capacity = newCapacity;
    }
    return true;
}
}  // namespace SignatureTools
}  // namespace OHOS