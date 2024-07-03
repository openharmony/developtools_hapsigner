/*
 * Copyright (c) 2020-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <filesystem>
#include <fstream>
#include <unistd.h> 
#include "packet_helper.h"

namespace OHOS {
namespace SignatureTools {
void GenUnvaildHap(const std::string& path)
{
    std::ofstream outfile(path);
    if (!outfile) {
        SIGNATURE_TOOLS_LOGE("Unable to open file: %{public}s", path.c_str());
        return;
    }
    outfile << "Hello, this is a Unvaild Hap.\n";
    outfile.flush();
    outfile.close();
    return;
}

int Base64DecodeStringToFile(const char* base64Str, const char* outfile)
{
    BIO* b64;
    BIO* mem;
    FILE* fp;
    char buf[1024];
    int bytesRead;
    mem = BIO_new(BIO_s_mem());
    if (!mem) {
        SIGNATURE_TOOLS_LOGE("Unable to create memory BIO");
        return 1;
    }
    BIO_write(mem, base64Str, strlen(base64Str));

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        SIGNATURE_TOOLS_LOGE("Unable to create base64 BIO");
        BIO_free_all(mem);
        return 1;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    fp = fopen(outfile, "wb");
    if (!fp) {
        SIGNATURE_TOOLS_LOGE("Unable to open output file %{public}s", outfile);
        BIO_free_all(b64);
        return 1;
    }
    while ((bytesRead = BIO_read(b64, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, bytesRead, fp);
    }
    fflush(fp);
    int fd_no = fileno(fp); 
    if (fd_no == -1) {  
        SIGNATURE_TOOLS_LOGE("fileno Base64DecodeStringToFile");
        fclose(fp);
        BIO_free_all(b64);
        return 1;
    }
    if (fsync(fd_no) == -1) {
        SIGNATURE_TOOLS_LOGE("fsync Base64DecodeStringToFile");
    }
    fclose(fp);
    BIO_free_all(b64);
    return 0;
}
}
}