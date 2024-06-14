/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "cert_dn_utils.h"
#include "signature_tools_errno.h"
#include "constant.h"
 /*
 std::string OHOS::SignatureTools::Base64Encode(unsigned char *bytesToEncode, unsigned int inLen)
 {
     static const std::string base64Chars =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
         std::string ret;
     int i = 0;
     int j = 0;
     unsigned char charArray3[3];
     unsigned char charArray4[4];
         while (inLen--)
     {
         charArray3[i++] = *(bytesToEncode++);
         if (i == 3)
         {
             charArray4[0] = (charArray3[0] & 0xfc) >> 2;
             charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
             charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
             charArray4[3] = charArray3[2] & 0x3f;
                 for (i = 0; (i < 4); i++)
                 ret += base64Chars[charArray4[i]];
             i = 0;
         }
     }
         if (i)
     {
         for (j = i; j < 3; j++)
         {
             charArray3[j] = '\0';
         }
             charArray4[0] = (charArray3[0] & 0xfc) >> 2;
         charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
         charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
         charArray4[3] = charArray3[2] & 0x3f;
             for (j = 0; (j < i + 1); j++)
         {
             ret += base64Chars[charArray4[j]];
         }
             while ((i++ < 3))
         {
             ret += '=';
         }
     }
         return ret;
 }
 */
namespace OHOS {
namespace SignatureTools {

int CheckDn(std::string nameString, std::vector<pair<std::string, std::string>>& pairs)
{
    if (nameString.size() == 0) {
        return FORMAT_ERROR;
    }
    std::vector<std::string> tokens = StringUtils::SplitString(nameString.c_str(), ',');
    for (std::string pair : tokens) {
        if (StringUtils::Trim(pair).size() == 0) {
            return FORMAT_ERROR;
        }
        std::vector<std::string> kvPair = StringUtils::SplitString(pair, '=');
        if (kvPair.size() != DEFAULT_CERT_VERSION) {
            return FORMAT_ERROR;
        }
        kvPair[0] = StringUtils::Trim(kvPair[0]);
        kvPair[1] = StringUtils::Trim(kvPair[1]);
        if (kvPair[1].size() == 0) {
            return FORMAT_ERROR;
        }
        pairs.push_back({ kvPair[0], kvPair[1] });
    }
    return 0;
}
// DAIRAN

X509_NAME* BuildDN(std::string nameString, X509_REQ* req)
{
    std::vector<pair<std::string, std::string>> pairs;
    std::ostringstream oss;
    oss << "Format error, must be \"X=xx,XX=xxx,...\", please check: \"" << nameString << "\"";
    int ret = CheckDn(nameString, pairs);
    if (ret == FORMAT_ERROR) {
        SIGNATURE_TOOLS_LOGE(" Description The topic information verification failed %{public}d: %{public}s",
                             ret, oss.str().c_str());
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            oss.str().c_str());
        return nullptr;
    }
    X509_NAME* subject = nullptr;
    subject = X509_REQ_get_subject_name(req);
    if (!subject) {
        SIGNATURE_TOOLS_LOGE("X509_NAME get failed !");
        return nullptr;
    }
    for (auto idx = pairs.cbegin(); idx != pairs.cend(); idx++) {
        if (OBJ_txt2nid(idx->first.c_str()) == NID_undef) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                                "Error params near:" + nameString + " Reason: Unknown object id - " + idx->first +
                                " - passed to distinguished name");
            return nullptr;
        }
        X509_NAME_add_entry_by_txt(subject, idx->first.c_str(), MBSTRING_ASC,
                                   (const unsigned char*)idx->second.c_str(), -1, -1, 0);
    }
    return subject;
}
} // namespace SignatureTools
} // namespace OHOS