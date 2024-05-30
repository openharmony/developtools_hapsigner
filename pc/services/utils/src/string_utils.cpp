#include "string_utils.h"
#include <cstring>
#include "securec.h"
using namespace OHOS::SignatureTools;
StringUtils::StringUtils()
{
}
bool StringUtils::IsEmpty(const std::string& cs)
{
    return cs.empty();
}
bool StringUtils::ContainsIgnoreCase(std::vector<std::string> strs, std::string str)
{
    if (strs.empty()) {
        return false;
    }
    for (std::string& s : strs) {
        if (s.length() != str.length())continue;
        bool matched = true;
        for (int i = 0; i < s.length(); i++) {
            if (s[i] >= 'A' && s[i] <= 'Z')
                s[i] = tolower(s[i]);
            if (str[i] >= 'A' && str[i] <= 'Z')
                str[i] = tolower(str[i]);
            if (s[i] != str[i]) {
                matched = false;
                break;
            }
        }
        if (matched)
            return true;
    }
    return false;
}

bool StringUtils::ContainsCase(std::vector<std::string> strs, const std::string& str)
{
    for (const std::string& val : strs) {
        if (val == str)
            return true;
    }
    return false;
}

bool StringUtils::IgnoreCaseCompare(std::string str1, std::string str2)
{
    if (str1.size() != str2.size())
        return false;
    for (int i = 0; i < str1.size(); i++) {
        if (str1[i] >= 'a' && str1[i] <= 'z')str1[i] -= 'a' - 'A';
        if (str2[i] >= 'a' && str2[i] <= 'z')str2[i] -= 'a' - 'A';
        if (str1[i] != str2[i])
            return false;
    }
    return true;
}

bool StringUtils::CaseCompare(const std::string& str1, const std::string& str2)
{
    return str1 == str2;
}
std::vector<std::string> StringUtils::SplitString(const std::string& str, char delimiter)
{
    std::vector<std::string> tokens;
    std::istringstream tokenStream(str);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}
std::string StringUtils::Trim(const std::string& str)
{
    size_t startpos = str.find_first_not_of(" \t\n\r\f\v");
    if (std::string::npos == startpos) {
        return "";
    }
    size_t endpos = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(startpos, endpos - startpos + 1);
}
std::string StringUtils::FormatLoading(std::string& dealStr)
{
    char comma = ',';
    char slash = '/';
    std::string del = dealStr.substr(dealStr.find_first_of("/") + 1, dealStr.size());
    int position = 0;
    while ((position = del.find(slash, position)) != std::string::npos) {
        del.insert(position + 1, " ");
        position++;
    }
    for (auto& ch : del) {
        if (ch == slash) {
            ch = comma;
        }
    }
    return del.append("\n");
}
std::string StringUtils::Pkcs7ToString(PKCS7* p7)
{
    unsigned char* out = NULL;
    int outSize = i2d_PKCS7(p7, &out);
    if (out == NULL || outSize <= 0) {
        SIGNATURE_TOOLS_LOGE("pkcs7 to string failed\n");
        return "";
    }
    std::string ret;
    ret.clear();
    ret.resize(outSize);
    std::copy(out, out + outSize, &ret[0]);
    OPENSSL_free(out);
    return ret;
}
std::string StringUtils::x509CertToString(X509* cert)
{
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    std::string certStr(buffer, length);
    BIO_free(bio);
    return certStr;
}
std::string StringUtils::SubjectToString(X509* cert)
{
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    X509_NAME* subjectName = X509_get_subject_name(cert);
    if (!subjectName) {
        SIGNATURE_TOOLS_LOGE("Error getting subject name\n");
        return "";
    }
    HapVerifyOpensslUtils::GetOpensslErrorMessage();
    char* subjectStr = X509_NAME_oneline(subjectName, NULL, 0);
    if (!subjectStr) {
        SIGNATURE_TOOLS_LOGE("Error create subject string\n");
        return "";
    }
    std::string subjectString(subjectStr);
    std::string result = FormatLoading(subjectString);
    return result;
}