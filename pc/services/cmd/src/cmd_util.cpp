/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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
#include "cmd_util.h"
#include "filesystem"
#include<set>
using namespace OHOS::SignatureTools;
const std::regex INTEGER_PATTERN = std::regex("\\d{1,10}");
static const std::string SIGN_ALG_256 = "SHA256withECDSA";
static const std::string SIGN_ALG_384 = "SHA384withECDSA";
static constexpr int  NIST_P_256 = 256;
static constexpr int  NIST_P_384 = 384;
static constexpr int  DEFAULT_BASIC_CONSTRAINTS_PATH_LEN = 0;
static constexpr int  DEFAULT_VALIDITY = 365;
static constexpr bool DEFAULT_KEY_USAGE_CRITICAL = true;
static const std::string DEFAULT_PROFILE_SIGNED_1 = "1";
static const std::string DEFAULT_PROFILE_SIGNED_0 = "0";
static constexpr bool DEFAULT_EXT_KEY_USAGE_CRITICAL = false;
static constexpr bool DEFAULT_BASIC_CONSTRAINTS = false;
static constexpr bool DEFAULT_BASIC_CONSTRAINTS_CRITICAL = false;
static constexpr bool DEFAULT_BASIC_CONSTRAINTS_CA = false;
static const std::string ZIP = "zip";
static const std::string SIGN_APP = "sign-app";
static const std::string GENERATE_CA = "generate-ca";
static const std::string GENERATE_APP_CERT = "generate-app-cert";
static const std::string GENERATE_PROFILE_CERT = "generate-profile-cert";
static const std::string GENERATE_CERT = "generate-cert";
static const std::string VERIFY_APP = "verify-app";
static const std::string OUT_FORM_CERT = "cert";
static const std::string OUT_FORM_CERT_CHAIN = "certChain";
#define INVALIDCHAR 3

static bool UpdateParamForVariantInt(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    //general
    if (options->count(Options::KEY_SIZE)) { //int 类型
        std::string key_size = options->GetString(Options::KEY_SIZE);
        if (options->GetString(Options::KEY_SIZE) == "NIST-P-256") {
            (*options)[Options::KEY_SIZE] = NIST_P_256;
        } else if (options->GetString(Options::KEY_SIZE) == "NIST-P-384") {
            (*options)[Options::KEY_SIZE] = NIST_P_384;
        } else {
            CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "KeySize '" + key_size + "' is incorrect");
            return false;
        }
    }
    if (options->count(Options::BASIC_CONSTRAINTS_PATH_LEN)) { //int 类型
        int basicConstraintsPathLen = 0;
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_PATH_LEN);
        try {
            basicConstraintsPathLen = stoi(val);
        }
        catch (std::exception& e) {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints path len");
            return false;
        }
        (*options)[Options::BASIC_CONSTRAINTS_PATH_LEN] = basicConstraintsPathLen;
    } else if (param->GetMethod() == GENERATE_CA || param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_PATH_LEN] = DEFAULT_BASIC_CONSTRAINTS_PATH_LEN;
    }

    if (options->count(Options::VALIDITY)) { //int 类型
        int validity = 0;
        std::string val = options->GetString(Options::VALIDITY);
        for (char x : val) {
            if (!isdigit(x)) {
                CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid validity");
                return false;
            }
        }
        try {
            validity = stoi(val);
        } catch (std::exception& e) {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid validity");
            return false;
        }
        (*options)[Options::VALIDITY] = validity;
    } else if (param->GetMethod() == GENERATE_CA || param->GetMethod() == GENERATE_APP_CERT ||
              param->GetMethod() == GENERATE_PROFILE_CERT || param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::VALIDITY] = DEFAULT_VALIDITY;
    }
    return true;
}

static bool UpdateParamForVariantBool_1(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    if (options->count(Options::KEY_USAGE_CRITICAL)) { //bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::KEY_USAGE_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::KEY_USAGE_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::KEY_USAGE_CRITICAL] = false;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid key usage critical");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::KEY_USAGE_CRITICAL] = DEFAULT_KEY_USAGE_CRITICAL;
    }
    //bool 类型 仅generate-cert模块使用
    if (options->count(Options::EXT_KEY_USAGE_CRITICAL)) {
        std::string val = options->GetString(Options::EXT_KEY_USAGE_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::EXT_KEY_USAGE_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::EXT_KEY_USAGE_CRITICAL] = false;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid exit key usage critical");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::EXT_KEY_USAGE_CRITICAL] = DEFAULT_EXT_KEY_USAGE_CRITICAL;
    }
    return true;
}

static bool UpdateParamForVariantBool_2(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    if (options->count(Options::BASIC_CONSTRAINTS)) { //bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS] = false;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS] = DEFAULT_BASIC_CONSTRAINTS;
    }
    if (options->count(Options::BASIC_CONSTRAINTS_CRITICAL)) { //bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = false;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints critial");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = DEFAULT_BASIC_CONSTRAINTS_CRITICAL;
    }
    return true;
}

static bool UpdateParamForVariantBool_3(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    if (options->count(Options::BASIC_CONSTRAINTS_CA)) { //bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_CA);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS_CA] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS_CA] = false;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints ca");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_CA] = DEFAULT_BASIC_CONSTRAINTS_CA;
    }
    if (options->count(Options::PROFILE_SIGNED)) { //bool 类型 仅sign-app模块使用
        std::string val = options->GetString(Options::PROFILE_SIGNED);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_0;
        } else {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "invalid profile signed");
            return false;
        }
    } else if (param->GetMethod() == SIGN_APP) {
        (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
    }
    return true;
}

static bool outFilePath(Options* options)
{
    if (options->count(Options::OUT_FILE)) {
        std::filesystem::path pat = options->GetString(Options::OUT_FILE);
        if (std::filesystem::is_directory(pat)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " is a directory");
            return false;
        }
        std::string parentPath = pat.parent_path();
        if (!std::filesystem::exists(parentPath)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " not exist");
            return false;
        }
    }
    if (options->count(Options::KEY_STORE_FILE)) {
        std::filesystem::path pat = options->GetString(Options::KEY_STORE_FILE);
        if (std::filesystem::is_directory(pat)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " is a directory");
            return false;
        }
        std::string parentPath = pat.parent_path();
        if (!std::filesystem::exists(parentPath)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " not exist");
            return false;
        }
    }
    if (options->count(Options::ISSUER_KEY_STORE_FILE)) {
        std::filesystem::path pat = options->GetString(Options::ISSUER_KEY_STORE_FILE);
        if (std::filesystem::is_directory(pat)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " is a directory");
            return false;
        }
        std::string parentPath = pat.parent_path();
        if (!std::filesystem::exists(parentPath)) {
            CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                          + " not exist");
            return false;
        }
    }

    return true;
}

static bool UpdateParamForCheckFile(ParamsSharedPtr param)
{
    //check file exists
    Options* options = param->GetOptions();
    if (options->count(Options::IN_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::IN_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::IN_FILE) + " Not exist");
        return false;
    }
    if (!outFilePath(options)) {
        return false;
    }
    if (options->count(Options::SUB_CA_CERT_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::SUB_CA_CERT_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::SUB_CA_CERT_FILE)
                      + " not exist");
        return false;
    }
    if (options->count(Options::CA_CERT_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::CA_CERT_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::CA_CERT_FILE) + " not exist");
        return false;
    }
    if (options->count(Options::PROFILE_CERT_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::PROFILE_CERT_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::PROFILE_CERT_FILE)
                      + " not exist");
        return false;
    }
    if (options->count(Options::APP_CERT_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::APP_CERT_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::APP_CERT_FILE) + " not exist");
        return false;
    }
    if (options->count(Options::PROFILE_FILE) &&
        !std::filesystem::is_regular_file(options->GetString(Options::PROFILE_FILE))) {
        CMD_ERROR_MSG("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(Options::PROFILE_FILE) + " not exist");
        return false;
    }
    return true;
}
static bool UpdateParamForCheckSignAlg(ParamsSharedPtr param)
{
    //check signAlg
    Options* options = param->GetOptions();
    if (options->count(Options::SIGN_ALG) && options->GetString(Options::SIGN_ALG)
        != SIGN_ALG_256 && options->GetString(Options::SIGN_ALG) != SIGN_ALG_384) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "SignAlg params is incorrect");
        return false;
    }
    return true;
}
static bool UpdateParamForInform(ParamsSharedPtr param)
{
    //check sign_app verify_app inform
    Options* options = param->GetOptions();
    if (param->GetMethod() == SIGN_APP ||
        param->GetMethod() == VERIFY_APP) {
        if (options->count(Options::INFORM)) {
            std::string inForm = options->GetString(Options::INFORM);
            if (!StringUtils::ContainsCase(HapSignTool::InformList, inForm)) {
                CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "Inform only support zip/elf/bin");
                return false;
            }
        } else {
            (*options)[Options::INFORM] = ZIP;
        }
    }
    return true;
}
static bool UpdateParamForOutform(ParamsSharedPtr param)
{
    //check generate_app_cert generate_profile_cert
    Options* options = param->GetOptions();
    if (param->GetMethod() == GENERATE_APP_CERT ||
        param->GetMethod() == GENERATE_PROFILE_CERT) {
        std::string outForm = options->GetString(Options::OUT_FORM);
        if (options->count(Options::OUT_FORM)) {
            if (outForm != OUT_FORM_CERT && outForm != OUT_FORM_CERT_CHAIN) {
                CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "Outform only supprot cert/cerChain");
                return false;
            }
        } else {
            (*options)[Options::OUT_FORM] = OUT_FORM_CERT_CHAIN;
        }
    }
    return true;
}
static bool UpdateParam(ParamsSharedPtr param)
{
    if (UpdateParamForVariantInt(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBool_1(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBool_2(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBool_3(param) == false) {
        return false;
    }
    if (UpdateParamForCheckFile(param) == false) {
        return false;
    }
    if (UpdateParamForCheckSignAlg(param) == false) {
        return false;
    }
    if (UpdateParamForInform(param) == false) {
        return false;
    }
    if (UpdateParamForOutform(param) == false) {
        return false;
    }
    return true;
}

bool CmdUtil::Convert2Params(char** args, size_t size, ParamsSharedPtr param)
{
    param->SetMethod(args[1]);
    std::string keyStandBy = "";
    bool readKey = true;
    //获取help中generate-keypair [options]:和下面对应的字段，存入map中
    ParamsTrustlist params_trust_list;
    std::vector<std::string> trustList = params_trust_list.GetTrustList(args[1]);
    if (trustList.empty()) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "Unsupport comand");
        return false;
    }
    size_t i = 2;
    auto parseArgs = [&, this]()->bool {
        if (readKey) {
            // prepare key
            if (args[i][0] == '-') {
                bool isTrust = std::find(trustList.begin(), trustList.end(), args[i]) != trustList.end();
                if (!isTrust) {
                    CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Not support command param");
                    return false;
                }
                keyStandBy = std::string(args[i]).substr(1);
                readKey = false;
            } else {
                CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Param key-value must in pairs");
                return false;
            }
        } else {
            // prepare value
            bool success = ValidAndPutParam(param, keyStandBy, args[i]);
            if (success) {
                keyStandBy = "";
                readKey = true;
            } else {
                return false;
            }
        }
        return true;
        };
    for (; i < size; i++) {
        if (parseArgs() == false)
            return false;
    }
    if (!readKey) {
        CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "No matched value found");
        return false;
    }
    if (UpdateParam(param) == false)
        return false;
    return true;
}

bool CmdUtil::JudgeEndSignAlgType(std::string signAlg)
{
    if (signAlg != SIGN_ALG_256 && signAlg != SIGN_ALG_384) {
        CMD_ERROR_MSG("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR,
                      "SignAlg params is incorrect, signature algorithms include SHA256withECDSA,SHA384withECDSA");
        return false;
    }
    return true;
}
bool CmdUtil::ValidAndPutParam(ParamsSharedPtr params, const std::string& key, char* value)
{
    std::string  str = "Pwd";
    bool result;
    if (key.empty()) {
        result = false;
    } else if (strlen(value) == 0) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "Command -" + std::string(value) + " cannot be empty!");
        result = false;
    } else if (params->GetOptions()->count(key)) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "duplicate param '" + key + "'. stop processing!");
        result = false;
    } else if (key.length() >= str.length() && key.substr(key.length() - INVALIDCHAR) == str) {
        params->GetOptions()->emplace(key, value);
        result = true;
    } else {
        params->GetOptions()->emplace(key, std::string(value));
        result = true;
    }
    return result;
}

bool CmdUtil::JudgeAlgType(std::string keyAlg)
{
    if (keyAlg != "ECC") {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "KeyAlg params is incorrect");
        return false;
    }
    return true;
}
bool CmdUtil::JudgeSize(int size)
{
    if (size != NIST_P_256 && size != NIST_P_384) {
        SIGNATURE_TOOLS_LOGE("Keysize params is incorrect!\n");
        return false;
    }
    return true;
}
bool CmdUtil::JudgeSignAlgType(std::string signAlg)
{
    if (signAlg != "SHA256withECDSA" && signAlg != "SHA384withECDSA") {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "SignAlg params is incorrect");
        return  false;
    }
    return true;
}

bool CmdUtil::VerifyTypes(std::string inputType)
{
    if (inputType.size() == 0) {
        return false;
    }
    std::vector<std::string> vecs = StringUtils::SplitString(inputType.c_str(), ',');
    std::set<std::string> sets;
    sets.insert("digitalSignature");
    sets.insert("nonRepudiation");
    sets.insert("keyEncipherment");
    sets.insert("dataEncipherment");
    sets.insert("keyAgreement");
    sets.insert("certificateSignature");
    sets.insert("crlSignature");
    sets.insert("encipherOnly");
    sets.insert("decipherOnly");
    for (const auto& val : vecs) {
        if (sets.count(val) == 0) {
            CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, val + " in  params list is not support");
            return false;
        }
    }   
    return true;
}


bool CmdUtil::VerifyType(std::string inputType)
{
    std::set<std::string> sets; 
    sets.insert("clientAuthentication");
    sets.insert("serverAuthentication");
    sets.insert("codeSignature");
    sets.insert("emailProtection");
    sets.insert("smartCardLogin");
    sets.insert("timestamp");
    sets.insert("ocspSignature"); 
    if (sets.count(inputType) == 0) {
         CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, inputType + " in  params list is not support");
         return false;
    }
    return true;
}
bool CmdUtil::VerifyType(std::string inputtype, std::string supportTypes)
{
    std::string firstStr = supportTypes.substr(0, supportTypes.find_last_of(","));
    std::string secondStr = supportTypes.substr(supportTypes.find_first_of(",") + 1,
                                                supportTypes.size() - supportTypes.find_first_of(","));
    if (inputtype == firstStr || inputtype == secondStr) {
        return true;
    }
    CMD_ERROR_MSG("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Not support command param");

    return false;
}
