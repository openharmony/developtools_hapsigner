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
#include "cmd_util.h"
#include <set>
#include <filesystem>

#include "params_run_tool.h"
#include "constant.h"
#include "param_constants.h"

namespace OHOS {
namespace SignatureTools {
const std::regex INTEGER_PATTERN = std::regex("\\d{1,10}");

static bool UpdateParamForVariantCertInt(ParamsSharedPtr param)
{
    int defualtValidity = 0;
    Options* options = param->GetOptions();
    if (options->count(Options::VALIDITY)) { // int 类型
        int validity = 0;
        std::string val = options->GetString(Options::VALIDITY);
        for (char x : val) {
            if (!isdigit(x)) {
                PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid validity");
                return false;
            }
        }
        try {
            validity = stoi(val);
        }
        catch (std::exception& e) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid validity");
            return false;
        }
        validity *= ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = validity;
    } else if (param->GetMethod() == GENERATE_CA || param->GetMethod() == GENERATE_APP_CERT ||
               param->GetMethod() == GENERATE_PROFILE_CERT) {
        defualtValidity = DEFAULT_VALIDITY_DAYS * ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = defualtValidity;
    } else if (param->GetMethod() == GENERATE_CERT) {
        defualtValidity = DEFAULT_CUSTOM_VALIDITY_DAYS * ONE_DAY_TIME;
        (*options)[Options::VALIDITY] = defualtValidity;
    }
    return true;

}

static bool UpdateParamForVariantInt(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    // general
    if (options->count(Options::KEY_SIZE)) { // int 类型
        std::string key_size = options->GetString(Options::KEY_SIZE);
        if (key_size == "NIST-P-256") {
            (*options)[Options::KEY_SIZE] = NIST_P_256;
        } else if (key_size == "NIST-P-384") {
            (*options)[Options::KEY_SIZE] = NIST_P_384;
        } else {
            PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "KeySize '" + key_size + "' is incorrect");
            return false;
        }
    }
    if (options->count(Options::BASIC_CONSTRAINTS_PATH_LEN)) { // int 类型
        int basicConstraintsPathLen = 0;
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_PATH_LEN);
        try {
            basicConstraintsPathLen = stoi(val);
        }
        catch (std::exception& e) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints path len");
            return false;
        }
        (*options)[Options::BASIC_CONSTRAINTS_PATH_LEN] = basicConstraintsPathLen;
    } else if (param->GetMethod() == GENERATE_CA || param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_PATH_LEN] = DEFAULT_BASIC_CONSTRAINTS_PATH_LEN;
    }
    if (!UpdateParamForVariantCertInt(param)) {
        return false;
    }
    return true;
}

static bool UpdateParamForVariantBoolKeyUsage(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    if (options->count(Options::KEY_USAGE_CRITICAL)) { // bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::KEY_USAGE_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::KEY_USAGE_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::KEY_USAGE_CRITICAL] = false;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid key usage critical");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::KEY_USAGE_CRITICAL] = DEFAULT_KEY_USAGE_CRITICAL;
    }
    // bool 类型 仅generate-cert模块使用
    if (options->count(Options::EXT_KEY_USAGE_CRITICAL)) {
        std::string val = options->GetString(Options::EXT_KEY_USAGE_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::EXT_KEY_USAGE_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::EXT_KEY_USAGE_CRITICAL] = false;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid exit key usage critical");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::EXT_KEY_USAGE_CRITICAL] = DEFAULT_EXT_KEY_USAGE_CRITICAL;
    }
    return true;
}

static bool UpdateParamForVariantBoolConstraints(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    if (options->count(Options::BASIC_CONSTRAINTS)) { // bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS] = false;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS] = DEFAULT_BASIC_CONSTRAINTS;
    }
    if (options->count(Options::BASIC_CONSTRAINTS_CRITICAL)) { // bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_CRITICAL);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = false;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints critial");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_CRITICAL] = DEFAULT_BASIC_CONSTRAINTS_CRITICAL;
    }
    return true;
}

static bool UpdateParamForVariantBoolProfileSigned(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();

    if (options->count(Options::PROFILE_SIGNED)) { // bool 类型 仅sign-app模块使用
        std::string val = options->GetString(Options::PROFILE_SIGNED);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_0;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "invalid profile signed");
            return false;
        }
    } else if (param->GetMethod() == SIGN_APP) {
        (*options)[Options::PROFILE_SIGNED] = DEFAULT_PROFILE_SIGNED_1;
    }
    if (options->count(Options::BASIC_CONSTRAINTS_CA)) { // bool 类型 仅generate-cert模块使用
        std::string val = options->GetString(Options::BASIC_CONSTRAINTS_CA);
        if (val == "1" || val == "true" || val == "TRUE") {
            (*options)[Options::BASIC_CONSTRAINTS_CA] = true;
        } else if (val == "0" || val == "false" || val == "FALSE") {
            (*options)[Options::BASIC_CONSTRAINTS_CA] = false;
        } else {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Invalid basic constraints ca");
            return false;
        }
    } else if (param->GetMethod() == GENERATE_CERT) {
        (*options)[Options::BASIC_CONSTRAINTS_CA] = DEFAULT_BASIC_CONSTRAINTS_CA;
    }
    return true;
}

static bool outFilePath(Options* options)
{
    std::initializer_list<std::string> outFileKeys = {
        Options::OUT_FILE, Options::KEY_STORE_FILE,
        Options::ISSUER_KEY_STORE_FILE,
        Options::OUT_PROFILE, Options::OUT_CERT_CHAIN };
    // check path directory is exists
    for (auto& key : outFileKeys) {
        if (options->count(key)) {
            std::filesystem::path pat = options->GetString(key);
            if (std::filesystem::is_directory(pat)) {
                PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, "File: " + std::string(pat.c_str())
                                    + " is a directory");
                return false;
            }
            std::string parentPath = pat.parent_path();
            if (!std::filesystem::exists(parentPath)) {
                PrintErrorNumberMsg("IO_ERROR", IO_ERROR, "output file parent directory not exist : "
                                    + std::string(parentPath.c_str()) + " not exist");
                return false;
            }
        }
    }
    return true;
}

static bool UpdateParamForCheckFile(ParamsSharedPtr param)
{
    // check file exists
    Options* options = param->GetOptions();
    std::initializer_list<std::string> inFileKeys = {
        Options::IN_FILE,
        Options::SUB_CA_CERT_FILE,
        Options::CA_CERT_FILE,
        Options::PROFILE_CERT_FILE,
        Options::APP_CERT_FILE,
        Options::PROFILE_FILE };
    for (auto& key : inFileKeys) {
        if (options->count(key) &&
            !FileUtils::IsValidFile(options->GetString(key))) {
            PrintErrorNumberMsg("FILE_NOT_FOUND", FILE_NOT_FOUND, options->GetString(key) + " Not exist");
            return false;
        }
    }
    // check path exists
    if (!outFilePath(options)) {
        return false;
    }
    return true;
}

static bool UpdateParamForCheckSignAlg(ParamsSharedPtr param)
{
    // check signAlg
    Options* options = param->GetOptions();
    if (options->count(Options::SIGN_ALG) && options->GetString(Options::SIGN_ALG)
        != SIGN_ALG_SHA256 && options->GetString(Options::SIGN_ALG) != SIGN_ALG_SHA384) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "SignAlg params is incorrect");
        return false;
    }
    return true;
}

static bool UpdateParamForInform(ParamsSharedPtr param)
{
    // check sign_app verify_app inform
    Options* options = param->GetOptions();
    if (param->GetMethod() == SIGN_APP ||
        param->GetMethod() == VERIFY_APP) {
        if (options->count(Options::INFORM)) {
            std::string inForm = options->GetString(Options::INFORM);
            if (!StringUtils::ContainsCase(ParamsRunTool::InformList, inForm)) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "Inform only support zip/elf/bin");
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
    // check generate_app_cert generate_profile_cert
    Options* options = param->GetOptions();
    if (param->GetMethod() == GENERATE_APP_CERT ||
        param->GetMethod() == GENERATE_PROFILE_CERT) {
        if (options->count(Options::OUT_FORM)) {
            std::string outForm = options->GetString(Options::OUT_FORM);
            if (outForm != OUT_FORM_CERT && outForm != OUT_FORM_CERT_CHAIN) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "Outform only supprot cert/cerChain");
                return false;
            }
        } else {
            (*options)[Options::OUT_FORM] = OUT_FORM_CERT_CHAIN;
        }
    }
    return true;
}

/* 检查remoteSign 额外参数都必填 */
static bool UpdateParamForCheckRemoteSignProfile(ParamsSharedPtr param)
{
    Options* options = param->GetOptions();
    std::set<std::string> signProfileRemoteParams{ ParamConstants::PARAM_REMOTE_SERVER,
                                                   ParamConstants::PARAM_REMOTE_USERNAME,
                                                   ParamConstants::PARAM_REMOTE_USERPWD,
                                                   ParamConstants::PARAM_REMOTE_ONLINEAUTHMODE,
                                                   ParamConstants::PARAM_REMOTE_SIGNERPLUGIN };

    if (param->GetMethod() == SIGN_PROFILE && options->count(Options::MODE) &&
        options->GetString(Options::MODE) == REMOTE_SIGN) {
        for (const std::string& key : signProfileRemoteParams) {
            if (options->count(key) == 0) {
                PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "sign profile RemoteSign absence param");
                return false;
            }
        }
    }
    return true;
}

static bool UpdateParam(ParamsSharedPtr param)
{
    if (UpdateParamForVariantInt(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBoolKeyUsage(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBoolConstraints(param) == false) {
        return false;
    }
    if (UpdateParamForVariantBoolProfileSigned(param) == false) {
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
    if (UpdateParamForCheckRemoteSignProfile(param) == false) {
        return false;
    }
    return true;
}

int CmdUtil::GetCommandParameterKey(char strChar, std::string& strChars, std::vector<std::string>& trustList,
                                    std::string& keyStandBy)
{
    if (strChar == '-') {
        bool isTrust = std::find(trustList.begin(), trustList.end(), strChars) != trustList.end();
        if (!isTrust) {
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Not support command param");
            return RET_FAILED;
        }
        keyStandBy = strChars.substr(1);
    } else {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Param key-value must in pairs");
        return RET_FAILED;
    }

    return RET_OK;
}

bool CmdUtil::Convert2Params(char** args, size_t size, ParamsSharedPtr param)
{
    param->SetMethod(args[1]);
    std::string keyStandBy = "";
    bool readKey = true;
    ParamsTrustlist params_trust_list;
    std::vector<std::string> trustList = params_trust_list.GetTrustList(args[1]);
    if (trustList.empty()) {
        return false;
    }
    size_t i = 2;
    char strChar;
    std::string strChars;
    for (; i < size; i++) {
        if (readKey) {
            strChar = args[i][0];
            strChars = args[i];
            if (GetCommandParameterKey(strChar, strChars, trustList, keyStandBy) == RET_OK) {
                readKey = false;
            } else {
                return false;
            }
        } else {
            bool success = ValidAndPutParam(param, keyStandBy, args[i]);
            if (success) {
                keyStandBy = "";
                readKey = true;
            } else {
                return false;
            }
        }
    }
    if (!readKey) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "No matched value found");
        return false;
    }
    if (UpdateParam(param) == false)
        return false;
    return true;
}

bool CmdUtil::JudgeEndSignAlgType(std::string signAlg)
{
    if (signAlg != SIGN_ALG_SHA256 && signAlg != SIGN_ALG_SHA384) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR,
                            "SignAlg params is incorrect,"
                            "signature algorithms include SHA256withECDSA,SHA384withECDSA");
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
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "Command -" + std::string(value) + " cannot be empty!");
        result = false;
    } else if (params->GetOptions()->count(key)) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "duplicate param '" + key + "'. stop processing!");
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
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "KeyAlg params is incorrect");
        return false;
    }
    return true;
}

bool CmdUtil::JudgeSize(int size)
{
    if (size != NIST_P_256 && size != NIST_P_384) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "Keysize params is incorrect");
        return false;
    }
    return true;
}

bool CmdUtil::JudgeSignAlgType(std::string signAlg)
{
    if (signAlg != SIGN_ALG_SHA256 && signAlg != SIGN_ALG_SHA384) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "SignAlg params is incorrect");
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
            PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, val + " in  params list is not support");
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
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, inputType +
                            " in  params list is not support");
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
    PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "Not support command param");

    return false;
}
} // namespace SignatureTools
} // namespace OHOS