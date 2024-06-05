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
#include "hap_sign_tool.h"
#include "constant.h"
#include <memory>

using namespace OHOS::SignatureTools;
using std::pair;
const std::string HapSignTool::VERSION = "1.0.0";
const std::string HapSignTool::LOCAL_SIGN = "localSign";
const std::string HapSignTool::REMOTE_SIGN = "remoteSign";

std::vector<std::string> HapSignTool::InformList;
enum MapNum {
    NUM_1 = 1,
    NUM_2 = 2,
    NUM_3 = 3,
    NUM_4 = 4,
    NUM_5 = 5,
    NUM_6 = 6
};
HapSignTool::HapSignTool()
{
    InformList.push_back("bin");
    InformList.push_back("elf");
    InformList.push_back("zip");
}
bool HapSignTool::ProcessCmd(char** args, size_t size)
{
    if (size < CmdUtil::ARGS_MIN_LEN) {
        args[1] = const_cast<char*>("");
    }
    if (args == nullptr || strcmp(args[1], "") == 0) {
        PrintHelp();
        return true;
    } else if (strcmp(args[1], "-h") == 0 || strcmp(args[1], "-help") == 0) {
        PrintHelp();
        return true;
    } else if (strcmp(args[1], "-v") == 0 || strcmp(args[1], "-version") == 0) {
        Version();
        return true;
    } else {
        std::shared_ptr<SignToolServiceImpl> service_api = std::make_shared<SignToolServiceImpl>();
        CmdUtil cmdUtil;
        ParamsSharedPtr param = std::make_shared<Params>();
        if (!cmdUtil.Convert2Params(args, size, param)) {
            return false;
        }
        CMD_MSG("Start " + param->GetMethod());
        SIGNATURE_TOOLS_LOGI("%{public}s run start time \n ", param->GetMethod().c_str());
        if (!DispatchParams(param, *service_api.get())) {
            SIGNATURE_TOOLS_LOGI("%{public}s run end time \n ", param->GetMethod().c_str());
            return false;
        }
        CMD_MSG(param->GetMethod() + " success");
        SIGNATURE_TOOLS_LOGI("%{public}s run end time \n ", param->GetMethod().c_str());
    }
    return true;
}
bool HapSignTool::CallGenerators(ParamsSharedPtr params, SignToolServiceImpl& api)
{
    bool isSuccess = false;
    std::map<std::string, int> map;
    map.insert(std::make_pair(Method::GENERATE_KEYPAIR, MapNum::NUM_1));
    map.insert(std::make_pair(Method::GENERATE_CSR, MapNum::NUM_2));
    map.insert(std::make_pair(Method::GENERATE_CA, MapNum::NUM_3));
    map.insert(std::make_pair(Method::GENERATE_APP_CERT, MapNum::NUM_4));
    map.insert(std::make_pair(Method::GENERATE_PROFILE_CERT, MapNum::NUM_5));
    map.insert(std::make_pair(Method::GENERATE_CERT, MapNum::NUM_6));
    switch (map[params->GetMethod()]) {
        case MapNum::NUM_1:
            isSuccess = RunKeypair(params->GetOptions(), api);
            break;
        case MapNum::NUM_2:
            isSuccess = RunCsr(params->GetOptions(), api);
            break;
        case MapNum::NUM_3:
            isSuccess = RunCa(params->GetOptions(), api);
            break;
        case MapNum::NUM_4:
            isSuccess = RunAppCert(params->GetOptions(), api);
            break;
        case MapNum::NUM_5:
            isSuccess = RunProfileCert(params->GetOptions(), api);
            break;
        case MapNum::NUM_6:
            isSuccess = RunCert(params->GetOptions(), api);
            break;
        default:
            break;
    }
    return isSuccess;
}
bool HapSignTool::RunSignApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::MODE, Options::IN_FILE, Options::OUT_FILE, Options::SIGN_ALG })) {
        return false;
    }
    std::string mode = params->GetString(Options::MODE);
    std::string remote = "remoteResign";
    if (!StringUtils::CaseCompare(mode, HapSignTool::LOCAL_SIGN) &&
        !StringUtils::CaseCompare(mode, HapSignTool::REMOTE_SIGN) &&
        !StringUtils::CaseCompare(mode, remote)) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "mode params is incorrect");
        return false;
    }
    if (StringUtils::CaseCompare(mode, HapSignTool::LOCAL_SIGN)) {
        if (!params->Required({ Options::KEY_STORE_FILE, Options::KEY_ALIAS, Options::APP_CERT_FILE })) {
            return false;
        }
        if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" })) {
            return false;
        }
    }
    if (!CheckProfile(*params)) {
        return false;
    }
    std::string zip = "zip";
    std::string inForm = params->GetString(Options::INFORM, zip);
    if (!StringUtils::IsEmpty(inForm) && !StringUtils::ContainsCase(InformList, inForm)) {
        CMD_ERROR_MSG("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "inForm params is incorrect");
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeEndSignAlgType(signAlg)) {
        return false;
    }
    return api.SignHap(params);
}
bool HapSignTool::CheckProfile(Options& params)
{
    std::string inForm = params.GetString(Options::INFORM);
    std::string profileFile = params.GetString(Options::PROFILE_FILE);

    std::string profileSigned = params.GetString(Options::PROFILE_SIGNED);
    std::string elf = "elf";
    if (StringUtils::CaseCompare(inForm, elf) && FileUtils::IsEmpty(profileFile)) {
        SIGNATURE_TOOLS_LOGW("INFORM with PROFILE_FILE Check error ! \n");
        return true;
    }

    if (profileSigned == "1") {
        if (!FileUtils::ValidFileType(profileFile, { "p7b" })) {
            return false;
        }
        return true;
    } else {
        if (!FileUtils::ValidFileType(profileFile, { "json" })) {
            return false;
        }
        return true;
    }
}
bool HapSignTool::DispatchParams(ParamsSharedPtr params, SignToolServiceImpl& api)
{
    bool isSuccess = false;
    std::map<std::string, int> map;
    map.insert(std::make_pair(Method::SIGN_APP, MapNum::NUM_1));
    map.insert(std::make_pair(Method::SIGN_PROFILE, MapNum::NUM_2));
    map.insert(std::make_pair(Method::VERIFY_APP, MapNum::NUM_3));
    map.insert(std::make_pair(Method::VERIFY_PROFILE, MapNum::NUM_4));
    switch (map[params->GetMethod()]) {
        case MapNum::NUM_1:
            isSuccess = RunSignApp(params->GetOptions(), api);
            break;
        case MapNum::NUM_2:
            isSuccess = HapSignTool::RunSignProfile(params->GetOptions(), api);
            break;
        case MapNum::NUM_3:
            isSuccess = RunVerifyApp(params->GetOptions(), api);
            break;
        case MapNum::NUM_4:
            isSuccess = HapSignTool::RunVerifyProfile(params->GetOptions(), api);
            break;
        default:
            isSuccess = HapSignTool::CallGenerators(params, api);
            break;
    }
    return isSuccess;
}



bool HapSignTool::RunCa(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::KEY_ALIAS, Options::KEY_ALG,
        Options::KEY_SIZE, Options::SUBJECT, Options::SIGN_ALG, Options::KEY_STORE_FILE })) {
        return false;
    }
    std::string keyAlg = params->GetString(Options::KEY_ALG);
    if (!CmdUtil::JudgeAlgType(keyAlg)) {
        return false;
    }
    int size = params->GetInt(Options::KEY_SIZE);
    if (!CmdUtil::JudgeSize(size)) {
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" })) {
        return false;
    }
    
    return api.GenerateCA(params);
}
bool HapSignTool::RunCert(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::KEY_ALIAS, Options::ISSUER,
        Options::ISSUER_KEY_ALIAS, Options::SUBJECT, Options::KEY_USAGE,
        Options::SIGN_ALG, Options::KEY_STORE_FILE })) {
        return false;
    }
    std::string keyusage = params->GetString(Options::KEY_USAGE);
    if (!CmdUtil::VerifyTypes(keyusage)) {
        return false;
    }
    std::string extkeyusage = params->GetString(Options::EXT_KEY_USAGE);
    if (!extkeyusage.empty()) {
        if (!CmdUtil::VerifyType(extkeyusage)) {
            return false;
        }
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" })) {
        return false;
    }
    return api.GenerateCert(params);
}
bool HapSignTool::CheckEndCertArguments(Options& params)
{
    if (!params.Required({ params.KEY_ALIAS, params.ISSUER, params.ISSUER_KEY_ALIAS,
                        params.SUBJECT, params.SIGN_ALG, params.KEY_STORE_FILE })) {
        return false;
    }
    std::string signAlg = params.GetString(params.SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    std::string outForm = params.GetString(params.OUT_FORM);
    if (!outForm.empty()) {
        if (!CmdUtil::VerifyType(outForm, Options::OUT_FORM_SCOPE)) {
        }
    }
    if (!outForm.empty() && "certChain" == outForm) {
        if (!params.Required({ params.SUB_CA_CERT_FILE, params.CA_CERT_FILE })) {
            return false;
        }
        if (!FileUtils::ValidFileType(params.GetString(params.SUB_CA_CERT_FILE), { "cer" })
            || !FileUtils::ValidFileType(params.GetString(params.CA_CERT_FILE), { "cer" })) {
            return false;
        }
    }
    std::string keyStoreFile = params.GetString(params.KEY_STORE_FILE);
    if (!FileUtils::ValidFileType(keyStoreFile, { "p12", "jks" })) {
        return false;
    }
    if (params.find(params.ISSUER_KEY_STORE_FILE) != params.end()) {
        std::string issuerKeyStoreFile = params.GetString(params.ISSUER_KEY_STORE_FILE);
        if (!FileUtils::ValidFileType(issuerKeyStoreFile, { "p12", "jks" })) {
        }
    }
    std::string outFile = params.GetString(params.OUT_FILE);
    if (!outFile.empty()) {
        FileUtils::ValidFileType(outFile, { "cer", "pem" });
    }
    return true;
}
bool HapSignTool::RunAppCert(Options* params, SignToolServiceImpl& api)
{
    if (!HapSignTool::CheckEndCertArguments(*params)) {
        return false;
    }
    return api.GenerateAppCert(params);
}
bool HapSignTool::RunProfileCert(Options* params, SignToolServiceImpl& api)
{
    if (!HapSignTool::CheckEndCertArguments(*params)) {
        return false;
    }
    return api.GenerateProfileCert(params);
}
bool HapSignTool::RunKeypair(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::KEY_ALIAS, Options::KEY_ALG, Options::KEY_SIZE, Options::KEY_STORE_FILE })) {
        return false;
    }
    std::string keyAlg = params->GetString(Options::KEY_ALG);
    if (!CmdUtil::JudgeAlgType(keyAlg)) {
        return false;
    }
    int size = params->GetInt(Options::KEY_SIZE);
    if (!CmdUtil::JudgeSize(size)) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" })) {
        return false;
    }
    return api.GenerateKeyStore(params);
}
bool HapSignTool::RunCsr(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::KEY_ALIAS, Options::SUBJECT, Options::SIGN_ALG, Options::KEY_STORE_FILE })) {
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" })) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_FILE), { "csr" })) {
    }
    return api.GenerateCsr(params);
}
bool HapSignTool::RunSignProfile(Options* params, SignToolServiceImpl& api)
{
    if (params->Required({ params->MODE, params->SIGN_ALG, params->OUT_FILE, params->IN_FILE }) == false) {
        return false;
    }
    std::string mode = params->GetString(Options::MODE);
    if (!StringUtils::CaseCompare(mode, HapSignTool::LOCAL_SIGN) &&
        !StringUtils::CaseCompare(mode, HapSignTool::REMOTE_SIGN)) {
        CMD_ERROR_MSG("COMMAND_ERROR", COMMAND_ERROR, "mode params is incorrect");
        return false;
    }
    if (StringUtils::CaseCompare(mode, HapSignTool::LOCAL_SIGN)) {
        if (params->Required({ params->KEY_STORE_FILE, params->KEY_ALIAS, params->PROFILE_CERT_FILE }) == false)
            return false;
        if (FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), { "p12", "jks" }) == false)
            return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (CmdUtil::JudgeEndSignAlgType(signAlg) == false) {
        return false;
    }
    std::string outFile = params->GetString(Options::OUT_FILE);
    if (FileUtils::ValidFileType(outFile, { "p7b" }) == false) {
        return false;
    }
    return api.SignProfile(params);
}
bool HapSignTool::RunVerifyProfile(Options* params, SignToolServiceImpl& api)
{
    if (params->Required({ Options::IN_FILE }) == false)
        return false;
    if (FileUtils::ValidFileType(params->GetString(Options::IN_FILE), { "p7b" }) == false)
        return true;
    std::string outFile = params->GetString(Options::OUT_FILE);
    if (!outFile.empty()) {
        if (FileUtils::ValidFileType(outFile, { "json" }) == false)
            return false;
    }
    return api.VerifyProfile(params);
}
void HapSignTool::PrintHelp()
{
    std::ifstream readHelp(HELP_FILE_PATH.c_str(), std::ios::in | std::ios::binary);
    if (readHelp.is_open()) {
        std::string line;
        while (std::getline(readHelp, line)) {
            printf("%s\n", line.c_str());
        }
        readHelp.close();
    } else {
        CMD_ERROR_MSG("OPEN_FILE_ERROR", OPEN_FILE_ERROR, "Open " + HELP_FILE_PATH + " failed");
    }
}
void  HapSignTool::Version()
{
    printf("%s\n", HapSignTool::VERSION.c_str());
}
bool HapSignTool::RunVerifyApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({ Options::IN_FILE, Options::OUT_CERT_CHAIN, Options::OUT_PROFILE })) {
        return false;
    }
    std::string zip = "zip";
    std::string inForm = params->GetString(Options::INFORM, zip);
    if (!StringUtils::ContainsCase(InformList, inForm)) {
        CMD_ERROR_MSG("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "inForm params must is [bin, elf, zip]");
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_CERT_CHAIN), { "cer" })) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_PROFILE), { "p7b" })) {
        return false;
    }
    return api.VerifyHap(params);
}