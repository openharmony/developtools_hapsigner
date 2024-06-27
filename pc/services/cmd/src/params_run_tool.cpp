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

#include "params_run_tool.h"
#include <unistd.h>
#include <memory>

#include "constant.h"

namespace OHOS {
namespace SignatureTools {
const std::string ParamsRunTool::VERSION = "1.0.0";
const std::string ParamsRunTool::LOCAL_SIGN = "localSign";
const std::string ParamsRunTool::REMOTE_SIGN = "remoteSign";

std::string GetCurrentHelpTxtPath()
{
    static constexpr int len = 256;
    char buf[len]{0};
    std::string cwd = getcwd(buf, sizeof(buf));
    return cwd + "/help.txt";
}

std::vector<std::string> ParamsRunTool::InformList;
enum class MapNum {
    NUM_1 = 1,
    NUM_2,
    NUM_3,
    NUM_4,
    NUM_5,
    NUM_6
};

ParamsRunTool::ParamsRunTool()
{
    InformList.push_back("bin");
    InformList.push_back("elf");
    InformList.push_back("zip");
}

bool ParamsRunTool::ProcessCmd(char** args, size_t size)
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
            PrintMsg("Parameter processing failed");
            return false;
        }
        PrintMsg("Start " + param->GetMethod());
        SIGNATURE_TOOLS_LOGI("%{public}s run start time  ", param->GetMethod().c_str());
        if (!DispatchParams(param, *service_api.get())) {
            SIGNATURE_TOOLS_LOGI("%{public}s run end time  ", param->GetMethod().c_str());
            PrintMsg(param->GetMethod() + " failed");
            return false;
        }
        PrintMsg(param->GetMethod() + " success");
        SIGNATURE_TOOLS_LOGI("%{public}s run end time  ", param->GetMethod().c_str());
    }
    return true;
}

bool ParamsRunTool::CallGenerators(ParamsSharedPtr params, SignToolServiceImpl& api)
{
    bool isSuccess = false;
    std::map<std::string, MapNum> map;
    map.insert(std::make_pair(Params::GENERATE_KEYPAIR, MapNum::NUM_1));
    map.insert(std::make_pair(Params::GENERATE_CSR, MapNum::NUM_2));
    map.insert(std::make_pair(Params::GENERATE_CA, MapNum::NUM_3));
    map.insert(std::make_pair(Params::GENERATE_APP_CERT, MapNum::NUM_4));
    map.insert(std::make_pair(Params::GENERATE_PROFILE_CERT, MapNum::NUM_5));
    map.insert(std::make_pair(Params::GENERATE_CERT, MapNum::NUM_6));
    switch (map[params->GetMethod()]) {
        case MapNum::NUM_1:
            isSuccess = ParamsRunTool::RunKeypair(params->GetOptions(), api);
            break;
        case MapNum::NUM_2:
            isSuccess = ParamsRunTool::RunCsr(params->GetOptions(), api);
            break;
        case MapNum::NUM_3:
            isSuccess = ParamsRunTool::RunCa(params->GetOptions(), api);
            break;
        case MapNum::NUM_4:
            isSuccess = ParamsRunTool::RunAppCert(params->GetOptions(), api);
            break;
        case MapNum::NUM_5:
            isSuccess = ParamsRunTool::RunProfileCert(params->GetOptions(), api);
            break;
        case MapNum::NUM_6:
            isSuccess = ParamsRunTool::RunCert(params->GetOptions(), api);
            break;
        default:
            break;
    }
    return isSuccess;
}

bool ParamsRunTool::RunSignApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::MODE, Options::IN_FILE, Options::OUT_FILE, Options::SIGN_ALG})) {
        return false;
    }
    std::string mode = params->GetString(Options::MODE);
    std::string remote = "remoteResign";
    if (!StringUtils::CaseCompare(mode, ParamsRunTool::LOCAL_SIGN) &&
        !StringUtils::CaseCompare(mode, ParamsRunTool::REMOTE_SIGN) &&
        !StringUtils::CaseCompare(mode, remote)) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "mode params is incorrect");
        return false;
    }
    if (StringUtils::CaseCompare(mode, ParamsRunTool::LOCAL_SIGN)) {
        if (!params->Required({Options::KEY_STORE_FILE, Options::KEY_ALIAS, Options::APP_CERT_FILE})) {
            return false;
        }
        if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
            return false;
        }
    }
    if (!CheckProfile(*params)) {
        return false;
    }
    std::string inForm = params->GetString(Options::INFORM, ZIP);
    if (!StringUtils::IsEmpty(inForm) && !StringUtils::ContainsCase(InformList, inForm)) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "inForm params is incorrect");
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeEndSignAlgType(signAlg)) {
        return false;
    }
    return api.SignHap(params);
}

bool ParamsRunTool::CheckProfile(Options& params)
{
    std::string inForm = params.GetString(Options::INFORM);
    std::string profileFile = params.GetString(Options::PROFILE_FILE);

    std::string profileSigned = params.GetString(Options::PROFILE_SIGNED);
    if (StringUtils::CaseCompare(inForm, ELF) && FileUtils::IsEmpty(profileFile)) {
        SIGNATURE_TOOLS_LOGE("INFORM with PROFILE_FILE Check error ! \n");
        return false;
    }

    if (profileSigned == "1") {
        if (!FileUtils::ValidFileType(profileFile, {"p7b"})) {
            return false;
        }
        return true;
    } else {
        if (!FileUtils::ValidFileType(profileFile, {"json"})) {
            return false;
        }
        return true;
    }
}

bool ParamsRunTool::DispatchParams(ParamsSharedPtr params, SignToolServiceImpl& api)
{
    bool isSuccess = false;
    std::map<std::string, MapNum> map;
    map.insert(std::make_pair(Params::SIGN_APP, MapNum::NUM_1));
    map.insert(std::make_pair(Params::SIGN_PROFILE, MapNum::NUM_2));
    map.insert(std::make_pair(Params::VERIFY_APP, MapNum::NUM_3));
    map.insert(std::make_pair(Params::VERIFY_PROFILE, MapNum::NUM_4));
    switch (map[params->GetMethod()]) {
        case MapNum::NUM_1:
            isSuccess = ParamsRunTool::RunSignApp(params->GetOptions(), api);
            break;
        case MapNum::NUM_2:
            isSuccess = ParamsRunTool::RunSignProfile(params->GetOptions(), api);
            break;
        case MapNum::NUM_3:
            isSuccess = ParamsRunTool::RunVerifyApp(params->GetOptions(), api);
            break;
        case MapNum::NUM_4:
            isSuccess = ParamsRunTool::RunVerifyProfile(params->GetOptions(), api);
            break;
        default:
            isSuccess = ParamsRunTool::CallGenerators(params, api);
            break;
    }
    return isSuccess;
}

bool ParamsRunTool::RunCa(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::KEY_ALIAS, Options::KEY_ALG,
        Options::KEY_SIZE, Options::SUBJECT, Options::SIGN_ALG, Options::KEY_STORE_FILE})) {
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
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
        return false;
    }

    return api.GenerateCA(params);
}

bool ParamsRunTool::RunCert(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::KEY_ALIAS, Options::ISSUER,
        Options::ISSUER_KEY_ALIAS, Options::SUBJECT, Options::KEY_USAGE,
        Options::SIGN_ALG, Options::KEY_STORE_FILE})) {
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
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
        return false;
    }
    return api.GenerateCert(params);
}

bool ParamsRunTool::CheckEndCertArguments(Options& params)
{
    if (!params.Required({params.KEY_ALIAS, params.ISSUER, params.ISSUER_KEY_ALIAS,
                        params.SUBJECT, params.SIGN_ALG, params.KEY_STORE_FILE})) {
        return false;
    }
    std::string signAlg = params.GetString(params.SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    std::string outForm = params.GetString(params.OUT_FORM);
    if (!outForm.empty()) {
        if (!CmdUtil::VerifyType(outForm, Options::OUT_FORM_SCOPE)) {
            return false;
        }
    }
    if (!outForm.empty() && "certChain" == outForm) {
        if (!params.Required({params.SUB_CA_CERT_FILE, params.CA_CERT_FILE})) {
            return false;
        }
        if (!FileUtils::ValidFileType(params.GetString(params.SUB_CA_CERT_FILE), {"cer"}) ||
            !FileUtils::ValidFileType(params.GetString(params.CA_CERT_FILE), {"cer"})) {
            return false;
        }
    }
    std::string keyStoreFile = params.GetString(params.KEY_STORE_FILE);
    if (!FileUtils::ValidFileType(keyStoreFile, {"p12", "jks"})) {
        return false;
    }
    if (params.find(params.ISSUER_KEY_STORE_FILE) != params.end()) {
        std::string issuerKeyStoreFile = params.GetString(params.ISSUER_KEY_STORE_FILE);
        if (!FileUtils::ValidFileType(issuerKeyStoreFile, {"p12", "jks"})) {
            return false;
        }
    }
    std::string outFile = params.GetString(params.OUT_FILE);
    if (!outFile.empty()) {
        if (!FileUtils::ValidFileType(outFile, {"cer", "pem"})) {
            return false;
        }
    }
    return true;
}

bool ParamsRunTool::RunAppCert(Options* params, SignToolServiceImpl& api)
{
    if (!ParamsRunTool::CheckEndCertArguments(*params)) {
        return false;
    }
    return api.GenerateAppCert(params);
}

bool ParamsRunTool::RunProfileCert(Options* params, SignToolServiceImpl& api)
{
    if (!ParamsRunTool::CheckEndCertArguments(*params)) {
        return false;
    }
    return api.GenerateProfileCert(params);
}

bool ParamsRunTool::RunKeypair(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::KEY_ALIAS, Options::KEY_ALG, Options::KEY_SIZE, Options::KEY_STORE_FILE})) {
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
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
        return false;
    }
    return api.GenerateKeyStore(params);
}

bool ParamsRunTool::RunCsr(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::KEY_ALIAS, Options::SUBJECT, Options::SIGN_ALG, Options::KEY_STORE_FILE})) {
        return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (!CmdUtil::JudgeSignAlgType(signAlg)) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"})) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_FILE), {"csr"})) {
    }
    return api.GenerateCsr(params);
}

bool ParamsRunTool::RunSignProfile(Options* params, SignToolServiceImpl& api)
{
    if (params->Required({params->MODE, params->SIGN_ALG, params->OUT_FILE, params->IN_FILE}) == false) {
        return false;
    }
    std::string mode = params->GetString(Options::MODE);
    if (!StringUtils::CaseCompare(mode, ParamsRunTool::LOCAL_SIGN) &&
        !StringUtils::CaseCompare(mode, ParamsRunTool::REMOTE_SIGN)) {
        PrintErrorNumberMsg("COMMAND_ERROR", COMMAND_ERROR, "mode params is incorrect");
        return false;
    }
    if (StringUtils::CaseCompare(mode, ParamsRunTool::LOCAL_SIGN)) {
        if (params->Required({params->KEY_STORE_FILE, params->KEY_ALIAS, params->PROFILE_CERT_FILE}) == false)
            return false;
        if (FileUtils::ValidFileType(params->GetString(Options::KEY_STORE_FILE), {"p12", "jks"}) == false)
            return false;
    }
    std::string signAlg = params->GetString(Options::SIGN_ALG);
    if (CmdUtil::JudgeEndSignAlgType(signAlg) == false) {
        return false;
    }
    std::string outFile = params->GetString(Options::OUT_FILE);
    if (FileUtils::ValidFileType(outFile, {"p7b"}) == false) {
        return false;
    }
    return api.SignProfile(params);
}

bool ParamsRunTool::RunVerifyProfile(Options* params, SignToolServiceImpl& api)
{
    if (params->Required({Options::IN_FILE}) == false)
        return false;
    if (FileUtils::ValidFileType(params->GetString(Options::IN_FILE), {"p7b"}) == false)
        return true;
    std::string outFile = params->GetString(Options::OUT_FILE);
    if (!outFile.empty()) {
        if (FileUtils::ValidFileType(outFile, {"json"}) == false)
            return false;
    }
    return api.VerifyProfile(params);
}

void ParamsRunTool::PrintHelp()
{
    std::ifstream readHelp(GetCurrentHelpTxtPath().c_str(), std::ios::in | std::ios::binary);
    if (readHelp.is_open()) {
        std::string line;
        PrintMsg("");
        while (std::getline(readHelp, line)) {
            printf("%s\n", line.c_str());
        }
        readHelp.close();
    } else {
        PrintErrorNumberMsg("OPEN_FILE_ERROR", OPEN_FILE_ERROR, "Open " + GetCurrentHelpTxtPath() + " failed");
    }
}

void  ParamsRunTool::Version()
{
    PrintMsg(ParamsRunTool::VERSION);
}

bool ParamsRunTool::RunVerifyApp(Options* params, SignToolServiceImpl& api)
{
    if (!params->Required({Options::IN_FILE, Options::OUT_CERT_CHAIN, Options::OUT_PROFILE})) {
        return false;
    }
    std::string inForm = params->GetString(Options::INFORM, ZIP);
    if (!StringUtils::ContainsCase(InformList, inForm)) {
        PrintErrorNumberMsg("NOT_SUPPORT_ERROR", NOT_SUPPORT_ERROR, "inForm params must is [bin, elf, zip]");
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_CERT_CHAIN), {"cer"})) {
        return false;
    }
    if (!FileUtils::ValidFileType(params->GetString(Options::OUT_PROFILE), {"p7b"})) {
        return false;
    }
    return api.VerifyHapSigner(params);
}
} // namespace SignatureTools
} // namespace OHOS