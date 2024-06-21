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
#include "sign_provider.h"

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <cstdio>
#include <filesystem>

#include "nlohmann/json.hpp"
#include "string_utils.h"
#include "file_utils.h"
#include "sign_elf.h"
#include "sign_bin.h"
#include "params.h"

using namespace nlohmann;
namespace OHOS {
namespace SignatureTools {
std::vector<std::string> SignProvider::VALID_SIGN_ALG_NAME = std::vector<std::string>();
std::vector<std::string> SignProvider::PARAMETERS_NEED_ESCAPE = std::vector<std::string>();

bool SignProvider::PrintErrorLog(const std::string& log, const int& errorCode, std::string path)
{
    PrintErrorNumberMsg("SIGN_HAP", errorCode, log);
    if (path != "") {
        remove(path.c_str());
    }
    return false;
}

bool SignProvider::InitSigerConfig(SignerConfig& signerConfig, STACK_OF(X509)* publicCerts, Options* options)
{
    std::optional<X509_CRL*> crl = GetCrl();
    if (!CreateSignerConfigs(publicCerts, crl, options, signerConfig)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] create Signer Configs failed");
        return false;
    }
    int CompatibleVersion;
    if (!CheckStringToint(signParams.at(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION), CompatibleVersion)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] CompatibleVersion String To int failed");
        return false;
    }
    signerConfig.SetCompatibleVersion(CompatibleVersion);
    return true;
}

fileIOTuple SignProvider::PrepareIOStreams(const std::string& inputPath,
                                           const std::string& outputPath, bool& ret)
{
    std::shared_ptr<std::ifstream> inputFile = nullptr;
    std::shared_ptr<std::ofstream> outputFile = nullptr;
    std::string tmpOutputFilePath;
    ret = false;
    inputFile = std::make_shared<std::ifstream>(inputPath, std::ios::binary);
    if (!inputFile->good()) {
        SIGNATURE_TOOLS_LOGE("[signHap] Failed to open input file : %s", inputPath.c_str());
        return { nullptr, nullptr, "" };
    }
    if (inputPath == outputPath) {
        std::filesystem::path filePath = outputPath;
        std::filesystem::path directory = filePath.parent_path();
        std::string strDirectory = directory;
        tmpOutputFilePath = strDirectory + '/' + std::string("signedHap") + "." + "hap";
        outputFile = std::make_shared<std::ofstream>(tmpOutputFilePath, std::ios::binary | std::ios::trunc);
        if (!outputFile->good()) {
            SIGNATURE_TOOLS_LOGE("[signHap] Failed to open output file : %s", tmpOutputFilePath.c_str());
            return { nullptr, nullptr, "" };
        }
        ret = true;
    } else {
        outputFile = std::make_shared<std::ofstream>(outputPath, std::ios::binary | std::ios::trunc);
        if (!outputFile->good()) {
            SIGNATURE_TOOLS_LOGE("[signHap] Failed to open output file : %s", outputPath.c_str());
            return { nullptr, nullptr, "" };
        }
        tmpOutputFilePath = outputPath;
    }
    return { inputFile, outputFile, tmpOutputFilePath };
}

bool SignProvider::InitZipOutput(std::shared_ptr<RandomAccessFile> outputHap,
                                 std::shared_ptr<ZipSigner> zip,
                                 std::shared_ptr<std::ifstream> inputStream,
                                 std::shared_ptr<std::ofstream>tmpOutput,
                                 std::string Path)
{
    int alignment;
    if (!CheckStringToint(signParams.at(ParamConstants::PARAM_BASIC_ALIGNMENT), alignment)) {
        SIGNATURE_TOOLS_LOGE("[signHap] alignment String To int failed");
        return false;
    }

    if (!CopyFileAndAlignment(*inputStream, *tmpOutput, alignment, *zip)) {
        SIGNATURE_TOOLS_LOGE("[signHap] copy File And Alignment failed");
        remove(Path.c_str());
        return false;
    }
    inputStream->close();
    tmpOutput->flush();
    tmpOutput->close();
    if (!outputHap->Init(Path)) {
        SIGNATURE_TOOLS_LOGE("[signHap] init outputFile failed %s", Path.c_str());
        remove(Path.c_str());
        return false;
    }
    return true;
}

bool SignProvider::InitDataSourceContents(RandomAccessFile& outputHap, DataSourceContents& dataSrcContents)
{
    std::shared_ptr<ZipDataInput> outputHapIn = std::make_shared<RandomAccessFileInput>(outputHap);
    // get eocd bytebuffer and eocd offset
    if (!HapSignerBlockUtils::FindEocdInHap(outputHap, dataSrcContents.eocdPair)) 
        return PrintErrorLog("[signHap] can not find eocd in file", ZIP_ERROR);
    dataSrcContents.endOfCentralDir = new ByteBufferDataSource(dataSrcContents.eocdPair.first);
    if (!dataSrcContents.endOfCentralDir) return false;

    // get cd offset
    if (!HapSignerBlockUtils::GetCentralDirectoryOffset(dataSrcContents.eocdPair.first,
        dataSrcContents.eocdPair.second, dataSrcContents.cDOffset)) return false;

    SIGNATURE_TOOLS_LOGI("Central Directory Offset is %{public}lld.", dataSrcContents.cDOffset);

    // get beforeCentralDir
    dataSrcContents.beforeCentralDir = outputHapIn->Slice(0, dataSrcContents.cDOffset);
    if (!dataSrcContents.beforeCentralDir) return false;

    // get cd size
    long cDSize;
    if (!HapSignerBlockUtils::GetCentralDirectorySize(dataSrcContents.eocdPair.first, cDSize)) return false;

    // get cd buffer
    dataSrcContents.cDByteBuffer = outputHapIn->CreateByteBuffer(dataSrcContents.cDOffset, cDSize);
    if (dataSrcContents.cDByteBuffer.GetCapacity() == 0) return false;
    dataSrcContents.centralDir = new ByteBufferDataSource(dataSrcContents.cDByteBuffer);
    if (!dataSrcContents.centralDir) return false;
    return true;
}

bool SignProvider::Sign(Options* options)
{
    bool isPathOverlap = false;
    STACK_OF(X509)* publicCerts = nullptr;
    int ret = GetX509Certificates(options, &publicCerts);
    if (ret != RET_OK) {
        if (publicCerts) {
            sk_X509_pop_free(publicCerts, X509_free);
        }
        PrintErrorNumberMsg("SIGNHAP_ERROR", ret, "get X509 Certificates failed");
        return false;
    }
    // todo 错误判断
    if (!CheckCompatibleVersion())
        return PrintErrorLog("[SignHap] check Compatible Version failed!!", COMMAND_PARAM_ERROR);
    std::string inputFilePath = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    std::string suffix = FileUtils::GetSuffix(inputFilePath);
    if (suffix == "")
        return PrintErrorLog("[SignHap] hap format error pleass check!!", COMMAND_PARAM_ERROR);
    auto [inputStream, tmpOutput, tmpOutputFilePath] =
        PrepareIOStreams(inputFilePath,
                         signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE),
                         isPathOverlap);
    if (!inputStream || !tmpOutput)
        return PrintErrorLog("[signHap] Prepare IO Streams failed", IO_ERROR);
    std::shared_ptr<ZipSigner> zip = std::make_shared<ZipSigner>();
    std::shared_ptr<RandomAccessFile> outputHap = std::make_shared<RandomAccessFile>();
    if (!InitZipOutput(outputHap, zip, inputStream, tmpOutput, tmpOutputFilePath))
        return PrintErrorLog("[signHap] Init Zip Output failed", IO_ERROR);
    DataSourceContents dataSrcContents;
    if (!InitDataSourceContents(*outputHap, dataSrcContents))
        return PrintErrorLog("[signHap] Init Data Source Contents failed", ZIP_ERROR);
    DataSource* contents[] = { dataSrcContents.beforeCentralDir,
        dataSrcContents.centralDir, dataSrcContents.endOfCentralDir
    };
    SignerConfig signerConfig;
    if (!InitSigerConfig(signerConfig, publicCerts, options))
        return PrintErrorLog("SignHap] create Signer Configs failed", COMMAND_PARAM_ERROR, tmpOutputFilePath);
    //// 追加代码签名块
    if (!AppendCodeSignBlock(&signerConfig, tmpOutputFilePath, suffix, dataSrcContents.cDOffset, *zip))
        return PrintErrorLog("[SignCode] AppendCodeSignBlock failed", SIGN_ERROR, tmpOutputFilePath);
    ByteBuffer signingBlock;
    if (!SignHap::Sign(contents, sizeof(contents) / sizeof(contents[0]), signerConfig, optionalBlocks,
        signingBlock))
        return PrintErrorLog("[SignHap] SignHap Sign failed.", SIGN_ERROR, tmpOutputFilePath);
    long long newCentralDirectoryOffset = dataSrcContents.cDOffset + signingBlock.GetCapacity();
    SIGNATURE_TOOLS_LOGI("new Central Directory Offset is %{public}lld.", newCentralDirectoryOffset);

    dataSrcContents.eocdPair.first.SetPosition(0);
    if (!ZipUtils::SetCentralDirectoryOffset(dataSrcContents.eocdPair.first, newCentralDirectoryOffset))
        return PrintErrorLog("[SignHap] Set Central Directory Offset.", ZIP_ERROR, tmpOutputFilePath);
    if (!OutputSignedFile(outputHap.get(), dataSrcContents.cDOffset, signingBlock, dataSrcContents.centralDir,
        dataSrcContents.eocdPair.first))
        return PrintErrorLog("[SignHap] write output signed file failed.", ZIP_ERROR, tmpOutputFilePath);
    return DoAfterSign(isPathOverlap, tmpOutputFilePath, inputFilePath);
}

bool SignProvider::SignElf(Options* options)
{
    bool isPathOverlap = false;
    STACK_OF(X509)* publicCerts = nullptr;
    int ret = GetX509Certificates(options, &publicCerts);
    if (ret != RET_OK) {
        if (publicCerts) {
            sk_X509_pop_free(publicCerts, X509_free);
        }
        SIGNATURE_TOOLS_LOGE("[SignElf] get X509 Certificates failed! errorCode:%{public}d", ret);
        return false;
    }
    if (!CheckCompatibleVersion()) {
        SIGNATURE_TOOLS_LOGE("[SignElf] check Compatible Version failed!!");
        return false;
    }

    std::string inputFilePath = signParams.at(ParamConstants::PARAM_BASIC_INPUT_FILE);
    std::string suffix = FileUtils::GetSuffix(inputFilePath);
    if (suffix == "") {
        SIGNATURE_TOOLS_LOGE("[SignElf] elf format error pleass check!!");
        return false;
    }

    auto [inputStream, tmpOutput, tmpOutputFilePath] =
        PrepareIOStreams(inputFilePath,
                         signParams.at(ParamConstants::PARAM_BASIC_OUTPUT_FILE),
                         isPathOverlap);

    if (!inputStream || !tmpOutput) {
        SIGNATURE_TOOLS_LOGE("[signElf] Prepare IO Streams failed");
        return false;
    }

    SignerConfig signerConfig;
    if (!InitSigerConfig(signerConfig, publicCerts, options)) {
        SIGNATURE_TOOLS_LOGE("SignElf] create Signer Configs failed");
        return false;
    }

    if (!profileContent.empty()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_PROFILE_JSON_CONTENT, profileContent));
    }

    if (!SignElf::Sign(signerConfig, signParams)) {
        SIGNATURE_TOOLS_LOGE("[SignElf] sign elf failed");
        return false;
    }

    return true;
}

bool SignProvider::SignBin(Options* options)
{
    STACK_OF(X509)* x509Certificates = nullptr;
    int ret = GetX509Certificates(options, &x509Certificates);
    if (ret != RET_OK) {
        if (x509Certificates) {
            sk_X509_pop_free(x509Certificates, X509_free);
        }
        SIGNATURE_TOOLS_LOGE("[SignBin] get X509 Certificates failed! errorCode:%{public}d", ret);
        return false;
    }
    if (!CheckCompatibleVersion()) {
        SIGNATURE_TOOLS_LOGE("check Compatible Version failed!");
        return false;
    }

    SignerConfig signerConfig;
    if (!InitSigerConfig(signerConfig, x509Certificates, options)) {
        SIGNATURE_TOOLS_LOGE("[SignBin] create Signer Configs failed");
        return false;
    }

    bool signFlag = SignBin::Sign(signerConfig, signParams);
    if (!signFlag) {
        SIGNATURE_TOOLS_LOGE("sign bin internal failed");
        return false;
    }

    SIGNATURE_TOOLS_LOGE("sign bin success");
    return true;
}

bool SignProvider::AppendCodeSignBlock(SignerConfig* signerConfig, std::string outputFilePath,
                                       const std::string& suffix, long long centralDirectoryOffset, ZipSigner& zip)
{
    if (signParams.at(ParamConstants::PARAM_SIGN_CODE) == CodeSigning::ENABLE_SIGN_CODE_VALUE) {
        SIGNATURE_TOOLS_LOGI("start code signing.");
        if (std::find(CodeSigning::SUPPORT_FILE_FORM.begin(), CodeSigning::SUPPORT_FILE_FORM.end(),
            suffix) == CodeSigning::SUPPORT_FILE_FORM.end()) {
            SIGNATURE_TOOLS_LOGE("no need to sign code.");
            return true;
        }
        // 4 means hap format occupy 4 byte storage location,2 means optional blocks reserve 2 storage location
        long long codeSignOffset = centralDirectoryOffset + ((4 + 4 + 4) * (optionalBlocks.size() + 2 + 1));
        // create CodeSigning Object
        CodeSigning codeSigning(signerConfig);
        std::vector<int8_t> codeSignArray;
        if (!codeSigning.GetCodeSignBlock(outputFilePath, codeSignOffset, suffix, profileContent, zip,
            codeSignArray)) {
            SIGNATURE_TOOLS_LOGE("Codesigning getCodeSignBlock Fail.");
            return false;
        }
        SIGNATURE_TOOLS_LOGI("generate codeSignArray finished.");
        std::unique_ptr<ByteBuffer> result =
            std::make_unique<ByteBuffer>(codeSignArray.size()
                                         + (FOUR_BYTE + FOUR_BYTE + FOUR_BYTE));
        result->PutInt32(HapUtils::HAP_CODE_SIGN_BLOCK_ID);
        result->PutInt32(codeSignArray.size()); // length
        result->PutInt32((int32_t)codeSignOffset); // offset
        result->PutData(codeSignArray.data(), codeSignArray.size());

        OptionalBlock tmp = { HapUtils::HAP_PROPERTY_BLOCK_ID, *result };
        optionalBlocks.insert(optionalBlocks.begin(), tmp);
    }
    return true;
}

bool SignProvider::CreateSignerConfigs(STACK_OF(X509)* certificates, const std::optional<X509_CRL*>& crl,
                                       Options* options, SignerConfig& in_out)
{
    in_out.FillParameters(signParams); // 假定signParams是一个全局或类成员变量
    in_out.SetCertificates(certificates);
    in_out.SetOptions(options);
    std::vector<SignatureAlgorithmHelper> signatureAlgorithms;
    // lhx todo 默认构造函数
    SignatureAlgorithmHelper alg;
    if (!Params::GetSignatureAlgorithm(signParams.at(ParamConstants::PARAM_BASIC_SIGANTURE_ALG),
        alg)) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get Signature Algorithm failed");
        return false;
    }
    signatureAlgorithms.push_back(alg); // 注意：at()会抛出out_of_range异常，需处理或使用find()
    in_out.SetSignatureAlgorithms(signatureAlgorithms);
    if (crl.has_value()) {
    }
    return true;
}

int SignProvider::LoadOptionalBlocks()
{
    int ret = RET_OK;
    if (auto property = signParams.find(ParamConstants::PARAM_BASIC_PROPERTY);
        property != signParams.end()) {
        if ((ret = LoadOptionalBlock(property->second, HapUtils::HAP_PROPERTY_BLOCK_ID)) != RET_OK)
            return ret;
    }
    if (auto profile = signParams.find(ParamConstants::PARAM_BASIC_PROFILE); profile != signParams.end()) {
        if ((ret = LoadOptionalBlock(profile->second, HapUtils::HAP_PROFILE_BLOCK_ID)) != RET_OK)
            return ret;
    }
    if (auto proofOfRotation = signParams.find(ParamConstants::PARAM_BASIC_PROOF);
        proofOfRotation != signParams.end()) {
        if ((LoadOptionalBlock(proofOfRotation->second, HapUtils::HAP_PROOF_OF_ROTATION_BLOCK_ID)) != RET_OK)
            return ret;
    }
    return ret;
}

int SignProvider::LoadOptionalBlock(const std::string& file, int type)
{
    if (file.empty())
        return RET_OK;
    if (!CheckFile(file)) {
        SIGNATURE_TOOLS_LOGE("check file failed. Invalid file: %{public}s, file type: %{public}d",
                             file.c_str(), type);
        return FILE_NOT_FOUND;
    }
    ByteBuffer optionalBlockBuffer;
    if (!HapUtils::ReadFileToByteBuffer(file, optionalBlockBuffer))
        return IO_ERROR;
    if (optionalBlockBuffer.GetCapacity() == 0) {
        SIGNATURE_TOOLS_LOGE("Optional block is empty!");
        return IO_ERROR;
    }
    optionalBlocks.push_back({ type, optionalBlockBuffer });
    return RET_OK;
}

std::optional<X509_CRL*> SignProvider::GetCrl()
{
    return std::nullopt;
}

bool SignProvider::CheckFile(const std::string& filePath)
{
    if (filePath.empty()) {
        SIGNATURE_TOOLS_LOGE("fileName is null.");
        return false;
    }
    if (!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath)) {
        SIGNATURE_TOOLS_LOGE("%{public}s not exist or can not read!", filePath.c_str());
        return false;
    }
    return true;
}

int SignProvider::GetX509Certificates(Options* options, STACK_OF(X509)** X509Vec)
{
    int ret = RET_OK;
    // 1.check the parameters
    if (!CheckParams(options)) {
        SIGNATURE_TOOLS_LOGE("[SignProvider] Check Params failed please check");
        return COMMAND_ERROR;
    }
    // 2.get x509 verify certificate
    ret = GetPublicCerts(options, X509Vec);
    if (ret != RET_OK) {
        return ret;
    }
    // 3. load optionalBlocks
    ret = LoadOptionalBlocks();
    if (ret != RET_OK) {
        return ret;
    }
    // 4. check Profile Valid
    if ((ret = CheckProfileValid(*X509Vec)) < 0) {
        SIGNATURE_TOOLS_LOGE("invalid profile!");
        sk_X509_pop_free(*X509Vec, X509_free);
        *X509Vec = nullptr;
        return ret;
    }

    sk_X509_pop_free(*X509Vec, X509_free);
    *X509Vec = nullptr;
    return ret;
}

int SignProvider::GetPublicCerts(Options* options, STACK_OF(X509)** ret)
{
    // 参数 -appCertFile 应用签名证书文件（证书链，顺序为实体证书-中间CA证书-根证书），必填项;就是我们的 ./test1/app-release1.pem
    std::string appCertFileName = options->GetString(Options::APP_CERT_FILE);
    if (appCertFileName.empty()) {
        SIGNATURE_TOOLS_LOGI("appCertFile param can not find,may be is RemoteSigner");
        return RET_OK;
    }
    return GetCertificateChainFromFile(appCertFileName, ret);
}

int SignProvider::GetCertificateChainFromFile(const std::string& certChianFile, STACK_OF(X509)** ret)
{
    return GetCertListFromFile(certChianFile, ret);
}

int SignProvider::GetCertListFromFile(const std::string& certsFile, STACK_OF(X509)** ret)
{
    // lhxtodo 内存释放
    X509* cert = nullptr;
    *ret = sk_X509_new(nullptr);
    if (*ret == nullptr) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get CertList FromFile [sk_X509_new] failed");
        return IO_CERT_ERROR;
    }
    BIO* certBio = BIO_new_file(certsFile.c_str(), "rb");
    if (!certBio) {
        SIGNATURE_TOOLS_LOGE("[SignHap] get CertList FromFile [BIO_new_file] failed");
        sk_X509_free(*ret);
        return READ_FILE_ERROR;
    }
    // 读取
    while (1) {
        cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        if (cert == nullptr)
            break;
        sk_X509_push(*ret, cert);
    }
    BIO_free(certBio);
    return RET_OK;
}

bool SignProvider::DoAfterSign(bool isPathOverlap, std::string tmpOutputFile, std::string inputFilePath)
{
    if (isPathOverlap) {
        remove(inputFilePath.c_str());
        if (rename(tmpOutputFile.c_str(), inputFilePath.c_str()) != 0) {
            return PrintErrorLog("[SignHap] File name modification error !.", IO_ERROR);
        }
    }
    return true;
}

bool SignProvider::CopyFileAndAlignment(std::ifstream& input, std::ofstream& tmpOutput, int alignment, ZipSigner& zip)
{
    if (!zip.Init(input)) {
        SIGNATURE_TOOLS_LOGE("zip init failed");
        return false;
    }
    zip.Alignment(alignment);
    zip.RemoveSignBlock();
    if (!zip.ToFile(input, tmpOutput)) {
        SIGNATURE_TOOLS_LOGE("zip write to file failed");
        return false;
    }
    return true;
}

void SignProvider::StaticConstructor()
{
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA512_ECDSA);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA256_RSA_PSS);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA384_RSA_PSS);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA512_RSA_PSS);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA256_RSA_MGF1);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA384_RSA_MGF1);
    VALID_SIGN_ALG_NAME.push_back(ParamConstants::HAP_SIG_ALGORITHM_SHA512_RSA_MGF1);
    PARAMETERS_NEED_ESCAPE.push_back(ParamConstants::PARAM_REMOTE_CODE);
    PARAMETERS_NEED_ESCAPE.push_back(ParamConstants::PARAM_LOCAL_JKS_KEYSTORE_CODE);
    PARAMETERS_NEED_ESCAPE.push_back(ParamConstants::PARAM_LOCAL_JKS_KEYALIAS_CODE);
}
// YJR
bool SignProvider::CheckParams(Options* options)
{
    std::vector<std::string> paramFileds;
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_ALIGNMENT);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_SIGANTURE_ALG);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_INPUT_FILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_OUTPUT_FILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PRIVATE_KEY);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROFILE);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROOF);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROPERTY);
    paramFileds.emplace_back(ParamConstants::PARAM_REMOTE_SERVER);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    paramFileds.emplace_back(ParamConstants::PARAM_LOCAL_PUBLIC_CERT);
    paramFileds.emplace_back(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION);
    paramFileds.emplace_back(ParamConstants::PARAM_SIGN_CODE);
    paramFileds.emplace_back(ParamConstants::PARAM_IN_FORM);
    StaticConstructor();
    std::unordered_set<std::string> paramSet = Params::InitParamField(paramFileds);
    for (auto it = options->begin(); it != options->end(); it++) {
        if (paramSet.find(it->first) != paramSet.end()) {
            signParams.insert(std::make_pair(it->first, options->GetString(it->first)));
        }
    }
    // 参数 -profileSigned 指示profile文件是否已签名，1表示已签名，0表示未签名，默认为1。可选项
    // 如果外部没有指定 -profileSigned 或传空,指定为1
    if (signParams.find(ParamConstants::PARAM_BASIC_PROFILE_SIGNED) == signParams.end()
        || signParams.at(ParamConstants::PARAM_BASIC_PROFILE_SIGNED).empty()) {
        signParams[ParamConstants::PARAM_BASIC_PROFILE_SIGNED] = "1";
    }
    if (!CheckSignCode()) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR, "PARAM_SIGN_CODE Parameter check error");
        return false;
    }
    if (!CheckSignatureAlg()) {
        PrintErrorNumberMsg("COMMAND_PARAM_ERROR", COMMAND_PARAM_ERROR,
                            "PARAM_BASIC_SIGANTURE_ALG Parameter check error");
        return false;
    }
    CheckSignAlignment();
    return true;
}

bool SignProvider::CheckSignCode()
{
    if (signParams.find(ParamConstants::PARAM_SIGN_CODE) == signParams.end()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_SIGN_CODE, ParamConstants::ENABLE_SIGN_CODE));
        return true;
    }
    std::string codeSign = signParams[ParamConstants::PARAM_SIGN_CODE];
    if ((codeSign != ParamConstants::ENABLE_SIGN_CODE) && (codeSign != ParamConstants::DISABLE_SIGN_CODE)) {
        return false;
    }
    return true;
}

bool SignProvider::CheckSignatureAlg()
{
    std::string signAlg = signParams[ParamConstants::PARAM_BASIC_SIGANTURE_ALG];
    // 去除前导空格
    size_t start = signAlg.find_first_not_of(" ");
    if (start != std::string::npos) {
        signAlg = signAlg.substr(start);
    }
    // 去除尾随空格
    size_t end = signAlg.find_last_not_of(" ");
    if (end != std::string::npos) {
        signAlg = signAlg.substr(0, end + 1);
    }
    for (auto it = VALID_SIGN_ALG_NAME.begin(); it != VALID_SIGN_ALG_NAME.end(); it++) {
        if (StringUtils::CaseCompare(*it, signAlg)) {
            return true;
        }
    }
    return false;
}

void SignProvider::CheckSignAlignment()
{
    if (signParams.find(ParamConstants::PARAM_BASIC_ALIGNMENT) == signParams.end()) {
        signParams.insert(std::make_pair(ParamConstants::PARAM_BASIC_ALIGNMENT, ParamConstants::ALIGNMENT));
    }
}

bool SignProvider::CheckStringToint(const std::string& in, int& out)
{
    std::istringstream iss(in);
    if ((iss >> out) && iss.eof()) {
        return true;
    } else {
        SIGNATURE_TOOLS_LOGE("Invalid parameter: %s", in.c_str());
        return false;
    }
}

bool SignProvider::CheckCompatibleVersion()
{
    auto it = signParams.find(ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION);
    if (it == signParams.end()) {
        signParams[ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION] = "9";
        return true;
    }
    const std::string& compatibleApiVersionVal = it->second;
    int compatibleApiVersion;
    return CheckStringToint(compatibleApiVersionVal, compatibleApiVersion);
}

bool SignProvider::OutputSignedFile(RandomAccessFile* outputHap,
                                    long centralDirectoryOffset,
                                    ByteBuffer& signingBlock,
                                    ByteBufferDataSource* centralDirectory,
                                    ByteBuffer& eocdBuffer)
{
    std::shared_ptr<RandomAccessFileOutput> outputHapOut =
        std::make_shared<RandomAccessFileOutput>(outputHap, centralDirectoryOffset);
    if (!outputHapOut->Write(signingBlock)) {
        SIGNATURE_TOOLS_LOGE("output hap file write signingBlock failed");
        return false;
    }
    if (!outputHapOut->Write(centralDirectory->GetByteBuffer())) {
        SIGNATURE_TOOLS_LOGE("output hap file write central directory failed");
        return false;
    }
    if (!outputHapOut->Write(eocdBuffer) != 0) {
        SIGNATURE_TOOLS_LOGE("output hap file write eocd failed");
        return false;
    }
    return true;
}

X509* SignProvider::GetCertificate(const std::string& certificate)const
{
    BIO* in = BIO_new_mem_buf(certificate.data(), certificate.size());
    if (!in) {
        SIGNATURE_TOOLS_LOGE("bio new error");
        return NULL;
    }
    X509* cert = NULL;
    cert = PEM_read_bio_X509(in, NULL, NULL, NULL);
    if (!cert) {
        BIO_free(in);
        SIGNATURE_TOOLS_LOGE("not get cert");
        return NULL;
    }
    BIO_free(in);
    return cert;
}

std::string SignProvider::GetCertificateCN(X509* cert)const
{
    X509_NAME* name = NULL;
    int len = 0;
    std::string ret;
    if (cert == NULL)
        return "";
    name = X509_get_subject_name(cert);
    if (!name) {
        SIGNATURE_TOOLS_LOGE("get subject failed");
        return "";
    }
    len = X509_NAME_get_text_by_NID(name, NID_countryName, NULL, 0);
    if (len <= 0)
        return "";
    ret.resize(len + 1);
    if (X509_NAME_get_text_by_NID(name, NID_countryName, &ret[0], len + 1) != len)
        return "";
    return ret;
}

std::string SignProvider::FindProfileFromOptionalBlocks()const
{
    std::string profile;
    for (const OptionalBlock& optionalBlock : this->optionalBlocks) {
        if (optionalBlock.optionalType == HapUtils::HAP_PROFILE_BLOCK_ID) {
            profile = std::string(optionalBlock.optionalBlockValue.GetBufferPtr(),
                                  optionalBlock.optionalBlockValue.GetCapacity());
        }
    }
    return profile;
}

int SignProvider::CheckProfileValid(STACK_OF(X509)* inputCerts)
{
    std::string profile = FindProfileFromOptionalBlocks();
    std::map<std::string, std::string>::const_iterator ite =
        this->signParams.find(ParamConstants::PARAM_BASIC_PROFILE_SIGNED);
    if (ite == this->signParams.end()) {
        SIGNATURE_TOOLS_LOGE("find PARAM_BASIC_PROFILE_SIGNED failed");
        return CHCKE_PROFILE_ERROR;
    }
    bool isProfileWithoutSign = (ParamConstants::DISABLE_SIGN_CODE == ite->second);
    if (!isProfileWithoutSign) {
        json obj = json::parse(profile, nullptr, false);
        if (!obj.is_discarded() && obj.is_structured()) {
            this->profileContent = profile;
            return 0;
        }
        PKCS7Data p7Data;
        if (p7Data.Parse(profile) < 0)
            return PKCS7_PARSE_ERROR;
        if (p7Data.Verify() < 0) {
            SIGNATURE_TOOLS_LOGE("Verify profile pkcs7 failed! Profile is invalid.");
            return PKCS7_VERIFY_ERROR;
        }
        this->profileContent.clear();
        if (p7Data.GetContent(this->profileContent) < 0) {
            SIGNATURE_TOOLS_LOGE("get content data failed");
            return  NO_CONTENT_ERROR;
        }
    } else {
        this->profileContent = profile;
    }

    ProfileInfo info;
    if (ParseProvision(this->profileContent, info) != PROVISION_OK) {
        SIGNATURE_TOOLS_LOGE("parse provision error");
        return PARSE_PROVISION_ERROR;
    }
    if (CheckProfileInfo(info, inputCerts) < 0) {
        return CHCKE_PROFILE_ERROR;
    }
    return 0;
}

int SignProvider::CheckProfileInfo(const ProfileInfo& info, STACK_OF(X509)* inputCerts)const
{
    X509* certInProfile = NULL;
    if (info.type == ProvisionType::RELEASE) {
        certInProfile = GetCertificate(info.bundleInfo.distributionCertificate);
    } else if (info.type == ProvisionType::DEBUG) {
        certInProfile = GetCertificate(info.bundleInfo.developmentCertificate);
    } else {
        SIGNATURE_TOOLS_LOGE("Unsupported profile type!");
        return NOT_SUPPORT_ERROR;
    }
    if (!sk_X509_num(inputCerts) && !CheckInputCertMatchWithProfile(sk_X509_value(inputCerts, 0),
        certInProfile)) {
        X509_free(certInProfile);
        SIGNATURE_TOOLS_LOGE("input certificates do not match with profile!");
        return MATCH_ERROR;
    }
    std::string cn = GetCertificateCN(certInProfile);
    X509_free(certInProfile);
    SIGNATURE_TOOLS_LOGI("certificate in profile: %s", cn.c_str());
    if (cn.empty()) {
        SIGNATURE_TOOLS_LOGE("Common name of certificate is empty!");
        return CERTIFICATE_ERROR;
    }
    return 0;
}

bool SignProvider::CheckInputCertMatchWithProfile(X509* inputCert, X509* certInProfile)const
{
    return true;
}
} // namespace SignatureTools
} // namespace OHOS