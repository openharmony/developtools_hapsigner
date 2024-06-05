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

#ifndef SIGNERTOOLS_SIGN_PROVIDER_H
#define SIGNERTOOLS_SIGN_PROVIDER_H

#include "options.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/err.h"

#include "signature_tools_errno.h"
#include "hap_utils.h"
#include "hap_verify_result.h"
#include "param_process_util.h"
#include "signing_block_utils.h"
#include "sign_hap.h"
#include "signature_tools_log.h"
#include "signer_config.h"
#include "param_constants.h"
#include "byte_buffer.h"
#include "data_source.h"
#include "file_utils.h"
#include "random_access_file_zip_data_input.h"
#include "random_access_file_zip_data_output.h"
#include "random_access_file.h"
#include "zip_entry_header.h"
#include "zip_signer.h"
#include "zip_data_input.h"
#include "zip_utils.h"
#include "code_signing.h"
#include "byte_buffer_data_source.h"
#include "pkcs7_data.h"
#include "provision_verify.h"

#include <sstream>
#include <set>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <fstream>
#include <filesystem>
#include <unistd.h>
#include <iostream>
#include <utility>
#include <regex>
#include <codecvt>

typedef std::tuple<std::shared_ptr<std::ifstream>, std::shared_ptr<std::ofstream>, std::string> fileIOTuple;
namespace OHOS {
    namespace SignatureTools {
        class SignProvider {
        public:
            bool Sign(Options* options);
			bool SignElf(Options* options);
            bool SignBin(Options* options);
            
        public:
            virtual std::optional<X509_CRL*> GetCrl();
            virtual bool CheckParams(Options* options);
            virtual bool CheckInputCertMatchWithProfile(X509* inputCert, X509* certInProfile)const;
            void StaticConstructor();

            SignProvider() = default;
            virtual ~SignProvider() = default;
        private:

            fileIOTuple PrepareIOStreams(const std::string& inputPath, const std::string& outputPath, bool &ret);

            bool InitZipOutput(std::shared_ptr<RandomAccessFile> outputHap, std::shared_ptr<Zip> zip,
                std::shared_ptr<std::ifstream>, std::shared_ptr<std::ofstream>tmpOutput, std::string path);

            bool PrintErrorLog(const std::string& log, std::string path = "");

            bool InitSigerConfig(SignerConfig& signerConfig, STACK_OF(X509)* publicCerts, Options* options);

            bool DoAfterSign(bool isPathOverlap, std::string tmpOutputFile, std::string inputFilePath);

            bool CreateSignerConfigs(STACK_OF(X509)* certificates, const std::optional<X509_CRL*>& crl,
                Options* options, SignerConfig&);

            bool CopyFileAndAlignment(std::ifstream& input, std::ofstream& tmpOutput, int alignment, Zip& zip);

            bool CheckSignatureAlg();

            static bool CheckStringToint(const std::string& in, int& out);
            int LoadOptionalBlock(const std::string& file, int type);
            bool CheckFile(const std::string& filePath);
            
            int GetX509Certificates(Options* options, STACK_OF(X509)* ret);
            int GetPublicCerts(Options* options, STACK_OF(X509)* ret);
            int GetCertificateChainFromFile(const std::string& certChianFile, STACK_OF(X509)* ret);
            int GetCertListFromFile(const std::string& certsFile, STACK_OF(X509)* ret);
            
            bool AppendCodeSignBlock(SignerConfig &signerConfig, std::string outputFilePath,
                const std::string &suffix, long long centralDirectoryOffset, Zip& zip);
            bool OutputSignedFile(RandomAccessFile* outputHap, long centralDirectoryOffset,
                ByteBuffer& signingBlock, ByteBufferDataSource* centralDirectory, ByteBuffer& eocdBuffer);

        protected:
            void CheckSignAlignment();
            X509* GetCertificate(const std::string& certificate)const;
            std::string GetCertificateCN(X509* cert)const;
            std::string FindProfileFromOptionalBlocks()const;
            //Check profile is valid.A valid profile must include type and
            //certificate which has a non - empty value of DN.
            int CheckProfileValid(STACK_OF(X509)* inputCerts);
            int CheckProfileInfo(const ProvisionInfo& info, STACK_OF(X509)* inputCerts)const;

            bool CheckSignCode();
            int LoadOptionalBlocks();
            bool CheckCompatibleVersion();
            
        protected:
            std::vector<OptionalBlock> optionalBlocks;
            std::map<std::string, std::string> signParams = std::map<std::string, std::string>();

        private:
            static std::vector<std::string> VALID_SIGN_ALG_NAME;
            static std::vector<std::string> PARAMETERS_NEED_ESCAPE;
            static constexpr long long TIMESTAMP = 1230768000000LL;
            static constexpr int COMPRESSION_MODE = 9;
            static constexpr int FOUR_BYTE = 4;
            std::string profileContent;

            struct DataSourceContents {
                DataSource* beforeCentralDir = nullptr;
                ByteBufferDataSource* centralDir = nullptr;
                ByteBufferDataSource* endOfCentralDir = nullptr;
                ByteBuffer cDByteBuffer;
                std::pair<ByteBuffer, long long> eocdPair;
                long long cDOffset = 0LL;

                ~DataSourceContents()
                {
                    delete beforeCentralDir;
                    delete centralDir;
                    delete endOfCentralDir;
                }
            };

        private:
            bool InitDataSourceContents(RandomAccessFile& outputHap, DataSourceContents& dataSrcContents);
        };
    }
}

#endif
