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
#ifndef SIGNATRUETOOLS_PROFILE_INFO_H
#define SIGNATRUETOOLS_PROFILE_INFO_H

#include <string>
#include <vector>
#include <memory>

#include "export_define.h"

namespace OHOS {
namespace SignatureTools {

enum ProvisionType {
    NONE_PROVISION_TYPE = 0,
    RELEASE = 1,
    DEBUG = 2
};
enum AppDistType {
    NONE_TYPE = 0,
    APP_GALLERY = 1,
    ENTERPRISE = 2,
    OS_INTEGRATION = 3,
    CROWDTESTING = 4,
    ENTERPRISE_NORMAL = 5,
    ENTERPRISE_MDM = 6,
};
struct BundleInfo {
    std::string developerId;
    std::string developmentCertificate;
    std::string distributionCertificate;
    std::string bundleName;
    std::string apl;
    std::string appFeature;
    std::string appIdentifier;
    std::vector<std::string> dataGroupIds;
};
struct Acls {
    std::vector<std::string> allowedAcls;
};
struct Permissions {
    std::vector<std::string> restrictedPermissions;
    std::vector<std::string> restrictedCapabilities;
};
struct DebugInfo {
    std::string deviceIdType;
    std::vector<std::string> deviceIds;
};
struct Validity {
    int64_t notBefore = 0;
    int64_t notAfter = 0;
};
struct Metadata {
    std::string name;
    std::string value;
    std::string resource;
};
struct ProfileInfo {
    DLL_EXPORT ProfileInfo();
    DLL_EXPORT ~ProfileInfo();
    DLL_EXPORT ProfileInfo(const ProfileInfo& info);
    DLL_EXPORT ProfileInfo& operator=(const ProfileInfo& info);
    int32_t versionCode = 0;
    std::string versionName;
    std::string uuid;
    ProvisionType type = NONE_PROVISION_TYPE;
    AppDistType distributionType = NONE_TYPE;
    BundleInfo bundleInfo;
    Acls acls;
    Permissions permissions;
    DebugInfo debugInfo;
    std::string issuer;
    std::string appId;
    std::string fingerprint;
    std::vector<std::string> appPrivilegeCapabilities;
    Validity validity;
    std::vector<Metadata> metadatas;
    int32_t profileBlockLength = 0;
    std::unique_ptr<unsigned char[]> profileBlock;
    std::string appServiceCapabilities;
    std::string organization;
};
} // namespace SignatureTools
} // namespace OHOS
#endif // SIGNATRUETOOLS_PROFILE_INFO_H
