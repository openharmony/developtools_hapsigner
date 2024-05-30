#ifndef OHOS_INDUSTRIAL_BUS_LOG_H
#define OHOS_INDUSTRIAL_BUS_LOG_H
#include <stdio.h>
#include <iostream>
#include <time.h>
#include "hilog/log.h"
#include "signature_tools_errno.h"
namespace OHOS {
    namespace SignatureTools {
        static constexpr OHOS::HiviewDFX::HiLogLabel SIGNATURE_MGR_LABEL = { LOG_CORE, LOG_DOMAIN, "SignatureTools" };

#define SIGNATURE_LOG(level, fmt, ...) \
    OHOS::HiviewDFX::HiLog::level(SIGNATURE_MGR_LABEL, \
                                 "%{public}s:[%{public}s:%{public}d]" fmt, \
                                 SIGNATURE_LOG_TAG, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define SIGNATURE_TOOLS_LOGF(fmt, ...) SIGNATURE_LOG(Fatal, fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGE(fmt, ...) SIGNATURE_LOG(Error, fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGW(fmt, ...) SIGNATURE_LOG(Warn, fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGI(fmt, ...) SIGNATURE_LOG(Info, fmt, ##__VA_ARGS__)
#define SIGNATURE_TOOLS_LOGD(fmt, ...) SIGNATURE_LOG(Debug, fmt, ##__VA_ARGS__)

#define CMD_ERROR_MSG(command, code, details) \
    do { \
        time_t now = time(0);\
        char timebuffer[100];\
        strftime(timebuffer, sizeof(timebuffer), "%m-%d %H:%M:%S", localtime(&now));\
        std::cerr << timebuffer <<" ERROR - " << command << ", code: " \
                    << code << ". Details: " << details << std::endl; \
    } while(0)
#define CMD_MSG(content) \
    do { \
        time_t now = time(0);\
        char timebuffer[100];\
        strftime(timebuffer, sizeof(timebuffer), "%m-%d %H:%M:%S", localtime(&now));\
        std::cout << timebuffer << " INFO  - " << content << std::endl; \
    } while(0)

    } // namespace SignatureTools
} // namespace OHOS


#endif // OHOS_INDUSTRIAL_BUS_LHOS_INDUSTRIAL_BUS_LBUS_L