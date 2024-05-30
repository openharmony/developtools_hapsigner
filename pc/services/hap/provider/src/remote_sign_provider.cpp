#include "remote_sign_provider.h"


namespace OHOS {
    namespace SignatureTools {

        bool RemoteSignProvider::CheckParams(Options* options)
        {
            if (!SignProvider::CheckParams(options)) {
                printf("Parameter check failed !\n");
                return false;
            }

            return true;
        }

    }
}