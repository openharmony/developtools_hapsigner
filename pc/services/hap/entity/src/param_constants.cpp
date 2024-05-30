#include "param_constants.h"
namespace OHOS {
    namespace SignatureTools {
        const std::string ParamConstants::HAP_SIG_SCHEME_V256_DIGEST_ALGORITHM = "SHA-256";
        const std::string ParamConstants::HAP_SIG_SCHEME_V384_DIGEST_ALGORITHM = "SHA-384";
        const std::string ParamConstants::HAP_SIG_SCHEME_V512_DIGEST_ALGORITHM = "SHA-512";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA256_ECDSA = "SHA256withECDSA";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA384_ECDSA = "SHA384withECDSA";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA512_ECDSA = "SHA512withECDSA";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA256_RSA = "SHA256withRSA";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA384_RSA = "SHA384withRSA";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA256_RSA_PSS = "SHA256withRSA/PSS";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA384_RSA_PSS = "SHA384withRSA/PSS";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA512_RSA_PSS = "SHA512withRSA/PSS";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA256_RSA_MGF1 = "SHA256withRSAANDMGF1";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA384_RSA_MGF1 = "SHA384withRSAANDMGF1";
        const std::string ParamConstants::HAP_SIG_ALGORITHM_SHA512_RSA_MGF1 = "SHA512withRSAANDMGF1";
        const std::string ParamConstants::ALIGNMENT = "4";
        const std::string ParamConstants::PARAM_SIGN_MODE = "mode";
        const std::string ParamConstants::PARAM_BASIC_CRL = "crl";
        const std::string ParamConstants::PARAM_BASIC_PROPERTY = "property";
        const std::string ParamConstants::PARAM_BASIC_PROFILE = "profileFile";
        const std::string ParamConstants::PARAM_PROFILE_JSON_CONTENT = "profileContent";
        const std::string ParamConstants::PARAM_BASIC_PROOF = "proof";
        const std::string ParamConstants::PARAM_BASIC_ALIGNMENT = "a";
        const std::string ParamConstants::PARAM_BASIC_PRIVATE_KEY = "keyAlias";
        const std::string ParamConstants::PARAM_BASIC_INPUT_FILE = "inFile";
        const std::string ParamConstants::PARAM_BASIC_OUTPUT_FILE = "outFile";
        const std::string ParamConstants::PARAM_BASIC_SIGANTURE_ALG = "signAlg";
        const std::string ParamConstants::PARAM_BASIC_PROFILE_SIGNED = "profileSigned";
        const std::string ParamConstants::PARAM_BASIC_COMPATIBLE_VERSION = "compatibleVersion";
        const std::string ParamConstants::PARAM_REMOTE_SERVER = "signServer";
        const std::string ParamConstants::PARAM_REMOTE_USERNAME = "username";
        const std::string ParamConstants::PARAM_REMOTE_CODE = "password";
        const std::string ParamConstants::PARAM_LOCAL_JKS_KEYSTORE = "keystoreFile";
        const std::string ParamConstants::PARAM_LOCAL_JKS_KEYSTORE_CODE = "keystorePwd";
        const std::string ParamConstants::PARAM_LOCAL_JKS_KEYALIAS_CODE = "keyPwd";
        const std::string ParamConstants::PARAM_LOCAL_PUBLIC_CERT = "appCertFile";
        const std::string ParamConstants::PARAM_VERIFY_CERTCHAIN_FILE = "outCertChain";
        const std::string ParamConstants::PARAM_VERIFY_PROFILE_FILE = "outProfile";
        const std::string ParamConstants::PARAM_VERIFY_PROOF_FILE = "outproof";
        const std::string ParamConstants::PARAM_VERIFY_PROPERTY_FILE = "outproperty";
        const std::string ParamConstants::PARAM_RESIGN_CONFIG_FILE = "resignconfig";
        const std::string ParamConstants::PARAM_IN_FORM = "inForm";
        const std::string ParamConstants::PARAM_SIGN_CODE = "signCode";
        const std::string ParamConstants::DISABLE_SIGN_CODE = "0";
        const std::string ParamConstants::ENABLE_SIGN_CODE = "1";
    }
}