#ifndef BRANCH_COVERAGE_H
#define BRANCH_COVERAGE_H
#include "signature_tools_log.h"
#define PLACEHOLDER {}
#define ASSERT_TRUE_PRINTE_RETURN(CONDITION, RETURN_VALUE, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGE(LOG, ##__VA_ARGS__); \
        return RETURN_VALUE; \
    } \
}

#define ASSERT_TRUE_PRINTE(CONDITION, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGE(LOG, ##__VA_ARGS__); \
    } \
}

#define ASSERT_TRUE_PRINTW_RETURN(CONDITION, RETURN_VALUE, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGW(LOG, ##__VA_ARGS__); \
        return RETURN_VALUE; \
    } \
}

#define ASSERT_TRUE_PRINTW(CONDITION, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGW(LOG, ##__VA_ARGS__); \
    } \
}

#define ASSERT_TRUE_PRINTI_RETURN(CONDITION, RETURN_VALUE, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGI(LOG, ##__VA_ARGS__); \
        return RETURN_VALUE; \
    } \
}

#define ASSERT_TRUE_PRINTW(CONDITION, LOG, ...) { \
    if ( (CONDITION) ) { \
        SIGNATURE_TOOLS_LOGW(LOG, ##__VA_ARGS__); \
    } \
}

#define ASSERT_TRUE_RETURN(CONDITION, RETURN_VALUE) { \
    if ( (CONDITION) ) { \
        return RETURN_VALUE; \
    } \
}
#endif