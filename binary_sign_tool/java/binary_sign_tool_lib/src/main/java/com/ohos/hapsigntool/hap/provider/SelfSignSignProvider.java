/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.provider;

import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.error.InvalidParamsException;
import com.ohos.hapsigntool.hap.config.SignerConfig;
import com.ohos.hapsigntool.hap.sign.SignElf;
import com.ohos.hapsigntool.utils.LogUtils;

/**
 * Self-sign provider for ELF files
 *
 * @since 2025/01/26
 */
public class SelfSignSignProvider extends SignProvider {
    private static final LogUtils LOGGER = new LogUtils(SelfSignSignProvider.class);

    /**
     * Constructor
     */
    public SelfSignSignProvider() {
        super();
    }

    /**
     * Sign ELF file in self-sign mode
     *
     * @param options parameters for signing
     * @return true if sign successfully
     */
    @Override
    public boolean signElf(Options options) {
        try {
            // Check parameters
            checkParams(options);

            // Create empty signer config for self-sign mode
            SignerConfig signerConfig = new SignerConfig();
            signerConfig.setParameters(this.signParams);
            signerConfig.setOptions(options);

            // Sign ELF in self-sign mode
            if (!SignElf.sign(signerConfig, signParams)) {
                LOGGER.error("[SelfSignSignProvider] Sign elf failed");
                return false;
            }

            LOGGER.info("Self-sign elf success");
            return true;
        } catch (InvalidParamsException e) {
            LOGGER.error("Self-sign elf error: {}", e.getMessage());
            return false;
        }
    }
}
