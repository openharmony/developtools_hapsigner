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

package com.ohos.entity;

import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.error.ParamException;

/**
 * ReSignEnterpriseAppParameters.
 *
 * @since 2026/03/31
 */
public class ReSignEnterpriseAppParameters extends SignAppParameters {
    @Override
    public Options toOptions() throws ParamException {
        Options options = new Options();
        if (getMode() == null) {
            throw new ParamException(Options.MODE);
        }
        options.put(Options.MODE, getMode().getValue());

        if (getKeyAlias() == null) {
            throw new ParamException(Options.KEY_ALIAS);
        }
        options.put(Options.KEY_ALIAS, getKeyAlias());

        if (getKeyPwd() != null) {
            options.put(Options.KEY_RIGHTS, getKeyPwd());
        }

        if (getInForm() != null) {
            options.put(Options.IN_FORM, getInForm().getValue());
        }

        if (getInFile() == null) {
            throw new ParamException(Options.IN_FILE);
        }
        options.put(Options.IN_FILE, getInFile());

        if (getSignAlg() == null) {
            throw new ParamException(Options.SIGN_ALG);
        }
        options.put(Options.SIGN_ALG, getSignAlg());

        if (getKeystorePwd() != null) {
            options.put(Options.KEY_STORE_RIGHTS, getKeystorePwd());
        }

        if (getOutFile() == null) {
            throw new ParamException(Options.OUT_FILE);
        }
        options.put(Options.OUT_FILE, getOutFile());

        keyStoreFileToOptions(options);
        appCertFileToOptions(options);
        remoteSignParamToOptions(options);
        return options;
    }
}
