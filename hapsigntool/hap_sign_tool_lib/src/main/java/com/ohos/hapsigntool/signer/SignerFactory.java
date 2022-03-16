/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.signer;

import com.ohos.hapsigntool.api.LocalizationAdapter;

import java.security.KeyPair;

/**
 * Factory pattern to create signer.
 *
 * @since 2021/12/28
 */
public class SignerFactory {
    /**
     * Create a signer.
     *
     * @param adapter Params adapter
     * @return Local signer or remote signer
     */
    public ISigner getSigner(LocalizationAdapter adapter) {
        if (adapter.isRemoteSigner()) {
            return new RemoteSigner(adapter.getOptions());
        } else {
            KeyPair keyPair = adapter.getAliasKey(false);
            adapter.releasePwd();
            return new LocalSigner(keyPair.getPrivate(), adapter.getSignCertChain());
        }
    }
}
