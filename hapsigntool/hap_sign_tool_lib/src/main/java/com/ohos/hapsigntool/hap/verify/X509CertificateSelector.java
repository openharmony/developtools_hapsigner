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

package com.ohos.hapsigntool.hap.verify;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.util.Selector;

/**
 * Class used to verify hap-file with signature
 *
 * @since 2026/3/28
 */
public class X509CertificateSelector implements Selector<X509CertificateHolder> {
    private final SignerId signerId;

    public X509CertificateSelector(SignerId signerId) {
        this.signerId = signerId;
    }

    @Override
    public boolean match(X509CertificateHolder x509CertificateHolder) {
        return this.signerId.match(x509CertificateHolder);
    }

    @Override
    public Object clone() {
        if (this.signerId == null) {
            try {
                return super.clone();
            } catch (CloneNotSupportedException e) {
                return new Object();
            }
        }
        return new X509CertificateSelector(this.signerId);
    }
}
