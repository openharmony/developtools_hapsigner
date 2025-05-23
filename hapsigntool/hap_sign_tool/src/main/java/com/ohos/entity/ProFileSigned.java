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

package com.ohos.entity;

/**
 * SignCode.
 *
 * @since 2024/04/09
 */
public enum ProFileSigned {
    SIGNED("1"),
    UNSIGNED("0");

    private final String value;

    ProFileSigned(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
