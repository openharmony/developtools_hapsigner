/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.hap.entity;

/**
 * Define class of hap signature block types
 */
public class SignatureBlockTypes {
    /**
     * type-value of hap signature block
     */
    public static final char SIGNATURE_BLOCK = 0;

    /**
     * type-value of unsigned profile
     */
    public static final char PROFILE_NOSIGNED_BLOCK = 1;

    /**
     * type-value of signed profile
     */
    public static final char PROFILE_SIGNED_BLOCK = 2;

    /**
     * type-value of key rotation block
     */
    public static final char KEY_ROTATION_BLOCK = 3;
}