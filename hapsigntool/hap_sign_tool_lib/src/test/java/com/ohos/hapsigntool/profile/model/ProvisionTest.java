/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with License.
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

package com.ohos.hapsigntool.profile.model;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

/**
 * ProvisionTest.
 *
 * @since 2026/03/31
 */
public class ProvisionTest {
    /**
     * Test enterprise distribution type
     */
    @Test
    public void testIsEnterpriseAppWithEnterprise() {
        assertTrue(Provision.isEnterpriseApp(Provision.ENTERPRISE));
    }

    /**
     * Test enterprise normal distribution type
     */
    @Test
    public void testIsEnterpriseAppWithEnterpriseNormal() {
        assertTrue(Provision.isEnterpriseApp(Provision.ENTERPRISE_NORMAL));
    }

    /**
     * Test enterprise mdm distribution type
     */
    @Test
    public void testIsEnterpriseAppWithEnterpriseMdm() {
        assertTrue(Provision.isEnterpriseApp(Provision.ENTERPRISE_MDM));
    }

    /**
     * Test distribution type null
     */
    @Test
    public void testIsEnterpriseAppWithNull() {
        assertFalse(Provision.isEnterpriseApp(null));
    }

    /**
     * Test distribution type empty
     */
    @Test
    public void testIsEnterpriseAppWithEmpty() {
        assertFalse(Provision.isEnterpriseApp(""));
    }

    /**
     * Test distribution type not enterprise
     */
    @Test
    public void testIsEnterpriseAppWithInvalidType() {
        assertFalse(Provision.isEnterpriseApp("invalid_type"));
    }
}
