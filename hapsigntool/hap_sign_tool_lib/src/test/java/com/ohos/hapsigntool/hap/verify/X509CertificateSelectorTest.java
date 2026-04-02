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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * X509CertificateSelectorTest.
 *
 * @since 2026/03/31
 */
public class X509CertificateSelectorTest {
    @BeforeAll
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test signer id match
     *
     * @throws Exception if error occurs
     */
    @Test
    public void testSignerIdMatch() throws Exception {
        X509CertificateHolder certHolder = generateX509CertificateHolder();
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = extensionUtils.createSubjectKeyIdentifier(cert.getPublicKey());
        byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();

        SignerId signerId = new SignerId(certHolder.getIssuer(), cert.getSerialNumber(), keyIdentifier);
        X509CertificateSelector hapSignerId = new X509CertificateSelector(signerId);

        assertNotNull(hapSignerId);
        assertTrue(hapSignerId.match(certHolder));

        X500Name difIssuer = new X500Name("CN=Different Issuer");
        SignerId difIssuerSignerId = new SignerId(difIssuer, certHolder.getSerialNumber(), keyIdentifier);
        X509CertificateSelector differentIssuerSelector = new X509CertificateSelector(difIssuerSignerId);
        assertFalse(differentIssuerSelector.match(certHolder));

        byte[] difKeyIdentifier = new byte[keyIdentifier.length];
        SignerId difKeyIdentifierSignerId = new SignerId(null, null, difKeyIdentifier);
        X509CertificateSelector difKeyIdentifierSelector = new X509CertificateSelector(difKeyIdentifierSignerId);
        assertFalse(difKeyIdentifierSelector.match(certHolder));

        BigInteger difSerialNumber = BigInteger.valueOf(System.nanoTime());
        SignerId difSerialNumberSignerId = new SignerId(certHolder.getIssuer(), difSerialNumber, keyIdentifier);
        X509CertificateSelector difSerialNumberSelector = new X509CertificateSelector(difSerialNumberSignerId);
        assertFalse(difSerialNumberSelector.match(certHolder));
    }

    /**
     * Test clone method
     *
     * @throws Exception if error occurs
     */
    @Test
    public void testHapSignerIdClone() throws Exception {
        X509CertificateHolder certHolder = generateX509CertificateHolder();
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = extensionUtils.createSubjectKeyIdentifier(
                certHolder.getSubjectPublicKeyInfo());
        byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
        SignerId signerId = new SignerId(certHolder.getIssuer(), certHolder.getSerialNumber(), keyIdentifier);
        X509CertificateSelector hapSignerId = new X509CertificateSelector(signerId);

        Object cloned = hapSignerId.clone();
        assertNotNull(cloned);
        assertTrue(cloned instanceof X509CertificateSelector);

        X509CertificateSelector clonedHapSignerId = (X509CertificateSelector) cloned;
        assertTrue(clonedHapSignerId.match(certHolder));
    }

    private KeyPair generateTestKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    private X509CertificateHolder generateX509CertificateHolder() throws Exception {
        KeyPair keyPair = generateTestKeyPair();
        X500Name issuer = new X500Name("CN=Test Issuer");
        X500Name subject = new X500Name("CN=Test Subject");
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date notAfter = calendar.getTime();
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());
        return certBuilder.build(signer);
    }
}
