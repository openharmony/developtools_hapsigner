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

package com.ohos.hapsigntool.utils;

import com.google.gson.Gson;
import com.ohos.hapsigntool.error.CustomException;
import com.ohos.hapsigntool.error.ERROR;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Cert Usage Util.
 *
 * @since 2021/12/28
 */
public final class CertUtils {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LogManager.getLogger(CertUtils.class);

    /**
     * Max length to print certificate string.
     */
    private static final int MAX_LINE_LENGTH = 65;
    /**
     * Length of serial security random number.
     */
    private static final int RANDOM_SERIAL_LENGTH = 32;
    /**
     * number constant.
     */
    private static final int SECOND_INDEX = 2;

    private CertUtils() {
        // Empty constructor
    }

    /**
     * Parse string to key usage.
     *
     * @param keyUsageStr Key usage string
     * @return Key usage
     */
    public static int parseKeyUsage(String keyUsageStr) {
        int keyUsage = 0;
        if (keyUsageStr.contains("digitalSignature")) {
            keyUsage |= KeyUsage.digitalSignature;
        }
        if (keyUsageStr.contains("nonRepudiation")) {
            keyUsage |= KeyUsage.nonRepudiation;
        }
        if (keyUsageStr.contains("keyEncipherment")) {
            keyUsage |= KeyUsage.keyEncipherment;
        }
        if (keyUsageStr.contains("dataEncipherment")) {
            keyUsage |= KeyUsage.dataEncipherment;
        }
        if (keyUsageStr.contains("keyAgreement")) {
            keyUsage |= KeyUsage.keyAgreement;
        }
        if (keyUsageStr.contains("certificateSignature")) {
            keyUsage |= KeyUsage.keyCertSign;
        }
        if (keyUsageStr.contains("crlSignature")) {
            keyUsage |= KeyUsage.cRLSign;
        }
        if (keyUsageStr.contains("encipherOnly")) {
            keyUsage |= KeyUsage.encipherOnly;
        }
        if (keyUsageStr.contains("decipherOnly")) {
            keyUsage |= KeyUsage.decipherOnly;
        }
        return keyUsage;
    }

    /**
     * Parse string to KeyPurposeId[]
     *
     * @param extKeyUsageStr ext key usage string
     * @return KeyPurposeId[]
     */
    public static KeyPurposeId[] parseExtKeyUsage(String extKeyUsageStr) {
        ArrayList<KeyPurposeId> ids = new ArrayList<>();
        if (extKeyUsageStr.contains("clientAuthentication")) {
            ids.add(KeyPurposeId.id_kp_clientAuth);
        }
        if (extKeyUsageStr.contains("serverAuthentication")) {
            ids.add(KeyPurposeId.id_kp_serverAuth);
        }
        if (extKeyUsageStr.contains("codeSignature")) {
            ids.add(KeyPurposeId.id_kp_codeSigning);
        }
        if (extKeyUsageStr.contains("emailProtection")) {
            ids.add(KeyPurposeId.id_kp_emailProtection);
        }
        if (extKeyUsageStr.contains("smartCardLogin")) {
            ids.add(KeyPurposeId.id_kp_smartcardlogon);
        }
        if (extKeyUsageStr.contains("timestamp")) {
            ids.add(KeyPurposeId.id_kp_timeStamping);
        }
        if (extKeyUsageStr.contains("ocspSignature")) {
            ids.add(KeyPurposeId.id_kp_OCSPSigning);
        }
        return ids.toArray(new KeyPurposeId[]{});
    }

    @SuppressWarnings("unchecked")
    public static X500Name buildDN(String nameString) {
        ValidateUtils.throwIfNotMatches(!StringUtils.isEmpty(nameString), ERROR.COMMAND_ERROR, "");

        String gsonStr = nameString.replace(",", "\",\"");
        gsonStr = "{\"" + gsonStr.replace("=", "\":\"") + "\"}";

        X500NameBuilder builder = new X500NameBuilder();
        HashMap<String, String> map = FileUtils.GSON.fromJson(gsonStr, HashMap.class);

        BCStyle x500NameStyle = (BCStyle) BCStyle.INSTANCE;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (StringUtils.isEmpty(entry.getKey()) || StringUtils.isEmpty(entry.getValue())) {
                continue;
            }
            try {
                ASN1ObjectIdentifier oid = x500NameStyle.attrNameToOID(entry.getKey().trim());
                builder.addRDN(oid, entry.getValue());
            } catch (IllegalArgumentException | IndexOutOfBoundsException exception) {
                LOGGER.debug(exception.getMessage(), exception);
                CustomException.throwException(ERROR.COMMAND_ERROR,
                        String.format("Error params near: %s. Reason: %s", nameString, exception.getMessage()));
            }
        }
        return builder.build();
    }

    /**
     * Generate crl.
     *
     * @param crl crl
     * @return X509CRL
     */
    public static X509CRL generateCrl(byte[] crl) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509CRL) factory.generateCRL(new ByteArrayInputStream(crl));
        } catch (CertificateException | CRLException exception) {
            LOGGER.debug(exception.getMessage(), exception);
            CustomException.throwException(ERROR.NOT_SUPPORT_ERROR, exception.getMessage());
        }
        return null;
    }

    /**
     * Convert byte to CSR String.
     *
     * @param csr bytes of CSR
     * @return String
     */
    public static String toCsrTemplate(byte[] csr) {
        return "-----BEGIN NEW CERTIFICATE REQUEST-----\n"
                + java.util.Base64.getMimeEncoder(MAX_LINE_LENGTH, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(csr)
                + "\n-----END NEW CERTIFICATE REQUEST-----\n";
    }

    /**
     * Encoding cert to String.
     *
     * @param certificate Cert to convert to string
     * @return Cert templated string
     * @throws CertificateEncodingException Failed encoding
     */
    public static String generateCertificateInCer(X509Certificate certificate)
            throws CertificateEncodingException {
        return "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(MAX_LINE_LENGTH, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(certificate.getEncoded())
                + "\n" + "-----END CERTIFICATE-----" + "\n";
    }

    /**
     * Random serial.
     *
     * @return Random big integer
     */
    public static BigInteger randomSerial() {
        return new BigInteger(RANDOM_SERIAL_LENGTH, new SecureRandom());
    }

    /**
     * save2Pem.
     *
     * @param certificates certificates to save
     * @param filePath     filePath to save
     */
    public static void save2Pem(List<X509Certificate> certificates, String filePath) {
        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filePath)))) {
            for (X509Certificate certificate : certificates) {
                PemObject object = new PemObject("certificate", certificate.getEncoded());
                pemWriter.writeObject(object);
            }
        } catch (CertificateEncodingException exception) {
            LOGGER.debug(exception.getMessage(), exception);
            CustomException.throwException(ERROR.NOT_SUPPORT_ERROR, exception.getMessage());
        } catch (IOException exception) {
            LOGGER.debug(exception.getMessage(), exception);
            CustomException.throwException(ERROR.WRITE_FILE_ERROR, exception.getMessage());
        }
    }

    /**
     * Convert byte to cert.
     *
     * @param cert Byte from cert file
     * @return Certs
     * @throws CertificateException Convert failed
     */
    @SuppressWarnings("unchecked")
    public static List<X509Certificate> generateCertificates(byte[] cert) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates =
                (List<X509Certificate>) factory.generateCertificates(new ByteArrayInputStream(cert));
        sortCertificateChain(certificates);
        return certificates;
    }

    private static void sortCertificateChain(List<X509Certificate> certificates) {
        if (certificates != null && certificates.size() > 1) {
            int size = certificates.size();
            X500Principal lastSubjectX500Principal = (certificates.get(size - 1)).getSubjectX500Principal();
            X500Principal beforeIssuerX500Principal = (certificates.get(size - SECOND_INDEX)).getIssuerX500Principal();
            if (!lastSubjectX500Principal.equals(beforeIssuerX500Principal)) {
                Collections.reverse(certificates);
            }
        }
    }
}
