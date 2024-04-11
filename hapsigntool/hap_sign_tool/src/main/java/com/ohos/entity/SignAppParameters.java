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

import com.ohos.hapsigntool.entity.Options;
import com.ohos.hapsigntool.entity.ParamConstants;
import com.ohos.hapsigntool.error.ParamException;

/**
 * SignAppParameters.
 *
 * @since 2024/04/06
 */
public class SignAppParameters implements Parameters {
    private Mode mode;

    private String keyAlias;

    private char[] keyPwd;

    private String appCertFile;

    private String profileFile;

    private ProFileSigned profileSigned = ProFileSigned.SIGNED;

    private InForm inForm = InForm.ZIP;

    private String inFile;

    private String signAlg;

    private String keyStoreFile;

    private char[] keystorePwd;

    private String outFile;

    private SignCode signCode;

    private String userName;

    private String userPwd;

    private String signServer;

    private String signerPlugin;

    private String compatibleVersion;

    private String onlineAuthMode;

    @Override
    public Options toOptions() throws ParamException {
        Options options = new Options();
        if (mode == null) {
            throw new ParamException(Options.MODE);
        }
        options.put(Options.MODE, mode.getValue());
        if (keyAlias == null) {
            throw new ParamException(Options.KEY_ALIAS);
        }
        options.put(Options.KEY_ALIAS, keyAlias);
        if (keyPwd != null) {
            options.put(Options.KEY_RIGHTS, keyPwd);
        }
        if (appCertFile == null) {
            throw new ParamException(Options.APP_CERT_FILE);
        }
        options.put(Options.APP_CERT_FILE, appCertFile);
        if (profileFile == null) {
            throw new ParamException(Options.PROFILE_FILE);
        }
        options.put(Options.PROFILE_FILE, profileFile);
        if (profileSigned != null) {
            options.put(Options.PROFILE_SIGNED, profileSigned.getValue());
        }
        if (inForm != null) {
            options.put(Options.IN_FORM, inForm.getValue());
        }
        if (inFile == null) {
            throw new ParamException(Options.IN_FILE);
        }
        options.put(Options.IN_FILE, inFile);
        if (signAlg == null) {
            throw new ParamException(Options.SIGN_ALG);
        }
        options.put(Options.SIGN_ALG, signAlg);
        if (keyStoreFile == null) {
            throw new ParamException(Options.KEY_STORE_FILE);
        }
        options.put(Options.KEY_STORE_FILE, keyStoreFile);
        if (keystorePwd != null) {
            options.put(Options.KEY_STORE_RIGHTS, keystorePwd);
        }
        if (outFile == null) {
            throw new ParamException(Options.OUT_FILE);
        }
        options.put(Options.OUT_FILE, outFile);
        if (signCode != null) {
            options.put(ParamConstants.PARAM_SIGN_CODE, signCode.getValue());
        }
        if (compatibleVersion != null) {
            options.put("compatibleVersion", compatibleVersion);
        }
        if (mode == Mode.REMOTE_SIGN) {
            if (signServer == null || userPwd == null || userName == null ||
                    signerPlugin == null || onlineAuthMode == null) {
                throw new ParamException("remote sign params failed");
            }
            options.put("signServer", signServer);
            options.put("userPwd", userPwd);
            options.put("username", userName);
            options.put("signerPlugin", signerPlugin);
            options.put("onlineAuthMode", onlineAuthMode);
        }
        return options;
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public char[] getKeyPwd() {
        return keyPwd;
    }

    public void setKeyPwd(char[] keyPwd) {
        this.keyPwd = keyPwd;
    }

    public String getAppCertFile() {
        return appCertFile;
    }

    public void setAppCertFile(String appCertFile) {
        this.appCertFile = appCertFile;
    }

    public String getProfileFile() {
        return profileFile;
    }

    public void setProfileFile(String profileFile) {
        this.profileFile = profileFile;
    }

    public ProFileSigned getProfileSigned() {
        return profileSigned;
    }

    public void setProfileSigned(ProFileSigned profileSigned) {
        this.profileSigned = profileSigned;
    }

    public InForm getInForm() {
        return inForm;
    }

    public void setInForm(InForm inForm) {
        this.inForm = inForm;
    }

    public String getInFile() {
        return inFile;
    }

    public void setInFile(String inFile) {
        this.inFile = inFile;
    }

    public String getSignAlg() {
        return signAlg;
    }

    public void setSignAlg(String signAlg) {
        this.signAlg = signAlg;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public char[] getKeystorePwd() {
        return keystorePwd;
    }

    public void setKeystorePwd(char[] keystorePwd) {
        this.keystorePwd = keystorePwd;
    }

    public String getOutFile() {
        return outFile;
    }

    public void setOutFile(String outFile) {
        this.outFile = outFile;
    }

    public SignCode getSignCode() {
        return signCode;
    }

    public void setSignCode(SignCode signCode) {
        this.signCode = signCode;
    }
}
