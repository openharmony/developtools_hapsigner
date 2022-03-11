/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

/**
 * Provider function of escape character.
 *
 * @since 2021/12/21
 */
public class EscapeCharacter {
    /**
     * Phase string which is escaped
     * @param src escaped string
     * @return string after unescape.
     */
    public static String unescape(String src) {
        StringBuffer tmp = new StringBuffer();
        tmp.ensureCapacity(src.length());
        int lastPos = 0;
        int pos = 0;
        while (lastPos < src.length()) {
            pos = src.indexOf('%', lastPos);
            if (pos == lastPos) {
                if (src.charAt(pos + 1) == 'u') {
                    char ch = (char) Integer.parseInt(src.substring(pos + 2, pos + 6), 16);
                    tmp.append(ch);
                    lastPos = pos + 6;
                } else {
                    char ch = (char) Integer.parseInt(src.substring(pos + 1, pos + 3), 16);
                    tmp.append(ch);
                    lastPos = pos + 3;
                }
            } else if (pos == -1) {
                tmp.append(src.substring(lastPos));
                lastPos = src.length();
            } else {
                tmp.append(src.substring(lastPos, pos));
                lastPos = pos;
            }
        }
        return tmp.toString();
    }
}
