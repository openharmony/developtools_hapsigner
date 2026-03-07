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

package com.ohos.elfio;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Accessor for string table sections.
 *
 * @since 2026/3/5
 */
public class StringSectionAccessor {
    private Section section;

    /**
     * Create a string section accessor.
     *
     * @param section The string section
     */
    public StringSectionAccessor(Section section) {
        this.section = section;
    }

    /**
     * Get a string at the specified offset.
     *
     * @param offset Offset in the string table
     * @return The string, or null if offset is invalid
     */
    public String getString(int offset) {
        byte[] data = section.getData();
        if (offset < 0 || offset >= data.length) {
            return null;
        }

        int end = offset;
        while (end < data.length && data[end] != 0) {
            end++;
        }

        return new String(data, offset, end - offset, StandardCharsets.UTF_8);
    }

    /**
     * Add a string to the string table.
     *
     * @param str The string to add
     * @return The offset where the string was added
     */
    public int addString(String str) {
        byte[] strBytes = (str + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] currentData = section.getData();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(currentData, 0, currentData.length);
        int offset = currentData.length;
        baos.write(strBytes, 0, strBytes.length);

        section.setData(baos.toByteArray());
        return offset;
    }

    /**
     * Get all strings in the string table.
     *
     * @return Array of all strings
     */
    public String[] getAllStrings() {
        java.util.List<String> strings = new java.util.ArrayList<>();
        byte[] data = section.getData();

        int offset = 0;
        while (offset < data.length) {
            if (data[offset] == 0) {
                offset++;
                continue;
            }
            String str = getString(offset);
            if (str != null && !str.isEmpty()) {
                strings.add(str);
            }
            offset += str.length() + 1;
        }

        return strings.toArray(new String[0]);
    }
}
