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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Accessor for .modinfo sections used in Linux kernel modules.
 * These sections contain null-terminated key=value pairs.
 *
 * @since 2026/3/5
 */
public class ModInfoSectionAccessor {
    private Section section;

    private List<KeyValuePair> content;

    /**
     * Create a modinfo section accessor.
     *
     * @param section The .modinfo section
     */
    public ModInfoSectionAccessor(Section section) {
        this.section = section;
        this.content = new ArrayList<>();
        processSection();
    }

    /**
     * A key-value pair from the modinfo section.
     */
    public static class KeyValuePair {
        public final String field;

        public final String value;

        public KeyValuePair(String field, String value) {
            this.field = field;
            this.value = value;
        }
    }

    /**
     * Get the number of attributes in the section.
     *
     * @return Number of attributes
     */
    public int getAttributeNum() {
        return content.size();
    }

    /**
     * Get an attribute by index.
     *
     * @param no The attribute index
     * @param outField Output parameter for the field name
     * @param outValue Output parameter for the value
     * @return true if successful
     */
    public boolean getAttribute(int no, StringBuilder outField, StringBuilder outValue) {
        if (no < 0 || no >= content.size()) {
            return false;
        }
        KeyValuePair pair = content.get(no);
        outField.setLength(0);
        outField.append(pair.field);
        outValue.setLength(0);
        outValue.append(pair.value);
        return true;
    }

    /**
     * Get an attribute by field name.
     *
     * @param fieldName The field name to search for
     * @param outValue Output parameter for the value
     * @return true if found
     */
    public boolean getAttribute(String fieldName, StringBuilder outValue) {
        for (KeyValuePair pair : content) {
            if (pair.field.equals(fieldName)) {
                outValue.setLength(0);
                outValue.append(pair.value);
                return true;
            }
        }
        return false;
    }

    /**
     * Add an attribute to the section.
     *
     * @param field The field name
     * @param value The value
     * @return The position where the attribute was added
     */
    public int addAttribute(String field, String value) {
        int currentPosition = 0;

        if (section != null) {
            currentPosition = (int) section.getSize();

            String attribute = field + "=" + value;
            byte[] attributeBytes = (attribute + "\0").getBytes(StandardCharsets.UTF_8);

            section.appendData(attributeBytes);
            content.add(new KeyValuePair(field, value));
        }

        return currentPosition;
    }

    /**
     * Process the section data and parse key=value pairs.
     */
    private void processSection() {
        byte[] data = section.getData();
        if (data == null || data.length == 0) {
            return;
        }

        int i = 0;
        while (i < data.length) {
            // Skip null bytes
            while (i < data.length && data[i] == 0) {
                i++;
            }

            if (i < data.length) {
                // Find the end of the current string
                int start = i;
                while (i < data.length && data[i] != 0) {
                    i++;
                }

                if (i > start) {
                    String info = new String(data, start, i - start, StandardCharsets.UTF_8);
                    int loc = info.indexOf('=');
                    if (loc > 0) {
                        String field = info.substring(0, loc);
                        String value = info.substring(loc + 1);
                        content.add(new KeyValuePair(field, value));
                    }
                }
                i++; // Skip the null terminator
            }
        }
    }

    /**
     * Get all attributes as a list.
     *
     * @return List of key-value pairs
     */
    public List<KeyValuePair> getAllAttributes() {
        return new ArrayList<>(content);
    }
}
