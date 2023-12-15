/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

package com.ohos.hapsigntool.zip;

import java.nio.ByteBuffer;

/**
 * Unsigned Decimal Util
 *
 * @since 2023/12/09
 */
public class UnsignedDecimalUtil {
    /**
     * max unsigned int value
     */
    public static final long MAX_UNSIGNED_INT_VALUE = 0xFFFFFFFFL;

    /**
     * max unsigned int value
     */
    public static final int MAX_UNSIGNED_SHORT_VALUE = 0xFFFF;

    private static final int BIT_SIZE = 8;

    private static final int DOUBLE_BIT_SIZE = 16;

    private static final int TRIPLE_BIT_SIZE = 24;

    /**
     * get unsigned int to long
     *
     * @param bf byteBuffer
     * @return long
     */
    public static long getUnsignedInt(ByteBuffer bf) {
        int value = bf.getInt();
        if (value >= 0) {
            return value;
        }
        return value & MAX_UNSIGNED_INT_VALUE;
    }

    /**
     * get unsigned short to int
     *
     * @param bf byteBuffer
     * @return int
     */
    public static int getUnsignedShort(ByteBuffer bf) {
        short value = bf.getShort();
        if (value >= 0) {
            return value;
        }
        return value & MAX_UNSIGNED_SHORT_VALUE;
    }

    /**
     * set long to unsigned int
     *
     * @param bf byteBuffer
     * @param l long
     */
    public static void setUnsignedInt(ByteBuffer bf, long l) {
        byte[] bytes = new byte[] {
                (byte) (l & 0xFF),
                (byte) ((l >> BIT_SIZE) & 0xFF),
                (byte) ((l >> DOUBLE_BIT_SIZE) & 0xFF),
                (byte) ((l >> TRIPLE_BIT_SIZE) & 0xFF)
        };
        bf.put(bytes);
    }

    /**
     * set int to unsigned short
     *
     * @param bf byteBuffer
     * @param i int
     */
    public static void setUnsignedShort(ByteBuffer bf, int i) {
        byte[] bytes = new byte[] {
                (byte) (i & 0xFF),
                (byte) ((i >> BIT_SIZE) & 0xFF)
        };
        bf.put(bytes);
    }
}
