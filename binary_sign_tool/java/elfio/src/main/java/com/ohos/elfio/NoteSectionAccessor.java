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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Accessor for note sections and note segments.
 * Note entries contain: name size, descriptor size, type, name (padded), descriptor (padded).
 *
 * @since 2026/3/5
 */
public class NoteSectionAccessor {
    private Elfio elfio;

    private byte[] data;

    private long dataSize;

    private List<Long> noteStartPositions;

    private ElfioUtils.EndiannessConvertor convertor;

    /**
     * Create a note section accessor for a section.
     *
     * @param elfio The Elfio instance
     * @param section The note section
     */
    public NoteSectionAccessor(Elfio elfio, Section section) {
        this.elfio = elfio;
        this.data = section.getData();
        this.dataSize = section.getSize();
        this.convertor = elfio.getConvertor();
        this.noteStartPositions = new ArrayList<>();
        processSection();
    }

    /**
     * Create a note segment accessor for a segment.
     *
     * @param elfio The Elfio instance
     * @param segment The note segment
     */
    public NoteSectionAccessor(Elfio elfio, Segment segment) {
        this.elfio = elfio;
        this.data = segment.getData();
        this.dataSize = segment.getFileSize();
        this.convertor = elfio.getConvertor();
        this.noteStartPositions = new ArrayList<>();
        processSection();
    }

    /**
     * Get the number of notes in the section/segment.
     *
     * @return Number of notes
     */
    public int getNotesNum() {
        return noteStartPositions.size();
    }

    /**
     * Get a note at the specified index.
     *
     * @param index The note index
     * @return NoteEntry object, or null if index is invalid
     */
    public NoteEntry getNote(int index) {
        if (index < 0 || index >= noteStartPositions.size()) {
            return null;
        }

        long pos = noteStartPositions.get(index);
        return parseNoteAt(pos);
    }

    /**
     * Add a note to the section/segment.
     * Note: This only works for sections, not segments, since segments need special handling.
     *
     * @param type The note type
     * @param name The note name
     * @param desc The descriptor data
     */
    public void addNote(int type, String name, byte[] desc) {
        int align = 4;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        ByteBuffer nameBuf = ByteBuffer.allocate(4);
        nameBuf.order(convertor.getByteOrder());
        int nameLen = name.length() + 1; // Include null terminator
        nameBuf.putInt(nameLen);
        buffer.write(nameBuf.array(), 0, 4);

        ByteBuffer descBuf = ByteBuffer.allocate(4);
        descBuf.order(convertor.getByteOrder());
        int descSize = (desc != null) ? desc.length : 0;
        descBuf.putInt(descSize);
        buffer.write(descBuf.array(), 0 ,4);

        ByteBuffer typeBuf = ByteBuffer.allocate(4);
        typeBuf.order(convertor.getByteOrder());
        typeBuf.putInt(type);
        buffer.write(typeBuf.array(), 0, 4);

        // Write name with padding
        try {
            buffer.write(name.getBytes(StandardCharsets.UTF_8));
            buffer.write(0); // Null terminator
            int namePadding = ((nameLen + align - 1) / align) * align - nameLen;
            for (int i = 0; i < namePadding; i++) {
                buffer.write(0);
            }

            // Write descriptor with padding
            if (desc != null && descSize > 0) {
                buffer.write(desc);
                int descPadding = ((descSize + align - 1) / align) * align - descSize;
                for (int i = 0; i < descPadding; i++) {
                    buffer.write(0);
                }
            }
        } catch (IOException e) {
            // Should not happen with ByteArrayOutputStream
        }

        noteStartPositions.add(dataSize);
        appendData(buffer.toByteArray());
    }

    /**
     * Process the section/segment to find all note entry positions.
     */
    private void processSection() {
        noteStartPositions.clear();

        if (data == null || dataSize == 0) {
            return;
        }

        int align = 4;
        long current = 0L;

        while (current + 3 * align <= dataSize) {
            // Read namesz and descsz
            ByteBuffer nameBuf = ByteBuffer.wrap(data, (int) current, 4);
            nameBuf.order(convertor.getByteOrder());
            int namesz = nameBuf.getInt();

            ByteBuffer descBuf = ByteBuffer.wrap(data, (int) current + 4, 4);
            descBuf.order(convertor.getByteOrder());
            int descsz = descBuf.getInt();

            if (namesz < 0 || descsz < 0 || namesz > dataSize || descsz > dataSize) {
                break;
            }

            long advance = 3 * 4L + ((namesz + align - 1) / align) * align + ((descsz + align - 1) / align) * align;

            if (current + advance <= dataSize) {
                noteStartPositions.add(current);
                current += advance;
            } else {
                break;
            }
        }
    }

    /**
     * Parse a note entry at the specified position.
     */
    private NoteEntry parseNoteAt(long pos) {
        int align = 4;

        if (pos + 3 * align > dataSize) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, (int) pos, (int) (dataSize - pos));
        buffer.order(convertor.getByteOrder());

        int namesz = buffer.getInt();
        int descsz = buffer.getInt();
        int type = buffer.getInt();

        if (namesz < 1 || namesz > dataSize || (pos + namesz + descsz) > dataSize) {
            return null;
        }

        // Extract name
        StringBuilder nameBuilder = new StringBuilder();
        for (int i = 0; i < namesz - 1 && buffer.hasRemaining(); i++) {
            nameBuilder.append((char) buffer.get());
        }

        // Skip padding after name
        int namePadding = ((namesz + align - 1) / align) * align - namesz;
        buffer.position(buffer.position() + namePadding);

        // Extract descriptor
        byte[] desc = null;
        if (descsz > 0) {
            desc = new byte[descsz];
            buffer.get(desc);
            // Skip padding after descriptor is automatic when parsing next note
        }

        return new NoteEntry(type, nameBuilder.toString(), desc, namesz, descsz);
    }

    /**
     * Append data to the backing store.
     * This is a simplified implementation - in a real scenario, you'd need
     * to update the actual section or segment data.
     */
    private void appendData(byte[] newData) {
        // This is a placeholder - actual implementation would need to
        // modify the Section or Segment that owns this data
        byte[] newDataArray = new byte[data.length + newData.length];
        System.arraycopy(data, 0, newDataArray, 0, data.length);
        System.arraycopy(newData, 0, newDataArray, data.length, newData.length);
        data = newDataArray;
        dataSize = data.length;
    }

    /**
     * Note entry class.
     */
    public static class NoteEntry {
        public final int type;

        public final String name;

        public final byte[] descriptor;

        public final int nameSize;

        public final int descriptorSize;

        public NoteEntry(int type, String name, byte[] descriptor, int nameSize, int descriptorSize) {
            this.type = type;
            this.name = name;
            this.descriptor = descriptor;
            this.nameSize = nameSize;
            this.descriptorSize = descriptorSize;
        }

        /**
         * Get the descriptor as a string (if it's text data).
         *
         * @return Descriptor as string, or empty string if no descriptor
         */
        public String getDescriptorAsString() {
            if (descriptor == null || descriptor.length == 0) {
                return "";
            }
            return new String(descriptor, StandardCharsets.UTF_8);
        }
    }
}
