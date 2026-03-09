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

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for dumping ELF file information in a readable format.
 * Similar to the 'readelf' command.
 *
 * @since 2026/3/5
 */
public class ElfioDump {
    private static final Map<Byte, String> OS_ABI_NAMES = createOsAbiNames();

    private static final Map<Long, String> DYNAMIC_TAG_NAMES = createDynamicTagNames();

    private static Map<Byte, String> createOsAbiNames() {
        Map<Byte, String> names = new HashMap<>();
        names.put((byte) 0, "UNIX System V");
        names.put((byte) 1, "HP-UX");
        names.put((byte) 2, "NetBSD");
        names.put((byte) 3, "Linux");
        names.put((byte) 4, "GNU Hurd");
        names.put((byte) 5, "Solaris");
        names.put((byte) 6, "AIX");
        names.put((byte) 7, "IRIX");
        names.put((byte) 8, "FreeBSD");
        names.put((byte) 9, "Tru64");
        names.put((byte) 10, "Novell Modesto");
        names.put((byte) 11, "OpenBSD");
        names.put((byte) 12, "OpenVMS");
        names.put((byte) 13, "NonStop Kernel");
        names.put((byte) 14, "AROS");
        names.put((byte) 15, "FenixOS");
        names.put((byte) 16, "CloudABI");
        names.put((byte) 17, "OpenVOS");
        names.put((byte) 64, "ARM");
        names.put((byte) 97, "Standalone");
        return names;
    }

    private static Map<Long, String> createDynamicTagNames() {
        Map<Long, String> names = new HashMap<>();
        names.put(0L, "NULL");
        names.put(1L, "NEEDED");
        names.put(2L, "PLTRELSZ");
        names.put(3L, "PLTGOT");
        names.put(4L, "HASH");
        names.put(5L, "STRTAB");
        names.put(6L, "SYMTAB");
        names.put(7L, "RELA");
        names.put(8L, "RELASZ");
        names.put(9L, "RELAENT");
        names.put(10L, "STRSZ");
        names.put(11L, "SYMENT");
        names.put(12L, "INIT");
        names.put(13L, "FINI");
        names.put(14L, "SONAME");
        names.put(15L, "RPATH");
        names.put(16L, "SYMBOLIC");
        names.put(17L, "REL");
        names.put(18L, "RELSZ");
        names.put(19L, "RELENT");
        names.put(20L, "PLTREL");
        names.put(21L, "DEBUG");
        names.put(22L, "TEXTREL");
        names.put(23L, "JMPREL");
        names.put(24L, "BIND_NOW");
        names.put(25L, "INIT_ARRAY");
        names.put(26L, "FINI_ARRAY");
        names.put(27L, "INIT_ARRAYSZ");
        names.put(28L, "FINI_ARRAYSZ");
        names.put(29L, "RUNPATH");
        names.put(30L, "FLAGS");
        names.put(32L, "PREINIT_ARRAY");
        names.put(33L, "PREINIT_ARRAYSZ");
        names.put(0x6ffffef5L, "GNU_HASH");
        names.put(0x6ffffff0L, "GNU_VERSYM");
        names.put(0x6ffffff9L, "GNU_RELRO");
        names.put(0x6ffffffaL, "GNU_CONFLICT");
        return names;
    }

    /**
     * Dump ELF header information.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpHeader(PrintStream out, Elfio reader) {
        if (reader.getHeaderSize() == 0) {
            return;
        }

        out.println("ELF Header:");
        out.println("  Class:                             " + strClass(reader.getElfClass()));
        out.println("  Encoding:                          " + strEndian(reader.getEncoding()));
        out.println("  ELF Version:                       " + strVersion(reader.getElfVersion()));
        out.println("  OS/ABI:                            " + strOsAbi(reader.getOsAbi()));
        out.println("  ABI Version:                       " + reader.getAbiVersion());
        out.println("  Type:                              " + strType(reader.getType()));
        out.println("  Machine:                           " + strMachine(reader.getMachine()));
        out.println("  Version:                           " + strVersion((byte) reader.getVersion()));
        out.println("  Entry:                             0x" + Long.toHexString(reader.getEntry()));
        out.println("  Flags:                             0x" + Long.toHexString(reader.getFlags()));
        out.println();
    }

    /**
     * Dump section headers.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpSectionHeaders(PrintStream out, Elfio reader) {
        int n = reader.getSectionsCount();

        if (n == 0) {
            return;
        }

        out.println("Section Headers:");

        if (reader.getElfClass() == ElfTypes.ELFCLASS32) {
            out.println("  [Nr] Type              Addr     Size     ES  Flg Lk   Inf  Al  Name");
        } else {
            out.println("  [Nr] Type              Addr               Size");
            out.println("       Offset              ES     Lk     Inf    Al      Name");
        }

        for (int i = 0; i < n; i++) {
            Section sec = reader.getSection(i);
            if (sec != null) {
                dumpSectionHeader(out, i, sec, reader.getElfClass());
            }
        }

        out.println("Key to Flags:");
        out.println("  W (write), A (alloc), X (execute), M (merge), S (strings)");
        out.println("  I (info), L (link order), O (extra OS processing required)");
        out.println("  G (group), T (TLS), C (compressed), E (exclude)");
        out.println();
    }

    /**
     * Dump a single section header.
     */
    private static void dumpSectionHeader(PrintStream out, int no, Section sec, byte elfClass) {
        if (elfClass == ElfTypes.ELFCLASS32) {
            out.printf("[%2d] %-17s 0x%08X 0x%08X %2d  %s %2d %3d  %2d  %s%n", no, strSectionType(sec.getType()),
                sec.getAddress(), sec.getSize(), sec.getEntSize(), sectionFlags(sec.getFlags()), sec.getLink(),
                sec.getInfo(), (int) sec.getAddrAlign(), sec.getName());
        } else {
            out.printf("[%2d] %-17s 0x%016X 0x%016X%n", no, strSectionType(sec.getType()), sec.getAddress(),
                sec.getSize());
            out.printf("     0x%016X %-6d %-6d %-6d %-6d %s%n", sec.getOffset(), sec.getEntSize(), sec.getLink(),
                sec.getInfo(), (int) sec.getAddrAlign(), sec.getName());
        }
    }

    /**
     * Dump segment headers.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpSegmentHeaders(PrintStream out, Elfio reader) {
        int n = reader.getSegmentsCount();
        if (n == 0) {
            return;
        }

        out.println("Program Headers:");

        if (reader.getElfClass() == ElfTypes.ELFCLASS32) {
            out.println("  [Nr] Type           VirtAddr PhysAddr FileSize MemSize  Flags    Align");
        } else {
            out.println("  [Nr] Type           Offset             VirtAddr           PhysAddr");
            out.println("                       FileSize           MemSize            Flags  Align");
        }

        for (int i = 0; i < n; i++) {
            Segment seg = reader.getSegment(i);
            if (seg != null) {
                dumpSegmentHeader(out, i, seg, reader.getElfClass());
            }
        }
        out.println();
    }

    /**
     * Dump a single segment header.
     */
    private static void dumpSegmentHeader(PrintStream out, int no, Segment seg, byte elfClass) {
        if (elfClass == ElfTypes.ELFCLASS32) {
            out.printf("[%2d] %-14s 0x%08X 0x%08X 0x%08X 0x%08X %s 0x%X%n", no, strSegmentType(seg.getType()),
                seg.getVirtualAddress(), seg.getPhysicalAddress(), seg.getFileSize(), seg.getMemorySize(),
                segmentFlags(seg.getFlags()), seg.getAlign());
        } else {
            out.printf("[%2d] %-14s 0x%016X 0x%016X%n", no, strSegmentType(seg.getType()), seg.getOffset(),
                seg.getVirtualAddress());
            out.printf("                     0x%016X 0x%016X  %s   0x%X%n", seg.getPhysicalAddress(), seg.getFileSize(),
                seg.getMemorySize(), segmentFlags(seg.getFlags()), seg.getAlign());
        }
    }

    /**
     * Dump symbol tables.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpSymbolTables(PrintStream out, Elfio reader) {
        for (int i = 0; i < reader.getSectionsCount(); i++) {
            Section sec = reader.getSection(i);
            if (sec != null && (sec.getType() == ElfTypes.SHT_SYMTAB || sec.getType() == ElfTypes.SHT_DYNSYM)) {
                SymbolSectionAccessor symbols = new SymbolSectionAccessor(reader, sec);
                int symNo = symbols.getSymbolsNum();

                if (symNo == 0) {
                    continue;
                }

                Section linkSection = reader.getSection(sec.getLink());
                out.println("Symbol table '" + sec.getName() + "'");

                if (reader.getElfClass() == ElfTypes.ELFCLASS32) {
                    out.println("  [Nr] Value      Size      Type    Bind      Sect Name");
                } else {
                    out.println("  [Nr] Value                Size                Type    Bind      Sect");
                    out.println("       Name");
                }

                for (int j = 0; j < symNo; j++) {
                    SymbolSectionAccessor.Symbol sym = symbols.getSymbol(j, linkSection);
                    if (sym != null) {
                        dumpSymbol(out, j, sym, reader.getElfClass());
                    }
                }
                out.println();
            }
        }
    }

    /**
     * Dump a single symbol.
     */
    private static void dumpSymbol(PrintStream out, int no, SymbolSectionAccessor.Symbol sym, byte elfClass) {
        if (elfClass == ElfTypes.ELFCLASS32) {
            out.printf("[%2d] 0x%08X 0x%08X %-7s %-8s %5d %s%n", no, sym.value, sym.size, strSymbolType(sym.getType()),
                strSymbolBind(sym.getBind()), sym.sectionIndex, sym.nameStr);
        } else {
            out.printf("[%2d] 0x%016X 0x%016X %-7s %-8s %5d%n", no, sym.value, sym.size, strSymbolType(sym.getType()),
                strSymbolBind(sym.getBind()), sym.sectionIndex);
            out.printf("     %s%n", sym.nameStr);
        }
    }

    /**
     * Dump dynamic tags.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpDynamicTags(PrintStream out, Elfio reader) {
        for (int i = 0; i < reader.getSectionsCount(); i++) {
            Section sec = reader.getSection(i);
            if (sec != null && sec.getType() == ElfTypes.SHT_DYNAMIC) {
                DynamicSectionAccessor dynamic = new DynamicSectionAccessor(reader, sec);
                int dynNo = dynamic.getEntriesNum();

                if (dynNo == 0) {
                    continue;
                }

                out.println("Dynamic section '" + sec.getName() + "'");
                out.println("  [Nr] Tag               Name/Value");

                for (int j = 0; j < dynNo; j++) {
                    DynamicSectionAccessor.DynamicEntry entry = dynamic.getEntry(j);
                    if (entry != null) {
                        out.printf("  [%2d] %-16s ", j, strDynamicTag(entry.tag));

                        // Check if it's a string tag
                        Section strSection = reader.getSection(sec.getLink());
                        if (strSection != null && isStringTag(entry.tag)) {
                            StringSectionAccessor strAccessor = new StringSectionAccessor(strSection);
                            String str = strAccessor.getString((int) entry.val);
                            out.println(str);
                        } else {
                            out.println("0x" + Long.toHexString(entry.val));
                        }

                        if (entry.tag == ElfTypes.DT_NULL) {
                            break;
                        }
                    }
                }
                out.println();
            }
        }
    }

    /**
     * Dump notes.
     *
     * @param out Output stream
     * @param reader Elfio instance
     */
    public static void dumpNotes(PrintStream out, Elfio reader) {
        dumpNoteSections(out, reader);
        dumpNoteSegments(out, reader);
    }

    private static void dumpNoteSections(PrintStream out, Elfio reader) {
        for (int i = 0; i < reader.getSectionsCount(); i++) {
            Section sec = reader.getSection(i);
            if (sec == null || sec.getType() != ElfTypes.SHT_NOTE) {
                continue;
            }
            NoteSectionAccessor notes = new NoteSectionAccessor(reader, sec);
            if (notes.getNotesNum() == 0) {
                continue;
            }
            out.println("Note section '" + sec.getName() + "'");
            dumpNotesFromAccessor(out, notes, true);
            out.println();
        }
    }

    private static void dumpNoteSegments(PrintStream out, Elfio reader) {
        for (int i = 0; i < reader.getSegmentsCount(); i++) {
            Segment seg = reader.getSegment(i);
            if (seg == null || seg.getType() != ElfTypes.PT_NOTE) {
                continue;
            }
            NoteSectionAccessor notes = new NoteSectionAccessor(reader, seg);
            if (notes.getNotesNum() == 0) {
                continue;
            }
            out.println("Note segment " + i);
            dumpNotesFromAccessor(out, notes, false);
            out.println();
        }
    }

    private static void dumpNotesFromAccessor(PrintStream out, NoteSectionAccessor notes, boolean includeDescriptor) {
        out.println("  No  Name          Data Size  Description");
        int noNotes = notes.getNotesNum();
        for (int j = 0; j < noNotes; j++) {
            NoteSectionAccessor.NoteEntry note = notes.getNote(j);
            if (note == null) {
                continue;
            }
            out.printf("  [%2d] %-12s 0x%08X  ", j, note.name, note.descriptorSize);
            String desc = noteTypeToString(note.name, note.type);
            out.println(desc.isEmpty() ? "0x" + Integer.toHexString(note.type) : desc);
            if (includeDescriptor) {
                printNoteDescriptor(out, note.descriptor);
            }
        }
    }

    private static void printNoteDescriptor(PrintStream out, byte[] descriptor) {
        if (descriptor == null || descriptor.length == 0) {
            return;
        }
        out.print("       ");
        int displayLen = Math.min(descriptor.length, 16);
        for (int k = 0; k < displayLen; k++) {
            out.printf("%02X ", descriptor[k] & 0xFF);
        }
        if (descriptor.length > 16) {
            out.print("...");
        }
        out.println();
    }

    /**
     * Convert note type to string.
     */
    private static String noteTypeToString(String name, int type) {
        if ("GNU".equals(name)) {
            switch (type) {
                case 1:
                    return "NT_GNU_ABI_TAG";
                case 2:
                    return "NT_GNU_HWCAP";
                case 3:
                    return "NT_GNU_BUILD_ID";
                case 4:
                    return "NT_GNU_GOLD_VERSION";
                case 5:
                    return "NT_GNU_PROPERTY_TYPE_0";
                default:
                    return "";
            }
        } else if ("CORE".equals(name) || "LINUX".equals(name)) {
            switch (type) {
                case 1:
                    return "NT_PRSTATUS";
                case 2:
                    return "NT_FPREGSET";
                case 3:
                    return "NT_PRPSINFO";
                case 4:
                    return "NT_TASKSTRUCT";
                case 6:
                    return "NT_AUXV";
                default:
                    return "";
            }
        }
        return "";
    }

    // Helper methods for converting enums to strings

    private static boolean isStringTag(long tag) {
        return tag == ElfTypes.DT_NEEDED || tag == ElfTypes.DT_SONAME || tag == ElfTypes.DT_RPATH
            || tag == ElfTypes.DT_RUNPATH;
    }

    private static String strClass(byte cls) {
        switch (cls) {
            case ElfTypes.ELFCLASS32:
                return "ELF32";
            case ElfTypes.ELFCLASS64:
                return "ELF64";
            default:
                return "Unknown (" + cls + ")";
        }
    }

    private static String strEndian(byte enc) {
        switch (enc) {
            case ElfTypes.ELFDATA2LSB:
                return "Little endian";
            case ElfTypes.ELFDATA2MSB:
                return "Big endian";
            default:
                return "Unknown (" + enc + ")";
        }
    }

    private static String strVersion(byte ver) {
        switch (ver) {
            case 0:
                return "None";
            case 1:
                return "Current";
            default:
                return "0x" + Integer.toHexString(ver);
        }
    }

    private static String strOsAbi(byte os) {
        return OS_ABI_NAMES.getOrDefault(os, "0x" + Integer.toHexString(os));
    }

    private static String strType(short type) {
        switch (type) {
            case 0:
                return "No file type";
            case 1:
                return "Relocatable file";
            case 2:
                return "Executable file";
            case 3:
                return "Shared object file";
            case 4:
                return "Core file";
            default:
                return "0x" + Integer.toHexString(type);
        }
    }

    private static String strMachine(short machine) {
        // Common machines only
        switch (machine) {
            case 0:
                return "No machine";
            case 3:
                return "Intel 80386";
            case 8:
                return "MIPS I Architecture";
            case 20:
                return "PowerPC";
            case 21:
                return "64-bit PowerPC";
            case 22:
                return "IBM S/390";
            case 40:
                return "ARM";
            case 50:
                return "Intel IA-64";
            case 62:
                return "Advanced Micro Devices X86-64";
            case 183:
                return "AArch64";
            case 243:
                return "RISC-V";
            default:
                return "0x" + Integer.toHexString(machine);
        }
    }

    private static String strSectionType(int type) {
        switch (type) {
            case 0:
                return "NULL";
            case 1:
                return "PROGBITS";
            case 2:
                return "SYMTAB";
            case 3:
                return "STRTAB";
            case 4:
                return "RELA";
            case 5:
                return "HASH";
            case 6:
                return "DYNAMIC";
            case 7:
                return "NOTE";
            case 8:
                return "NOBITS";
            case 9:
                return "REL";
            case 11:
                return "SYMTAB_SHNDX";
            case 0x6ffffff6:
                return "GNU_HASH";
            case 0x6ffffffd:
                return "GNU_VERSYM";
            case 0x6ffffffe:
                return "GNU_VERNEED";
            case 0x6fffffff:
                return "GNU_VERDEF";
            default:
                return "0x" + Integer.toHexString(type);
        }
    }

    private static String sectionFlags(long flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x1) != 0) {
            sb.append("W");
        } else {
            sb.append(" ");
        }
        if ((flags & 0x2) != 0) {
            sb.append("A");
        } else {
            sb.append(" ");
        }
        if ((flags & 0x4) != 0) {
            sb.append("X");
        } else {
            sb.append(" ");
        }
        if ((flags & 0x10) != 0) {
            sb.append("M");
        }
        if ((flags & 0x20) != 0) {
            sb.append("S");
        }
        if ((flags & 0x40) != 0) {
            sb.append("I");
        }
        if ((flags & 0x80) != 0) {
            sb.append("L");
        }
        if ((flags & 0x100) != 0) {
            sb.append("O");
        }
        if ((flags & 0x200) != 0) {
            sb.append("G");
        }
        if ((flags & 0x400) != 0) {
            sb.append("T");
        }
        if ((flags & 0x800) != 0) {
            sb.append("C");
        }
        if ((flags & 0x1000) != 0) {
            sb.append("E");
        }
        return sb.toString();
    }

    private static String strSegmentType(int type) {
        switch (type) {
            case 0:
                return "NULL";
            case 1:
                return "LOAD";
            case 2:
                return "DYNAMIC";
            case 3:
                return "INTERP";
            case 4:
                return "NOTE";
            case 5:
                return "SHLIB";
            case 6:
                return "PHDR";
            case 7:
                return "TLS";
            case 0x6474e551:
                return "GNU_EH_FRAME";
            case 0x6474e552:
                return "GNU_STACK";
            case 0x6474e553:
                return "GNU_RELRO";
            default:
                return "0x" + Integer.toHexString(type);
        }
    }

    private static String segmentFlags(int flags) {
        return String.format("%c%c%c", (flags & 0x4) != 0 ? 'R' : ' ', (flags & 0x2) != 0 ? 'W' : ' ',
            (flags & 0x1) != 0 ? 'E' : ' ');
    }

    private static String strSymbolType(byte type) {
        switch (type) {
            case 0:
                return "NOTYPE";
            case 1:
                return "OBJECT";
            case 2:
                return "FUNC";
            case 3:
                return "SECTION";
            case 4:
                return "FILE";
            case 5:
                return "COMMON";
            case 6:
                return "TLS";
            default:
                return "0x" + Integer.toHexString(type);
        }
    }

    private static String strSymbolBind(byte bind) {
        switch (bind) {
            case 0:
                return "LOCAL";
            case 1:
                return "GLOBAL";
            case 2:
                return "WEAK";
            default:
                return "0x" + Integer.toHexString(bind);
        }
    }

    private static String strDynamicTag(long tag) {
        return DYNAMIC_TAG_NAMES.getOrDefault(tag, "0x" + Long.toHexString(tag));
    }
}
