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

/**
 * ELF type definitions and constants.
 * This class contains all the ELF format constants and type definitions.
 *
 * @since 2026/3/5
 */
public final class ElfTypes {
    // ELF Header sizes
    public static final short HEADER_SIZE_64 = 64;

    public static final short HEADER_SIZE_32 = 52;

    // Section Header sizes
    public static final short SECTION_HEADER_SIZE_64 = 64;

    public static final short SECTION_HEADER_SIZE_32 = 40;

    // Program Header (Segment) sizes
    public static final short SEGMENT_HEADER_SIZE_64 = 56;

    public static final short SEGMENT_HEADER_SIZE_32 = 32;

    // Section Entry sizes (for specific section types)
    // Relocation entries
    public static final short RELA_ENTRY_SIZE_64 = 24;

    public static final short RELA_ENTRY_SIZE_32 = 12;

    public static final short REL_ENTRY_SIZE_64 = 16;

    public static final short REL_ENTRY_SIZE_32 = 8;

    // Symbol entries
    public static final short SYM_ENTRY_SIZE_64 = 24;

    public static final short SYM_ENTRY_SIZE_32 = 16;

    // Dynamic entries
    public static final short DYN_ENTRY_SIZE_64 = 16;

    public static final short DYN_ENTRY_SIZE_32 = 8;

    // ELF Identification indexes
    public static final int EI_MAG0 = 0;

    public static final int EI_MAG1 = 1;

    public static final int EI_MAG2 = 2;

    public static final int EI_MAG3 = 3;

    public static final int EI_CLASS = 4;

    public static final int EI_DATA = 5;

    public static final int EI_VERSION = 6;

    public static final int EI_OSABI = 7;

    public static final int EI_ABIVERSION = 8;

    public static final int EI_PAD = 9;

    public static final int EI_NIDENT = 16;

    // Magic number
    public static final byte ELFMAG0 = 0x7F;

    public static final byte ELFMAG1 = 'E';

    public static final byte ELFMAG2 = 'L';

    public static final byte ELFMAG3 = 'F';

    // File class
    public static final byte ELFCLASSNONE = 0;

    public static final byte ELFCLASS32 = 1;

    public static final byte ELFCLASS64 = 2;

    // Encoding
    public static final byte ELFDATANONE = 0;

    public static final byte ELFDATA2LSB = 1;

    public static final byte ELFDATA2MSB = 2;

    // File version
    public static final byte EV_NONE = 0;

    public static final byte EV_CURRENT = 1;

    // File type
    public static final short ET_NONE = 0;

    public static final short ET_REL = 1;

    public static final short ET_EXEC = 2;

    public static final short ET_DYN = 3;

    public static final short ET_CORE = 4;

    public static final short ET_LOOS = (short) 0xFE00;

    public static final short ET_HIOS = (short) 0xFEFF;

    public static final short ET_LOPROC = (short) 0xFF00;

    public static final short ET_HIPROC = (short) 0xFFFF;

    // Machine numbers (common ones)
    public static final short EM_NONE = 0;

    public static final short EM_M32 = 1;

    public static final short EM_SPARC = 2;

    public static final short EM_386 = 3;

    public static final short EM_68K = 4;

    public static final short EM_88K = 5;

    public static final short EM_860 = 7;

    public static final short EM_MIPS = 8;

    public static final short EM_S370 = 9;

    public static final short EM_MIPS_RS3_LE = 10;

    public static final short EM_PARISC = 15;

    public static final short EM_VPP550 = 17;

    public static final short EM_SPARC32PLUS = 18;

    public static final short EM_960 = 19;

    public static final short EM_PPC = 20;

    public static final short EM_PPC64 = 21;

    public static final short EM_S390 = 22;

    public static final short EM_SPU = 23;

    public static final short EM_V800 = 36;

    public static final short EM_FR20 = 37;

    public static final short EM_RH32 = 38;

    public static final short EM_MCORE = 39;

    public static final short EM_ARM = 40;

    public static final short EM_OLD_ALPHA = 41;

    public static final short EM_SH = 42;

    public static final short EM_SPARCV9 = 43;

    public static final short EM_TRICORE = 44;

    public static final short EM_ARC = 45;

    public static final short EM_H8_300 = 46;

    public static final short EM_H8_300H = 47;

    public static final short EM_H8S = 48;

    public static final short EM_H8_500 = 49;

    public static final short EM_IA_64 = 50;

    public static final short EM_MIPS_X = 51;

    public static final short EM_COLDFIRE = 52;

    public static final short EM_68HC12 = 53;

    public static final short EM_MMA = 54;

    public static final short EM_PCP = 55;

    public static final short EM_NCPU = 56;

    public static final short EM_NDR1 = 57;

    public static final short EM_STARCORE = 58;

    public static final short EM_ME16 = 59;

    public static final short EM_ST100 = 60;

    public static final short EM_TINYJ = 61;

    public static final short EM_X86_64 = 62;

    public static final short EM_PDSP = 63;

    public static final short EM_PDP10 = 64;

    public static final short EM_PDP11 = 65;

    public static final short EM_FX66 = 66;

    public static final short EM_ST9PLUS = 67;

    public static final short EM_ST7 = 68;

    public static final short EM_68HC16 = 69;

    public static final short EM_68HC11 = 70;

    public static final short EM_68HC08 = 71;

    public static final short EM_68HC05 = 72;

    public static final short EM_SVX = 73;

    public static final short EM_ST19 = 74;

    public static final short EM_VAX = 75;

    public static final short EM_CRIS = 76;

    public static final short EM_JAVELIN = 77;

    public static final short EM_FIREPATH = 78;

    public static final short EM_ZSP = 79;

    public static final short EM_MMIX = 80;

    public static final short EM_HUANY = 81;

    public static final short EM_PRISM = 82;

    public static final short EM_AVR = 83;

    public static final short EM_FR30 = 84;

    public static final short EM_D10V = 85;

    public static final short EM_D30V = 86;

    public static final short EM_V850 = 87;

    public static final short EM_M32R = 88;

    public static final short EM_MN10300 = 89;

    public static final short EM_MN10200 = 90;

    public static final short EM_PJ = 91;

    public static final short EM_OPENRISC = 92;

    public static final short EM_ARC_A5 = 93;

    public static final short EM_XTENSA = 94;

    public static final short EM_VIDEOCORE = 95;

    public static final short EM_TMM_GPP = 96;

    public static final short EM_NS32K = 97;

    public static final short EM_TPC = 98;

    public static final short EM_SNP1K = 99;

    public static final short EM_ST200 = 100;

    public static final short EM_IP2K = 101;

    public static final short EM_MAX = 102;

    public static final short EM_CR = 103;

    public static final short EM_F2MC16 = 104;

    public static final short EM_MSP430 = 105;

    public static final short EM_BLACKFIN = 106;

    public static final short EM_SE_C33 = 107;

    public static final short EM_SEP = 108;

    public static final short EM_ARCA = 109;

    public static final short EM_UNICORE = 110;

    public static final short EM_EXCESS = 111;

    public static final short EM_DXP = 112;

    public static final short EM_ALTERA_NIOS2 = 113;

    public static final short EM_CRX = 114;

    public static final short EM_XGATE = 115;

    public static final short EM_C166 = 116;

    public static final short EM_M16C = 117;

    public static final short EM_DSPIC30F = 118;

    public static final short EM_CE = 119;

    public static final short EM_M32C = 120;

    public static final short EM_TSK3000 = 131;

    public static final short EM_RS08 = 132;

    public static final short EMC_ECOG2 = 134;

    public static final short EM_SCORE = 135;

    public static final short EM_DSP24 = 136;

    public static final short EM_VIDEOCORE3 = 137;

    public static final short EM_LATTICEMICO32 = 138;

    public static final short EM_SE_C17 = 139;

    public static final short EM_TI_C6000 = 140;

    public static final short EM_TI_C2000 = 141;

    public static final short EM_TI_C5500 = 142;

    public static final short EM_MMDSP_PLUS = 160;

    public static final short EM_CYPRESS_M8C = 161;

    public static final short EM_R32C = 162;

    public static final short EM_TRIMEDIA = 163;

    public static final short EM_QDSP6 = 164;

    public static final short EM_8051 = 165;

    public static final short EM_STXP7X = 166;

    public static final short EM_NDS32 = 167;

    public static final short EM_ECOG1 = 168;

    public static final short EM_MAXQ30 = 169;

    public static final short EM_XIMO16 = 170;

    public static final short EM_MANIK = 171;

    public static final short EM_CRAYNV2 = 172;

    public static final short EM_RX = 173;

    public static final short EM_METAG = 174;

    public static final short EM_MCST_ELBRUS = 175;

    public static final short EM_ECOG16 = 176;

    public static final short EM_CR16 = 177;

    public static final short EM_ETPU = 178;

    public static final short EM_SLE9X = 179;

    public static final short EM_L1OM = 180;

    public static final short EM_INTEL181 = 181;

    public static final short EM_INTEL182 = 182;

    public static final short EM_AARCH64 = 183;

    public static final short EM_AVR32 = 185;

    public static final short EM_STM8 = 186;

    public static final short EM_TILE64 = 187;

    public static final short EM_TILEPRO = 188;

    public static final short EM_MICROBLAZE = 189;

    public static final short EM_CUDA = 190;

    public static final short EM_TILEGX = 191;

    public static final short EM_CLOUDSHIELD = 192;

    public static final short EM_COREA_1ST = 193;

    public static final short EM_COREA_2ND = 194;

    public static final short EM_ARC_COMPACT2 = 195;

    public static final short EM_OPEN8 = 196;

    public static final short EM_RL78 = 197;

    public static final short EM_VIDEOCORE5 = 198;

    public static final short EM_78KOR = 199;

    public static final short EM_56800EX = 200;

    public static final short EM_BA1 = 201;

    public static final short EM_BA2 = 202;

    public static final short EM_XCORE = 203;

    public static final short EM_MCHP_PIC = 204;

    public static final short EM_INTEL205 = 205;

    public static final short EM_INTEL206 = 206;

    public static final short EM_INTEL207 = 207;

    public static final short EM_INTEL208 = 208;

    public static final short EM_INTEL209 = 209;

    public static final short EM_KM32 = 210;

    public static final short EM_KMX32 = 211;

    public static final short EM_KMX16 = 212;

    public static final short EM_KMX8 = 213;

    public static final short EM_KVARC = 214;

    public static final short EM_CDP = 215;

    public static final short EM_COGE = 216;

    public static final short EM_COOL = 217;

    public static final short EM_NORC = 218;

    public static final short EM_CSR_KALIMBA = 219;

    public static final short EM_Z80 = 220;

    public static final short EM_VISIUM = 221;

    public static final short EM_FT32 = 222;

    public static final short EM_MOXIE = 223;

    public static final short EM_AMDGPU = 224;

    public static final short EM_RISCV = 243;

    public static final short EM_LANAI = 244;

    public static final short EM_CEVA = 245;

    public static final short EM_CEVA_X2 = 246;

    public static final short EM_BPF = 247;

    public static final short EM_GRAPHCORE_IPU = 248;

    public static final short EM_IMG1 = 249;

    public static final short EM_NFP = 250;

    public static final short EM_CSKY = 252;

    public static final short EM_ARC_COMPACT3_64 = 253;

    public static final short EM_MCS6502 = 254;

    public static final short EM_ARC_COMPACT3 = 255;

    public static final short EM_KVX = 256;

    public static final short EM_65816 = 257;

    public static final short EM_LOONGARCH = 258;

    public static final short EM_KF32 = 259;

    // OS/ABI identification
    public static final byte ELFOSABI_NONE = 0;

    public static final byte ELFOSABI_HPUX = 1;

    public static final byte ELFOSABI_NETBSD = 2;

    public static final byte ELFOSABI_LINUX = 3;

    public static final byte ELFOSABI_HURD = 4;

    public static final byte ELFOSABI_SOLARIS = 6;

    public static final byte ELFOSABI_AIX = 7;

    public static final byte ELFOSABI_IRIX = 8;

    public static final byte ELFOSABI_FREEBSD = 9;

    public static final byte ELFOSABI_TRU64 = 10;

    public static final byte ELFOSABI_MODESTO = 11;

    public static final byte ELFOSABI_OPENBSD = 12;

    public static final byte ELFOSABI_OPENVMS = 13;

    public static final byte ELFOSABI_NSK = 14;

    public static final byte ELFOSABI_AROS = 15;

    public static final byte ELFOSABI_FENIXOS = 16;

    public static final byte ELFOSABI_NUXI = 17;

    public static final byte ELFOSABI_OPENVOS = 18;

    public static final byte ELFOSABI_ARM = 97;

    public static final byte ELFOSABI_STANDALONE = (byte) 255;

    // Section indexes
    public static final int SHN_UNDEF = 0;

    public static final int SHN_LORESERVE = 0xFF00;

    public static final int SHN_LOPROC = 0xFF00;

    public static final int SHN_HIPROC = 0xFF1F;

    public static final int SHN_LOOS = 0xFF20;

    public static final int SHN_HIOS = 0xFF3F;

    public static final int SHN_ABS = 0xFFF1;

    public static final int SHN_COMMON = 0xFFF2;

    public static final int SHN_XINDEX = 0xFFFF;

    public static final int SHN_HIRESERVE = 0xFFFF;

    // Section types
    public static final int SHT_NULL = 0;

    public static final int SHT_PROGBITS = 1;

    public static final int SHT_SYMTAB = 2;

    public static final int SHT_STRTAB = 3;

    public static final int SHT_RELA = 4;

    public static final int SHT_HASH = 5;

    public static final int SHT_DYNAMIC = 6;

    public static final int SHT_NOTE = 7;

    public static final int SHT_NOBITS = 8;

    public static final int SHT_REL = 9;

    public static final int SHT_SHLIB = 10;

    public static final int SHT_DYNSYM = 11;

    public static final int SHT_INIT_ARRAY = 14;

    public static final int SHT_FINI_ARRAY = 15;

    public static final int SHT_PREINIT_ARRAY = 16;

    public static final int SHT_GROUP = 17;

    public static final int SHT_SYMTAB_SHNDX = 18;

    public static final int SHT_GNU_ATTRIBUTES = 0x6ffffff5;

    public static final int SHT_GNU_HASH = 0x6ffffff6;

    public static final int SHT_GNU_LIBLIST = 0x6ffffff7;

    public static final int SHT_CHECKSUM = 0x6ffffff8;

    public static final int SHT_LOSUNW = 0x6ffffffa;

    public static final int SHT_SUNW_move = 0x6ffffffa;

    public static final int SHT_SUNW_COMDAT = 0x6ffffffb;

    public static final int SHT_SUNW_syminfo = 0x6ffffffc;

    public static final int SHT_GNU_verdef = 0x6ffffffd;

    public static final int SHT_GNU_verneed = 0x6ffffffe;

    public static final int SHT_GNU_versym = 0x6fffffff;

    public static final int SHT_LOOS = 0x60000000;

    public static final int SHT_HIOS = 0x6fffffff;

    public static final int SHT_LOPROC = 0x70000000;

    public static final int SHT_ARM_EXIDX = 0x70000001;

    public static final int SHT_ARM_PREEMPTMAP = 0x70000002;

    public static final int SHT_ARM_ATTRIBUTES = 0x70000003;

    public static final int SHT_ARM_DEBUGOVERLAY = 0x70000004;

    public static final int SHT_ARM_OVERLAYSECTION = 0x70000005;

    public static final int SHT_HIPROC = 0x7FFFFFFF;

    public static final int SHT_LOUSER = 0x80000000;

    public static final int SHT_HIUSER = 0xFFFFFFFF;

    // Section attribute flags
    public static final long SHF_WRITE = 0x1L;

    public static final long SHF_ALLOC = 0x2L;

    public static final long SHF_EXECINSTR = 0x4L;

    public static final long SHF_MERGE = 0x10L;

    public static final long SHF_STRINGS = 0x20L;

    public static final long SHF_INFO_LINK = 0x40L;

    public static final long SHF_LINK_ORDER = 0x80L;

    public static final long SHF_OS_NONCONFORMING = 0x100L;

    public static final long SHF_GROUP = 0x200L;

    public static final long SHF_TLS = 0x400L;

    public static final long SHF_COMPRESSED = 0x800L;

    public static final long SHF_GNU_RETAIN = 0x200000L;

    public static final long SHF_GNU_MBIND = 0x01000000L;

    public static final long SHF_RPX_DEFLATE = 0x08000000L; // Wii U RPX compression flag

    public static final long SHF_MASKOS = 0x0FF00000L;

    public static final long SHF_MIPS_GPREL = 0x10000000L;

    public static final long SHF_ORDERED = 0x40000000L;

    public static final long SHF_EXCLUDE = 0x80000000L;

    public static final long SHF_MASKPROC = 0xF0000000L;

    // Symbol binding
    public static final byte STB_LOCAL = 0;

    public static final byte STB_GLOBAL = 1;

    public static final byte STB_WEAK = 2;

    public static final byte STB_LOOS = 10;

    public static final byte STB_HIOS = 12;

    public static final byte STB_LOPROC = 13;

    public static final byte STB_HIPROC = 15;

    // Symbol types
    public static final byte STT_NOTYPE = 0;

    public static final byte STT_OBJECT = 1;

    public static final byte STT_FUNC = 2;

    public static final byte STT_SECTION = 3;

    public static final byte STT_FILE = 4;

    public static final byte STT_COMMON = 5;

    public static final byte STT_TLS = 6;

    public static final byte STT_LOOS = 10;

    public static final byte STT_HIOS = 12;

    public static final byte STT_LOPROC = 13;

    public static final byte STT_HIPROC = 15;

    // Symbol visibility
    public static final byte STV_DEFAULT = 0;

    public static final byte STV_INTERNAL = 1;

    public static final byte STV_HIDDEN = 2;

    public static final byte STV_PROTECTED = 3;

    // Segment types
    public static final int PT_NULL = 0;

    public static final int PT_LOAD = 1;

    public static final int PT_DYNAMIC = 2;

    public static final int PT_INTERP = 3;

    public static final int PT_NOTE = 4;

    public static final int PT_SHLIB = 5;

    public static final int PT_PHDR = 6;

    public static final int PT_TLS = 7;

    public static final int PT_LOOS = 0x60000000;

    public static final int PT_GNU_EH_FRAME = 0x6474E550;

    public static final int PT_GNU_STACK = 0x6474E551;

    public static final int PT_GNU_RELRO = 0x6474E552;

    public static final int PT_GNU_PROPERTY = 0x6474E553;

    public static final int PT_GNU_MBIND_LO = 0x6474E555;

    public static final int PT_GNU_MBIND_HI = 0x6474F554;

    public static final int PT_PAX_FLAGS = 0x65041580;

    public static final int PT_OPENBSD_RANDOMIZE = 0x65A3DBE6;

    public static final int PT_OPENBSD_WXNEEDED = 0x65A3DBE7;

    public static final int PT_OPENBSD_BOOTDATA = 0x65A41BE6;

    public static final int PT_SUNWBSS = 0x6FFFFFFA;

    public static final int PT_SUNWSTACK = 0x6FFFFFFB;

    public static final int PT_HIOS = 0x6FFFFFFF;

    public static final int PT_LOPROC = 0x70000000;

    public static final int PT_HIPROC = 0x7FFFFFFF;

    // Segment flags
    public static final int PF_X = 0x1;

    public static final int PF_W = 0x2;

    public static final int PF_R = 0x4;

    public static final int PF_MASKOS = 0x0ff00000;

    public static final int PF_MASKPROC = 0xf0000000;

    // Dynamic tags
    public static final int DT_NULL = 0;

    public static final int DT_NEEDED = 1;

    public static final int DT_PLTRELSZ = 2;

    public static final int DT_PLTGOT = 3;

    public static final int DT_HASH = 4;

    public static final int DT_STRTAB = 5;

    public static final int DT_SYMTAB = 6;

    public static final int DT_RELA = 7;

    public static final int DT_RELASZ = 8;

    public static final int DT_RELAENT = 9;

    public static final int DT_STRSZ = 10;

    public static final int DT_SYMENT = 11;

    public static final int DT_INIT = 12;

    public static final int DT_FINI = 13;

    public static final int DT_SONAME = 14;

    public static final int DT_RPATH = 15;

    public static final int DT_SYMBOLIC = 16;

    public static final int DT_REL = 17;

    public static final int DT_RELSZ = 18;

    public static final int DT_RELENT = 19;

    public static final int DT_PLTREL = 20;

    public static final int DT_DEBUG = 21;

    public static final int DT_TEXTREL = 22;

    public static final int DT_JMPREL = 23;

    public static final int DT_BIND_NOW = 24;

    public static final int DT_INIT_ARRAY = 25;

    public static final int DT_FINI_ARRAY = 26;

    public static final int DT_INIT_ARRAYSZ = 27;

    public static final int DT_FINI_ARRAYSZ = 28;

    public static final int DT_RUNPATH = 29;

    public static final int DT_FLAGS = 30;

    public static final int DT_ENCODING = 32;

    public static final int DT_PREINIT_ARRAY = 32;

    public static final int DT_PREINIT_ARRAYSZ = 33;

    public static final int DT_MAXPOSTAGS = 34;

    public static final int DT_LOOS = 0x6000000D;

    public static final int DT_HIOS = 0x6ffff000;

    public static final int DT_GNU_HASH = 0x6ffffef5;

    public static final int DT_TLSDESC_PLT = 0x6ffffef6;

    public static final int DT_TLSDESC_GOT = 0x6ffffef7;

    public static final int DT_GNU_CONFLICT = 0x6ffffef8;

    public static final int DT_GNU_LIBLIST = 0x6ffffef9;

    public static final int DT_CONFIG = 0x6ffffefa;

    public static final int DT_DEPAUDIT = 0x6ffffefb;

    public static final int DT_AUDIT = 0x6ffffefc;

    public static final int DT_PLTPAD = 0x6ffffefd;

    public static final int DT_MOVETAB = 0x6ffffefe;

    public static final int DT_SYMINFO = 0x6ffffeff;

    public static final int DT_ADDRRNGHI = 0x6ffffeff;

    public static final int DT_VERSYM = 0x6ffffff0;

    public static final int DT_RELACOUNT = 0x6ffffff9;

    public static final int DT_RELCOUNT = 0x6ffffffa;

    public static final int DT_FLAGS_1 = 0x6ffffffb;

    public static final int DT_VERDEF = 0x6ffffffc;

    public static final int DT_VERDEFNUM = 0x6ffffffd;

    public static final int DT_VERNEED = 0x6ffffffe;

    public static final int DT_VERNEEDNUM = 0x6fffffff;

    public static final int DT_LOPROC = 0x70000000;

    public static final int DT_HIPROC = 0x7FFFFFFF;

    // DT_FLAGS values
    public static final int DF_ORIGIN = 0x1;

    public static final int DF_SYMBOLIC = 0x2;

    public static final int DF_TEXTREL = 0x4;

    public static final int DF_BIND_NOW = 0x8;

    public static final int DF_STATIC_TLS = 0x10;

    // Relocation types for x86
    public static final int R_386_NONE = 0;

    public static final int R_386_32 = 1;

    public static final int R_386_PC32 = 2;

    public static final int R_386_GOT32 = 3;

    public static final int R_386_PLT32 = 4;

    public static final int R_386_COPY = 5;

    public static final int R_386_GLOB_DAT = 6;

    public static final int R_386_JUMP_SLOT = 7;

    public static final int R_386_RELATIVE = 8;

    public static final int R_386_GOTOFF = 9;

    public static final int R_386_GOTPC = 10;

    public static final int R_386_32PLT = 11;

    public static final int R_386_16 = 20;

    public static final int R_386_PC16 = 21;

    public static final int R_386_8 = 22;

    public static final int R_386_PC8 = 23;

    public static final int R_386_IRELATIVE = 42;

    // Relocation types for x86_64
    public static final int R_X86_64_NONE = 0;

    public static final int R_X86_64_64 = 1;

    public static final int R_X86_64_PC32 = 2;

    public static final int R_X86_64_GOT32 = 3;

    public static final int R_X86_64_PLT32 = 4;

    public static final int R_X86_64_COPY = 5;

    public static final int R_X86_64_GLOB_DAT = 6;

    public static final int R_X86_64_JUMP_SLOT = 7;

    public static final int R_X86_64_RELATIVE = 8;

    public static final int R_X86_64_GOTPCREL = 9;

    public static final int R_X86_64_32 = 10;

    public static final int R_X86_64_32S = 11;

    public static final int R_X86_64_16 = 12;

    public static final int R_X86_64_PC16 = 13;

    public static final int R_X86_64_8 = 14;

    public static final int R_X86_64_PC8 = 15;

    public static final int R_X86_64_IRELATIVE = 37;

    // Private constructor to prevent instantiation
    private ElfTypes() {
    }

    /**
     * Extract symbol index from 32-bit relocation info.
     */
    public static int ELF32_R_SYM(int info) {
        return info >> 8;
    }

    /**
     * Extract type from 32-bit relocation info.
     */
    public static int ELF32_R_TYPE(int info) {
        return info & 0xff;
    }

    /**
     * Create 32-bit relocation info from symbol and type.
     */
    public static int ELF32_R_INFO(int sym, int type) {
        return (sym << 8) + (type & 0xff);
    }

    /**
     * Extract symbol index from 64-bit relocation info.
     */
    public static int ELF64_R_SYM(long info) {
        return (int) (info >>> 32);
    }

    /**
     * Extract type from 64-bit relocation info.
     */
    public static int ELF64_R_TYPE(long info) {
        return (int) (info & 0xffffffffL);
    }

    /**
     * Create 64-bit relocation info from symbol and type.
     */
    public static long ELF64_R_INFO(int sym, int type) {
        return ((long) sym << 32) + (type & 0xffffffffL);
    }

    // ELF Symbol helper methods

    /**
     * Extract symbol binding from info.
     */
    public static byte ELF_ST_BIND(byte info) {
        return (byte) (info >> 4);
    }

    /**
     * Extract symbol type from info.
     */
    public static byte ELF_ST_TYPE(byte info) {
        return (byte) (info & 0xf);
    }

    /**
     * Create symbol info from bind and type.
     */
    public static byte ELF_ST_INFO(int bind, int type) {
        return (byte) ((bind << 4) + (type & 0xf));
    }

    /**
     * Extract symbol visibility from other.
     */
    public static byte ELF_ST_VISIBILITY(byte stOther) {
        return (byte) (stOther & 0x3);
    }
}
