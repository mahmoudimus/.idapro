#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <Windows.h>
#include <DbgHelp.h>
#include <intrin.h>

extern "C" {
#include <xed-interface.h>
}

#include <vector>
#include <array>
#include <unordered_map>
#include <algorithm>
#include <functional>

#pragma intrinsic(_mul128)

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef int64_t i64;
typedef int32_t i32;
typedef int16_t i16;
typedef int8_t i8;

typedef uintptr_t uptr;
typedef intptr_t iptr;

// hash function
#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/*
-------------------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.

This is reversible, so any information in (a,b,c) before mix() is
still in (a,b,c) after mix().

If four pairs of (a,b,c) inputs are run through mix(), or through
mix() in reverse, there are at least 32 bits of the output that
are sometimes the same for one pair and different for another pair.
This was tested for:
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or 
  all zero plus a counter that starts at zero.

Some k values for my "a-=c; a^=rot(c,k); c+=b;" arrangement that
satisfy this are
    4  6  8 16 19  4
    9 15  3 18 27 15
   14  9  3  7 17  3
Well, "9 15 3 18 27 15" didn't quite get 32 bits diffing
for "differ" defined as + with a one-bit base and a two-bit delta.  I
used http://burtleburtle.net/bob/hash/avalanche.html to choose 
the operations, constants, and arrangements of the variables.

This does not achieve avalanche.  There are input bits of (a,b,c)
that fail to affect some output bits of (a,b,c), especially of a.  The
most thoroughly mixed value is c, but it doesn't really even achieve
avalanche in c.

This allows some parallelism.  Read-after-writes are good at doubling
the number of bits affected, so the goal of mixing pulls in the opposite
direction as the goal of parallelism.  I did what I could.  Rotates
seem to cost as much as shifts on every machine I could lay my hands
on, and rotates are much kinder to the top and bottom bits, so I used
rotates.
-------------------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

/*
-------------------------------------------------------------------------------
final -- final mixing of 3 32-bit values (a,b,c) into c

Pairs of (a,b,c) values differing in only a few bits will usually
produce values of c that look totally different.  This was tested for
* pairs that differed by one bit, by two bits, in any combination
  of top bits of (a,b,c), or in any combination of bottom bits of
  (a,b,c).
* "differ" is defined as +, -, ^, or ~^.  For + and -, I transformed
  the output delta to a Gray code (a^(a>>1)) so a string of 1's (as
  is commonly produced by subtraction) look like a single 1-bit
  difference.
* the base values were pseudorandom, all zero but one bit set, or 
  all zero plus a counter that starts at zero.

These constants passed:
 14 11 25 16 4 14 24
 12 14 25 16 4 14 24
and these came close:
  4  8 15 26 3 22 24
 10  8 15 26 3 22 24
 11  8 15 26 3 22 24
-------------------------------------------------------------------------------
*/
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

/*
-------------------------------------------------------------------------------
hashlittle() -- hash a variable-length key into a 32-bit value
  k       : the key (the unaligned variable-length array of bytes)
  length  : the length of the key, counting by bytes
  initval : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Two keys differing by one or two bits will have
totally different hash values.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hashlittle( k[i], len[i], h);

By Bob Jenkins, 2006.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

Use for hash table lookup, or anything where one collision in 2^^32 is
acceptable.  Do NOT use for cryptographic purposes.
-------------------------------------------------------------------------------
*/

uint32_t hashlittle( const void *key, size_t length, uint32_t initval)
{
  uint32_t a,b,c;                                          /* internal state */
  union { const void *ptr; size_t i; } u;     /* needed for Mac Powerbook G4 */

  /* Set up the internal state */
  a = b = c = 0xdeadbeef + ((uint32_t)length) + initval;

  u.ptr = key;
  if ((u.i & 0x3) == 0) {
    const uint32_t *k = (const uint32_t *)key;         /* read 32-bit chunks */
    const uint8_t  *k8;

    /*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      b += k[1];
      c += k[2];
      mix(a,b,c);
      length -= 12;
      k += 3;
    }

    /*----------------------------- handle the last (probably partial) block */
    /* 
     * "k[2]&0xffffff" actually reads beyond the end of the string, but
     * then masks off the part it's not allowed to read.  Because the
     * string is aligned, the masked-off tail is in the same word as the
     * rest of the string.  Every machine with memory protection I've seen
     * does it on word boundaries, so is OK with this.  But VALGRIND will
     * still catch it and complain.  The masking trick does make the hash
     * noticably faster for short strings (like English words).
     */
    switch(length)
    {
    case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
    case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
    case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
    case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
    case 8 : b+=k[1]; a+=k[0]; break;
    case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
    case 6 : b+=k[1]&0xffff; a+=k[0]; break;
    case 5 : b+=k[1]&0xff; a+=k[0]; break;
    case 4 : a+=k[0]; break;
    case 3 : a+=k[0]&0xffffff; break;
    case 2 : a+=k[0]&0xffff; break;
    case 1 : a+=k[0]&0xff; break;
    case 0 : return c;              /* zero length strings require no mixing */
    }
  } else if ((u.i & 0x1) == 0) {
    const uint16_t *k = (const uint16_t *)key;         /* read 16-bit chunks */
    const uint8_t  *k8;

    /*--------------- all but last block: aligned reads and different mixing */
    while (length > 12)
    {
      a += k[0] + (((uint32_t)k[1])<<16);
      b += k[2] + (((uint32_t)k[3])<<16);
      c += k[4] + (((uint32_t)k[5])<<16);
      mix(a,b,c);
      length -= 12;
      k += 6;
    }

    /*----------------------------- handle the last (probably partial) block */
    k8 = (const uint8_t *)k;
    switch(length)
    {
    case 12: c+=k[4]+(((uint32_t)k[5])<<16);
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 11: c+=((uint32_t)k8[10])<<16;     /* fall through */
    case 10: c+=k[4];
             b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 9 : c+=k8[8];                      /* fall through */
    case 8 : b+=k[2]+(((uint32_t)k[3])<<16);
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 7 : b+=((uint32_t)k8[6])<<16;      /* fall through */
    case 6 : b+=k[2];
             a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 5 : b+=k8[4];                      /* fall through */
    case 4 : a+=k[0]+(((uint32_t)k[1])<<16);
             break;
    case 3 : a+=((uint32_t)k8[2])<<16;      /* fall through */
    case 2 : a+=k[0];
             break;
    case 1 : a+=k8[0];
             break;
    case 0 : return c;                     /* zero length requires no mixing */
    }

  } else {                        /* need to read the key one byte at a time */
    const uint8_t *k = (const uint8_t *)key;

    /*--------------- all but the last block: affect some 32 bits of (a,b,c) */
    while (length > 12)
    {
      a += k[0];
      a += ((uint32_t)k[1])<<8;
      a += ((uint32_t)k[2])<<16;
      a += ((uint32_t)k[3])<<24;
      b += k[4];
      b += ((uint32_t)k[5])<<8;
      b += ((uint32_t)k[6])<<16;
      b += ((uint32_t)k[7])<<24;
      c += k[8];
      c += ((uint32_t)k[9])<<8;
      c += ((uint32_t)k[10])<<16;
      c += ((uint32_t)k[11])<<24;
      mix(a,b,c);
      length -= 12;
      k += 12;
    }

    /*-------------------------------- last block: affect all 32 bits of (c) */
    switch(length)                   /* all the case statements fall through */
    {
    case 12: c+=((uint32_t)k[11])<<24;
    case 11: c+=((uint32_t)k[10])<<16;
    case 10: c+=((uint32_t)k[9])<<8;
    case 9 : c+=k[8];
    case 8 : b+=((uint32_t)k[7])<<24;
    case 7 : b+=((uint32_t)k[6])<<16;
    case 6 : b+=((uint32_t)k[5])<<8;
    case 5 : b+=k[4];
    case 4 : a+=((uint32_t)k[3])<<24;
    case 3 : a+=((uint32_t)k[2])<<16;
    case 2 : a+=((uint32_t)k[1])<<8;
    case 1 : a+=k[0];
             break;
    case 0 : return c;
    }
  }

  final(a,b,c);
  return c;
}

// Set to 1 to make the output executable runnable.
// Note: doesn't work, might never work.
#define PATCH_TO_RUN 0

#define Print(s, ...) printf(TEXT(s), __VA_ARGS__)

struct ImageImport {
	u32 OriginalFirstThunk;
	u32 TimeDateStamp;
	u32 ForwarderChain;
	u32 Name;
	u32 FirstThunk;
};

struct PEReader {
	u8 *peFile;

	IMAGE_NT_HEADERS64 *GetNtHeader() {
		auto dosHeader = (IMAGE_DOS_HEADER *)peFile;
		return (IMAGE_NT_HEADERS64 *)(peFile + dosHeader->e_lfanew);
	}

	u8 *TranslateRVA(u32 rva) {
		auto ntHeader = GetNtHeader();
		auto firstSect = IMAGE_FIRST_SECTION(ntHeader);
		for (u16 i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			auto &sect = firstSect[i];
			u32 start = sect.VirtualAddress;
			u32 end = start + sect.Misc.VirtualSize;
			if (start <= rva && end > rva) {
				return peFile + sect.PointerToRawData + rva - start;
			}
		}
		return nullptr;
	}

	u8 *GetSectionPointer(const char *name, int nth, u32 *size) {
		auto ntHeader = GetNtHeader();
		auto firstSect = IMAGE_FIRST_SECTION(ntHeader);
		for (u16 i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			auto &sect = firstSect[i];
			if (!strcmp((const char *)sect.Name, name)) {
				if (!nth--) {
					if (size) *size = sect.SizeOfRawData;
					return peFile + sect.PointerToRawData;
				}
			}
		}
		return nullptr;
	}

	u32 GetMaxRVA() {
		u32 max = 0;
		auto ntHeader = GetNtHeader();
		auto firstSect = IMAGE_FIRST_SECTION(ntHeader);
		for (u16 i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
			auto &sect = firstSect[i];
			u32 rva = sect.VirtualAddress + sect.SizeOfRawData;
			if (rva > max) max = rva;
		}
		return max;
	}
};

LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	return 0;
}

using std::vector;

struct FlagState {
	u32 cf : 2;
	u32 pf : 2;
	u32 af : 2;
	u32 zf : 2;
	u32 sf : 2;
	u32 df : 2;
	u32 of : 2;
	// jcc combined logic:
	// 2 when on the taken side of Jcc, 1 when on the not taken side
	u32 jbe : 2;
	u32 jl : 2;
	u32 jle : 2;

	u32 knownIndex; // write index for following ring buffers:
	u64 knownAddresses[16]; // 0 means unknown
	i64 knownValues[16];
	u8 knownValueSizes[16]; // in bits
	u32 knownRegIndex;
	u8 knownRegs[16];
	i64 knownRegValues[16];

	// Addresses for things which aren't flat memory are prefixed:
	static const u64 kAddressRbp = 1ull << 48;
	static const u64 kAddressRsp = 2ull << 48;
	static const u64 kAddressMask = 0xffull << 48;

	u32 Hash() {
		u32 c = 0;
		c = hashlittle(this, 4, c);
		std::array<u64, 16> addrs;
		for (int i = 0; i < 16; i++)
			addrs[i] = knownAddresses[i];
		std::sort(addrs.begin(), addrs.end());
		for (int i = 0; i < 16; i++) {
			u64 a = addrs[i];
			if (a == 0) continue;
			i64 val;
			u8 sz;
			if (Knows(a, val, sz)) {
				c = hashlittle(&a, 8, c);
				c = hashlittle(&val, 8, c);
				c = hashlittle(&sz, 1, c);
			}
		}

		std::array<u8, 16> regNames;
		for (int i = 0; i < 16; i++)
			regNames[i] = knownRegs[i];
		std::sort(regNames.begin(), regNames.end());
		for (int i = 0; i < 16; i++) {
			u64 a = regNames[i];
			if (a == 0) continue;
			i64 val;
			u8 sz;
			if (Knows(a, val, sz)) {
				c = hashlittle(&a, 8, c);
				c = hashlittle(&val, 8, c);
				c = hashlittle(&sz, 1, c);
			}
		}
		return c;
	}

	bool Knows(u64 address, i64 &value, u8 &size) {
		if (address < 256) {
			u8 regName = (u8)address;
			for (u32 i = 0; i < 16; i++) {
				if (knownRegs[i] == regName) {
					value = knownRegValues[i];
					size = 64;
					return true;
				}
			}
			return false;
		}
		for (u32 i = 0; i < 16; i++) {
			if (knownAddresses[i] == address) {
				value = knownValues[i];
				size = knownValueSizes[i];
				return true;
			}
		}
		return false;
	}

	void Forget(u64 address) {
		if (address < 256) {
			if (address == 0x58) {
				printf("~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!* r14 doushite\n");
			}
			u8 regName = (u8)address;
			for (u32 i = 0; i < 16; i++) {
				if (knownRegs[i] == regName) {
					knownRegs[i] = 0;
					printf("forget   %13llx\n", address);
				}
			}
			return;
		}
		for (u32 i = 0; i < 16; i++) {
			if (knownAddresses[i] == address) {
				knownAddresses[i] = 0;
				printf("forget   %13llx\n", address);
			}
		}
	}

	void Remember(u64 address, i64 value, u8 size) {
		printf("remember %13llx => %16llx\n", address, value);
		if (address < 256) {
			if (address == 0x58) {
				printf("~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!*~!* r14 tasukete\n");
			}
			u8 regName = (u8)address;
			for (u32 i = 0; i < 16; i++) {
				if (knownRegs[i] == regName) {
					knownRegValues[i] = value;
					return;
				}
			}
			// look for a free slot before going to the ring buffer
			for (u32 i = 0; i < 16; i++) {
				if (knownRegs[i] == 0) {
					knownRegs[i] = regName;
					knownRegValues[i] = value;
					return;
				}
			}
			knownRegs[knownRegIndex] = regName;
			knownRegValues[knownRegIndex] = value;
			knownRegIndex = (knownRegIndex + 1) & 15;
			return;
		}
		for (u32 i = 0; i < 16; i++) {
			if (knownAddresses[i] == address) {
				knownValues[i] = value;
				knownValueSizes[i] = size;
				return;
			}
		}
		// look for a free slot before going to the ring buffer
		for (u32 i = 0; i < 16; i++) {
			if (knownAddresses[i] == 0) {
				knownAddresses[i] = address;
				knownValues[i] = value;
				knownValueSizes[i] = size;
				return;
			}
		}
		knownAddresses[knownIndex] = address;
		knownValues[knownIndex] = value;
		knownValueSizes[knownIndex] = size;
		knownIndex = (knownIndex + 1) & 15;
	}

	static u8 RegisterAddress(xed_reg_enum_t reg) {
		if (reg >= XED_REG_AL && reg <= XED_REG_R15B) {
			reg = (xed_reg_enum_t)(XED_REG_RAX + (reg - XED_REG_AL));
		} else if (reg >= XED_REG_AX && reg <= XED_REG_R15W) {
			reg = (xed_reg_enum_t)(XED_REG_RAX + (reg - XED_REG_AX));
		} else if (reg >= XED_REG_EAX && reg <= XED_REG_R15D) {
			reg = (xed_reg_enum_t)(XED_REG_RAX + (reg - XED_REG_EAX));
		}
		return (u8)reg;
	}
};

struct Disassembler {
	vector<u8 *> m_heads; // instructions which are set to be traversed.  added by branches in the disassembled code.
	vector<FlagState> m_flagStack; // FlagStates corresponding to m_heads
	u8 *m_ip; // pointer to the current instruction in a writable buffer
	u8 *m_base; // (invalid) pointer to the start of the va space relative to m_ip
	u64 m_replacements; // number of instructions replaced
	u64 m_originalBase; // base to display decoded instructions relative to (for debugging purposes to match up with IDA)
	u8 *m_addrFlags; // 1 byte for each byte of the va space, used to mark starting addresses of instructions
	size_t m_addrFlagsSize;

	// code blocks which have already been disassembled:
	struct Block {
		u8 *head; // pointer in m_ip space
		u32 rva;
		u32 extent; // size of the block
		u32 flags;
		u32 flagStates[8];
		std::vector<u8 *> children;
		u8 *firstParent;
		FlagState prevState; // state at the start of the most recent emulation of this block
		bool prevStateValid;
	};
	std::unordered_map<u8 *, Block> m_blocks;
	Block *m_block;

	static const u8 kAddrStartInst = 1;
	static const u8 kAddrStartBlock = 2;
	static const u8 kAddrStartFunction = 4;
	static const u8 kAddrBranchTaken = 8;
	static const u8 kAddrBranchNotTaken = 16;
	static const u8 kAddrOneByteInst = 32;
	
	static const u32 kBlockExitsAssumedBranch = 1;
	static const u32 kBlockExhaustedAnalysis = 2;
	static const u32 kBlockSearchMarker = 4;

	vector<u32> rdxLeaTargets;
	vector<u32> raxLeaTargets;
	vector<u32> callRvas;

	// 0: indeterminate, 1: clear, 2: set
	FlagState m_flagState;
	static const u16 kFlagIndeterminate = 0;
	static const u16 kFlagCleared = 1;
	static const u16 kFlagSet = 2;

	void DebugDumpParents() {
		auto b = m_block;
		for (;;) {
			printf("---> via %12llx\n", 0x140000000 + (b->head - m_base));
			if (!m_blocks.count(b->firstParent)) break;
			b = &m_blocks[b->firstParent];
		}
	}

	void HandleInst() {
		char buf[1024];
		xed_decoded_inst_t inst;
		xed_decoded_inst_zero(&inst);
		xed_decoded_inst_set_mode(&inst, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
		auto err = xed_decode(&inst, m_ip, 15);
		u32 instRva = m_ip - m_base;
		m_addrFlags[instRva] |= kAddrStartInst;
		u64 rebased = m_originalBase + instRva;
		if (err != XED_ERROR_NONE) {
			printf("!!! decode error at 0x%016llx\n", rebased);
			DebugDumpParents();
			assert(false);
		}
		u32 length = xed_decoded_inst_get_length(&inst);
		if (length <= 1) {
			m_addrFlags[instRva] |= kAddrOneByteInst;
		} else {
			m_addrFlags[instRva + 1] = (u8)length;
		}
		auto cat = xed_decoded_inst_get_category(&inst);
		auto iclass = xed_decoded_inst_get_iclass(&inst);
		auto op = xed_decoded_inst_operands(&inst);
		xed_format_context(XED_SYNTAX_INTEL, &inst, buf, 1024, rebased, 0, 0);
		printf("%016llx        %s\n", rebased, buf);
		const xed_simple_flag_t *flagsInfo = xed_decoded_inst_get_rflags_info(&inst);
		FlagState fs = m_flagState;
		if (flagsInfo && (flagsInfo->may_write || flagsInfo->must_write)) {
			if (flagsInfo->written.s.cf) fs.cf = 0;
			if (flagsInfo->written.s.pf) fs.pf = 0;
			if (flagsInfo->written.s.af) fs.af = 0;
			if (flagsInfo->written.s.zf) fs.zf = 0;
			if (flagsInfo->written.s.sf) fs.sf = 0;
			if (flagsInfo->written.s.df) fs.df = 0;
			if (flagsInfo->written.s.of) fs.of = 0;
			if (flagsInfo->written.s.cf || flagsInfo->written.s.zf) fs.jbe = 0;
			if (flagsInfo->written.s.sf || flagsInfo->written.s.of) fs.jl = 0;
			if (flagsInfo->written.s.sf || flagsInfo->written.s.of || flagsInfo->written.s.zf) fs.jle = 0;
		}
		if (rebased == 0x1400243fc) {
			DebugDumpParents();
			printf("break");
		}
		if (iclass != XED_ICLASS_CMP && iclass != XED_ICLASS_TEST) {
			bool memDst = xed_decoded_inst_mem_written(&inst, 0);
			xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
			if (memDst) {
				auto baseReg = xed_decoded_inst_get_reg(&inst, XED_OPERAND_BASE0);
				if (xed_operand_values_has_memory_displacement(op)) {
					if (baseReg == XED_REG_RBP) {
						i64 disp = xed_operand_values_get_memory_displacement_int64(op);
						fs.Forget(FlagState::kAddressRbp + disp);
					} else if (baseReg == XED_REG_RSP) {
						i64 disp = xed_operand_values_get_memory_displacement_int64(op);
						fs.Forget(FlagState::kAddressRsp + disp);
					}
				}
			} else if (reg0 != XED_REG_INVALID) {
				fs.Forget(FlagState::RegisterAddress(reg0));
			}
		}
		FlagState taken = fs;
		FlagState notTaken = fs;
		bool branch = false;
		bool jmp = false;
		bool ret = false;
		bool call = false;
		switch (cat) {
		case XED_CATEGORY_COND_BR:
			branch = true;
			break;
		case XED_CATEGORY_RET:
			ret = true;
			break;
		case XED_CATEGORY_UNCOND_BR:
			jmp = true;
			break;
		case XED_CATEGORY_CALL:
			call = true;
			for (u32 i = 0; i < 16; i++) {
				switch (fs.knownRegs[i]) {
				case (u8)XED_REG_R14:
					continue;
				}
				fs.knownRegs[i] = 0;
			}
			for (u32 i = 0; i < 16; i++) {
				fs.knownAddresses[i] = 0;
			}
			break;
		}
		bool jccIsJmp = false;
		bool jccIsNop = false;
		xed_reg_enum_t reg;
		u64 imm;
		switch (iclass) {
			case XED_ICLASS_HLT: // ida won't decode past hlt, but will past int3
				*m_ip = 0xcc;
				break;

			case XED_ICLASS_MOVSX:
			case XED_ICLASS_MOVZX:
			case XED_ICLASS_MOV: {
				bool hasImm = xed_operand_values_has_immediate(op);
				bool memSrc = xed_decoded_inst_mem_read(&inst, 0);
				bool memDst = xed_decoded_inst_mem_written(&inst, 0);
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				i64 immVal;
				u8 immSz;
				u64 dstAddr = 0;
				u64 srcAddr = 0;
				if (reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					// reg to reg
					dstAddr = FlagState::RegisterAddress(reg0);
					srcAddr = FlagState::RegisterAddress(reg1);
				} else if (memDst && !hasImm && reg0 != XED_REG_INVALID) {
					// reg to mem
					srcAddr = FlagState::RegisterAddress(reg0);
					auto baseReg = xed_decoded_inst_get_reg(&inst, XED_OPERAND_BASE0);
					if (xed_operand_values_has_memory_displacement(op)) {
						if (baseReg == XED_REG_RBP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							dstAddr = FlagState::kAddressRbp + disp;
						} else if (baseReg == XED_REG_RSP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							dstAddr = FlagState::kAddressRsp + disp;
						}
					}
				} else if (memSrc && !hasImm && reg0 != XED_REG_INVALID) {
					// mem to reg
					dstAddr = FlagState::RegisterAddress(reg0);
					auto baseReg = xed_decoded_inst_get_reg(&inst, XED_OPERAND_BASE0);
					if (xed_operand_values_has_memory_displacement(op)) {
						if (baseReg == XED_REG_RBP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							srcAddr = FlagState::kAddressRbp + disp;
						} else if (baseReg == XED_REG_RSP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							srcAddr = FlagState::kAddressRsp + disp;
						}
					}
				} else if (memDst && hasImm) {
					// imm to mem
					immVal = xed_operand_values_get_immediate_int64(op);
					u8 immWidth = (u8)xed_decoded_inst_get_immediate_width_bits(&inst);
					u8 dstWidth = (u8)xed_decoded_inst_get_operand_width(&inst);
					if (dstWidth < immWidth) {
						printf("sx needed?\n");
					}
					immSz = dstWidth;
					auto baseReg = xed_decoded_inst_get_reg(&inst, XED_OPERAND_BASE0);
					if (xed_operand_values_has_memory_displacement(op)) {
						if (baseReg == XED_REG_RBP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							dstAddr = FlagState::kAddressRbp + disp;
						} else if (baseReg == XED_REG_RSP) {
							i64 disp = xed_operand_values_get_memory_displacement_int64(op);
							dstAddr = FlagState::kAddressRsp + disp;
						}
					}
				} else if (hasImm && reg0 != XED_REG_INVALID) {
					// imm to reg -- disabled
					dstAddr = FlagState::RegisterAddress(reg0);
					immVal = xed_operand_values_get_immediate_int64(op);
					u8 immWidth = (u8)xed_decoded_inst_get_immediate_width_bits(&inst);
					u8 dstWidth = (u8)xed_get_register_width_bits64(reg0);
					if (dstWidth < immWidth) {
						printf("sx needed?\n");
					}
					immSz = dstWidth;
				}
				if (!hasImm && srcAddr && dstAddr) {
					i64 regVal;
					u8 regSz;
					if (m_flagState.Knows(srcAddr, regVal, regSz)) {
						fs.Remember(dstAddr, regVal, regSz);
					} else {
						fs.Forget(dstAddr);
					}
				}
				if (hasImm && dstAddr) {
					fs.Remember(dstAddr, immVal, immSz);
				}
			} break;
			// CF=1
			case XED_ICLASS_JB:
				jccIsJmp = m_flagState.cf == kFlagSet;
				taken.cf = kFlagSet;
				notTaken.cf = kFlagCleared;
				break;
			// CF=1 or ZF=1
			case XED_ICLASS_JBE:
				jccIsJmp = m_flagState.jbe == kFlagSet ||
					(m_flagState.cf == kFlagSet || m_flagState.zf == kFlagSet);
				taken.jbe = kFlagSet;
				notTaken.jbe = kFlagCleared;
				break;
			// SF!=OF
			case XED_ICLASS_JL:
				jccIsJmp = m_flagState.jl == kFlagSet ||
					(m_flagState.sf == kFlagSet && m_flagState.of == kFlagCleared) ||
					(m_flagState.sf == kFlagCleared && m_flagState.of == kFlagSet);
				jccIsNop = m_flagState.jl == kFlagCleared ||
					(m_flagState.sf == kFlagCleared && m_flagState.of == kFlagCleared) ||
					(m_flagState.sf == kFlagSet && m_flagState.of == kFlagSet);
				taken.jl = kFlagSet;
				notTaken.jl = kFlagCleared;
				break;
			// ZF=1 or SF!=OF
			case XED_ICLASS_JLE:
				jccIsJmp = m_flagState.jle == kFlagSet ||
					m_flagState.zf == kFlagSet ||
					((m_flagState.sf == kFlagSet && m_flagState.of == kFlagCleared) ||
					(m_flagState.sf == kFlagCleared && m_flagState.of == kFlagSet));
				taken.jle = kFlagSet;
				notTaken.jle = kFlagCleared;
				break;
			// CF=0
			case XED_ICLASS_JNB:
				jccIsJmp = m_flagState.cf == kFlagCleared;
				taken.cf = kFlagCleared;
				notTaken.cf = kFlagSet;
				break;
			// CF=0 and ZF=0
			case XED_ICLASS_JNBE:
				jccIsJmp = m_flagState.jbe == kFlagCleared ||
					m_flagState.cf == kFlagCleared && m_flagState.zf == kFlagCleared;
				taken.jbe = kFlagCleared;
				notTaken.jbe = kFlagSet;
				break;
			// SF=OF
			case XED_ICLASS_JNL:
				jccIsJmp = m_flagState.jl == kFlagCleared ||
					(m_flagState.sf == kFlagSet && m_flagState.of == kFlagSet) ||
					(m_flagState.sf == kFlagCleared && m_flagState.of == kFlagCleared);
				taken.jl = kFlagCleared;
				notTaken.jl = kFlagSet;
				break;
			// ZF=0 and SF=OF
			case XED_ICLASS_JNLE:
				jccIsJmp = m_flagState.jle == kFlagCleared ||
					((m_flagState.zf == kFlagCleared) &&
					((m_flagState.sf == kFlagSet && m_flagState.of == kFlagSet) ||
					(m_flagState.sf == kFlagCleared && m_flagState.of == kFlagCleared)));
				taken.jle = kFlagCleared;
				notTaken.jle = kFlagSet;
				break;
			case XED_ICLASS_JNO:
				jccIsJmp = m_flagState.of == kFlagCleared;
				taken.of = kFlagCleared;
				notTaken.of = kFlagSet;
				break;
			case XED_ICLASS_JNP:
				jccIsJmp = m_flagState.pf == kFlagCleared;
				taken.pf = kFlagCleared;
				notTaken.pf = kFlagSet;
				break;
			case XED_ICLASS_JNS:
				jccIsJmp = m_flagState.sf == kFlagCleared;
				taken.sf = kFlagCleared;
				notTaken.sf = kFlagSet;
				break;
			case XED_ICLASS_JNZ:
				jccIsJmp = m_flagState.zf == kFlagCleared;
				taken.zf = kFlagCleared;
				notTaken.zf = kFlagSet;
				break;
			case XED_ICLASS_JO:
				jccIsJmp = m_flagState.of == kFlagSet;
				taken.of = kFlagSet;
				notTaken.of = kFlagCleared;
				break;
			case XED_ICLASS_JP:
				jccIsJmp = m_flagState.pf == kFlagSet;
				taken.pf = kFlagSet;
				notTaken.pf = kFlagCleared;
				break;
			case XED_ICLASS_JS:
				jccIsJmp = m_flagState.sf == kFlagSet;
				taken.sf = kFlagSet;
				notTaken.sf = kFlagCleared;
				break;
			case XED_ICLASS_JZ:
				jccIsJmp = m_flagState.zf == kFlagSet;
				jccIsNop = m_flagState.zf == kFlagCleared;
				taken.zf = kFlagSet;
				notTaken.zf = kFlagCleared;
				break;

			case XED_ICLASS_STC:
				fs.cf = kFlagSet;
				break;

			case XED_ICLASS_CLC:
				fs.cf = kFlagCleared;
				break;

			case XED_ICLASS_CMP: {
				bool hasImm = xed_operand_values_has_immediate(op);
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				if (!hasImm && reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					// reg to reg
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					u64 srcAddr = FlagState::RegisterAddress(reg1);
					i64 dstVal, srcVal;
					u8 dstSz, srcSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz) && m_flagState.Knows(srcAddr, srcVal, srcSz)) {
						// none of this is "right" per se but...
						fs.cf = (dstVal < srcVal) ? kFlagSet : kFlagCleared;
						fs.of = (dstVal < srcVal) ? kFlagSet : kFlagCleared;
						fs.sf = (dstVal < srcVal) ? kFlagSet : kFlagCleared;
						fs.zf = (dstVal == srcVal) ? kFlagSet : kFlagCleared;
					}
				} else if (hasImm && reg0 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					i64 immVal = xed_operand_values_get_immediate_int64(op);
					i64 dstVal;
					u8 dstSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz)) {
						fs.cf = (dstVal < immVal) ? kFlagSet : kFlagCleared;
						fs.of = (dstVal < immVal) ? kFlagSet : kFlagCleared;
						fs.sf = (dstVal < immVal) ? kFlagSet : kFlagCleared;
						fs.zf = (dstVal == immVal) ? kFlagSet : kFlagCleared;
					}
				}
			} break;

			case XED_ICLASS_ADD: {
				bool hasImm = xed_operand_values_has_immediate(op);
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				if (!hasImm && reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					u64 srcAddr = FlagState::RegisterAddress(reg1);
					i64 dstVal, srcVal;
					u8 dstSz, srcSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz) && m_flagState.Knows(srcAddr, srcVal, srcSz)) {
						fs.Remember(dstAddr, dstVal + srcVal, dstSz);
					}
				} else if (hasImm && reg0 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					i64 immVal = xed_operand_values_get_immediate_int64(op);
					i64 dstVal;
					u8 dstSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz)) {
						fs.Remember(dstAddr, dstVal + immVal, dstSz);
					}
				}
			} break;

			case XED_ICLASS_SUB: {
				bool hasImm = xed_operand_values_has_immediate(op);
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				if (!hasImm && reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					if (reg0 == reg1) {
						fs.Remember(dstAddr, 0, 64);
					} else {
						u64 srcAddr = FlagState::RegisterAddress(reg1);
						i64 dstVal, srcVal;
						u8 dstSz, srcSz;
						if (m_flagState.Knows(dstAddr, dstVal, dstSz) && m_flagState.Knows(srcAddr, srcVal, srcSz)) {
							fs.Remember(dstAddr, dstVal - srcVal, dstSz);
						}
					}
				} else if (hasImm && reg0 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					i64 immVal = xed_operand_values_get_immediate_int64(op);
					i64 dstVal;
					u8 dstSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz)) {
						fs.Remember(dstAddr, dstVal - immVal, dstSz);
					}
				}
			} break;

			case XED_ICLASS_XOR: {
				bool hasImm = xed_operand_values_has_immediate(op);
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				if (!hasImm && reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					if (reg0 == reg1) {
						fs.Remember(dstAddr, 0, 64);
					} else {
						u64 srcAddr = FlagState::RegisterAddress(reg1);
						i64 dstVal, srcVal;
						u8 dstSz, srcSz;
						if (m_flagState.Knows(dstAddr, dstVal, dstSz) && m_flagState.Knows(srcAddr, srcVal, srcSz)) {
							fs.Remember(dstAddr, dstVal ^ srcVal, dstSz);
						}
					}
				} else if (hasImm && reg0 != XED_REG_INVALID) {
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					i64 immVal = xed_operand_values_get_immediate_int64(op);
					i64 dstVal;
					u8 dstSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz)) {
						fs.Remember(dstAddr, dstVal ^ immVal, dstSz);
					}
				}
			} 
				fs.cf = kFlagCleared;
				fs.of = kFlagCleared;
				break;

			case XED_ICLASS_TEST: {
				xed_reg_enum_t reg0 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
				xed_reg_enum_t reg1 = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG1);
				if (reg0 != XED_REG_INVALID && reg1 != XED_REG_INVALID) {
					// reg to reg
					u64 dstAddr = FlagState::RegisterAddress(reg0);
					u64 srcAddr = FlagState::RegisterAddress(reg1);
					i64 dstVal, srcVal;
					u8 dstSz, srcSz;
					if (m_flagState.Knows(dstAddr, dstVal, dstSz) && m_flagState.Knows(srcAddr, srcVal, srcSz)) {
						fs.zf = ((dstVal & srcVal) == 0) ? kFlagSet : kFlagCleared;
					}
				}
			} // fall through:
			case XED_ICLASS_AND:
			case XED_ICLASS_OR:
				fs.cf = kFlagCleared;
				fs.of = kFlagCleared;
				break;

			case XED_ICLASS_SAR:
			case XED_ICLASS_SHL:
			case XED_ICLASS_SHR:
				// flags unaffected when imm is 0
				if (!xed_operand_is_register(xed_operand_name(xed_inst_operand(xed_decoded_inst_inst(&inst), 1)))) {
					imm = xed_decoded_inst_get_unsigned_immediate(&inst);
					if (imm == 0) {
						// we cleared this above; just undo that
						fs = m_flagState;
					}
				}
				break;

			case XED_ICLASS_LEA:
				auto reg = xed_operand_values_get_base_reg(op, 0);
				if (reg == XED_REG_RIP) {
					auto target = m_ip + length + xed_operand_values_get_memory_displacement_int64(op);
					auto targetRva = (u32)(target - m_base);
					auto dstReg = xed_decoded_inst_get_reg(&inst, XED_OPERAND_REG0);
					if (dstReg == XED_REG_RDX) {
						rdxLeaTargets.push_back(targetRva);
					} else if (dstReg == XED_REG_RAX) {
						raxLeaTargets.push_back(targetRva);
					}
					printf("%lx\n", targetRva);
				}
				break;
		}
		int disp = xed_decoded_inst_get_branch_displacement(&inst);
		if (jccIsJmp && disp < 0 && disp > -16) {
			// when we jump backwards into already-executed code,
			// we will nop out the first N bytes and restart from
			// the previous instruction (e.g. test edi, imm32)
			u8 *jumpTarget = m_ip + length + disp;
			u8 *lastIp = m_ip - 1;
			for (;;) {
				// if the byte before is start inst but not one byte inst, then curr isn't an inst, it's a length
				// (if length is 2 then it's 01 02 01 and this is still okay)
				u8 prevFlag = m_addrFlags[lastIp - m_base - 1];
				if (!((prevFlag & kAddrStartInst) && !(prevFlag & kAddrOneByteInst))) {
					u8 currFlag = m_addrFlags[lastIp - m_base];
					if ((currFlag & kAddrStartInst)) {
						if (lastIp <= jumpTarget) {
							break;
						}
					}
				}
				lastIp--;
			}
			// we should be jumping backwards into a *different* instruction
			assert(lastIp != jumpTarget);
			u32 nopSize = jumpTarget - lastIp;
			memset(lastIp, 0x90, nopSize);
			// change the next instruction(s) from jcc to jmp
			// if we loop back over that instruction the flags will become indeterminate,
			// and we won't be able to resolve that it should be a jmp then.
			u8 *jccIp = lastIp + nopSize;
			while (*jccIp == 0x90) jccIp++;
			while (*jccIp == *m_ip) {
				*jccIp = 0xeb;
				jccIp += 2 + jccIp[1];
			}
			memset(&m_addrFlags[lastIp - m_base], kAddrOneByteInst | kAddrStartInst, nopSize);
			m_block->extent -= m_ip - lastIp;
			Branch(lastIp, fs);
			m_ip = 0;
			m_replacements++;
			return;
		}
		const static u8 branchesTaken = kAddrBranchNotTaken | kAddrBranchTaken;
		if (jccIsJmp) {
			// jcc rel8 -> jmp rel8
			// assert(*m_ip != 0xf);
			// *m_ip = 0xeb;
			jmp = true;
			fs = taken;
			m_replacements++;
			m_addrFlags[m_ip - m_base] |= kAddrBranchTaken;
			if ((m_addrFlags[m_ip - m_base] & branchesTaken) == branchesTaken) {
				m_block->flags &= ~kBlockExitsAssumedBranch;
			} else {
				m_block->flags |= kBlockExitsAssumedBranch;
			}
		} else if (jccIsNop) {
			// memset(m_ip, 0x90, length);
			branch = false;
			m_replacements++;
			m_addrFlags[m_ip - m_base] |= kAddrBranchNotTaken;
			if ((m_addrFlags[m_ip - m_base] & branchesTaken) == branchesTaken) {
				m_block->flags &= ~kBlockExitsAssumedBranch;
			} else {
				m_block->flags |= kBlockExitsAssumedBranch;
			}
		} else if (branch) {
			m_addrFlags[m_ip - m_base] |= branchesTaken;
			m_block->flags &= ~kBlockExitsAssumedBranch;
		}
		m_ip += length;
		m_block->extent = m_ip - m_block->head;
		m_flagState = fs;
		if (call) {
			if (xed_operand_values_has_branch_displacement(op)) {
				auto target = m_ip + disp;
				auto targetRva = (u32)(target - m_base);
				callRvas.push_back(targetRva);
			}
		}
		if (ret) {
			m_ip = 0;
		} else if (jmp) {
			Branch(m_ip + disp, fs);
			m_ip = 0;
		} else if (branch) {
			Branch(m_ip, notTaken);
			Branch(m_ip + disp, taken);
			m_ip = 0;
		}
	}

	void Replace() {
		u8 branch = kAddrBranchTaken | kAddrBranchNotTaken;
		for (size_t i = 0; i < m_addrFlagsSize; i++) {
			u8 f = m_addrFlags[i];
			u8 *ip = m_base + i;
			if (f & kAddrStartInst) {
				u8 fb = f & branch;
				u32 length = 1;
				if (!(f & kAddrOneByteInst)) {
					length = m_addrFlags[i + 1];
					i += length - 1;
				}
				if (fb == kAddrBranchNotTaken) {
					// jcc => nop
					memset(ip, 0x90, length);
				} else if (fb == kAddrBranchTaken) {
					if((*ip & 0xf0) == 0x70)
						*ip = 0xeb;
					else
						printf("!!! not replacing far jmp !!!\n");
				}
			}
		}
	}

	void Branch(u8 *ip, FlagState fs) {
		bool newBlock = true;
		u32 branchHash = fs.Hash();
		if (m_blocks.count(ip)) {
			newBlock = false;
		} else for (auto &pair : m_blocks) {
			auto &block = pair.second;
			u8 *b = block.head;
			u32 be = block.extent;
			if (b <= ip && b + be > ip) {
				// we are branching into an existing block
				// don't make a new head, but before we quit, split the block
				block.extent = ip - b;
				auto b2 = AddBlock(ip, b + be - ip);
				b2->children = block.children;
				b2->flags = block.flags;
				b2->firstParent = b;
				block.children.clear();
				block.children.push_back(ip);
				newBlock = false;
				break;
			}
		}
		// add a new head and a new block to track it
		if (newBlock) {
			m_heads.push_back(ip);
			m_flagStack.push_back(fs);
			auto b = AddBlock(ip);
			b->flagStates[0] = branchHash;
			b->firstParent = m_block->head;
		} else {
			auto &b = m_blocks[ip];
			u32 blockFlags = BlockFlagsWithChildren(b);
			if (true || (blockFlags & kBlockExitsAssumedBranch)) {
				bool stateIsDifferent = true;
				int freeIdx = 8;
				for (int i = 0; i < 8; i++) {
					if (b.flagStates[i] == branchHash) {
						stateIsDifferent = false;
					}
					if (b.flagStates[i] == 0) {
						freeIdx = i;
						break;
					}
				}
				if (stateIsDifferent) {
					if (freeIdx == 8) {
						b.flags |= kBlockExhaustedAnalysis;
					}
					if (b.flags & kBlockExhaustedAnalysis) {
						b.flags &= ~kBlockExitsAssumedBranch;
						u32 rva = b.head - m_base;
						for (u32 i = 0; i < b.extent; i++) {
							m_addrFlags[rva + i] &= ~(kAddrBranchNotTaken | kAddrBranchTaken);
							if (!(m_addrFlags[rva + i] & kAddrOneByteInst)) {
								i += m_addrFlags[rva + i + 1] - 1;
							}
						}
					} else {
						b.flagStates[freeIdx] = branchHash;
						m_heads.push_back(ip);
						m_flagStack.push_back(fs);
					}
				}
			}
		}
		{
			auto b = m_block->children.begin();
			auto e = m_block->children.end();
			if (std::find(b, e, ip) == e)
				m_block->children.push_back(ip);
		}
		return;
	}

	u32 BlockFlagsWithChildrenExplore(Block &head) {
		// in b4 stack overflow
		u32 res = head.flags;
		head.flags |= kBlockSearchMarker;
		for (auto ci : head.children) {
			auto &c = m_blocks[ci];
			if (!(c.flags & kBlockSearchMarker)) {
				res |= BlockFlagsWithChildrenExplore(c);
			}
		}
		return res;
	}

	void BlockFlagsWithChildrenUnmark(Block &head) {
		for (auto &b : m_blocks) {
			b.second.flags &= ~kBlockSearchMarker;
		}
	}

	u32 BlockFlagsWithChildren(Block &head) {
		u32 res = BlockFlagsWithChildrenExplore(head);
		BlockFlagsWithChildrenUnmark(head);
		return res;
	}

	// startIp: the first function to disassemble
	// rvaStart: the RVA corresponding to startIp
	// originalBase: base address to rebase displayed addresses to (for matching up to IDA)
	// vaSpaceFlatSize: the extent of the mapped va space of the original exe
	void Init(u8 *startIp, u32 rvaStart, u64 originalBase, size_t vaSpaceFlatSize) {
		memset(&m_flagState, 0, sizeof(m_flagState));
		m_heads.reserve(256);
		m_flagStack.reserve(256);
		m_blocks.reserve(256);
		m_block = nullptr;
		m_base = startIp - rvaStart;
		m_replacements = 0;
		m_originalBase = originalBase;
		m_addrFlags = new u8[vaSpaceFlatSize];
		m_addrFlagsSize = vaSpaceFlatSize;
		memset(m_addrFlags, 0, vaSpaceFlatSize);
		AddFunction(startIp);
	}

	void AddFunction(u8 *ip) {
		m_block = AddBlock(ip, 0);
		m_block->prevStateValid = true;
		m_ip = ip;
		m_addrFlags[ip - m_base] |= kAddrStartFunction;
		memset(&m_flagState, 0, sizeof(m_flagState));
	}

	Block *AddBlock(u8 *ip, u32 size = 0) {
		m_blocks[ip] = Block{};
		auto &b = m_blocks[ip];
		b.head = ip;
		m_addrFlags[ip - m_base] |= kAddrStartBlock;
		return &b;
	}

	void Run() {
		// TODO: make this less braindead
		do {
			while (m_ip) {
				u8 *ip = m_ip;
				HandleInst();
			}

			if (m_heads.size()) {
				m_ip = m_heads.back();
				m_flagState = m_flagStack.back();
				m_heads.pop_back();
				m_flagStack.pop_back();
				// set m_blockIndex according to m_ip:
				m_block = &m_blocks[m_ip];
				if (m_block->prevStateValid) {
					MergeFlagState(m_block->prevState);
				}
				m_block->prevState = m_flagState;
				m_block->prevStateValid = true;
			}
		} while (m_ip);
	}

	void MergeFlagState(FlagState &fs) {
		if (m_flagState.cf != fs.cf) m_flagState.cf = kFlagIndeterminate;
		if (m_flagState.pf != fs.pf) m_flagState.pf = kFlagIndeterminate;
		if (m_flagState.af != fs.af) m_flagState.af = kFlagIndeterminate;
		if (m_flagState.zf != fs.zf) m_flagState.zf = kFlagIndeterminate;
		if (m_flagState.sf != fs.sf) m_flagState.sf = kFlagIndeterminate;
		if (m_flagState.df != fs.df) m_flagState.df = kFlagIndeterminate;
		if (m_flagState.of != fs.of) m_flagState.of = kFlagIndeterminate;
		if (m_flagState.jbe != fs.jbe) m_flagState.jbe = kFlagIndeterminate;
		if (m_flagState.jl != fs.jl) m_flagState.jl = kFlagIndeterminate;
		if (m_flagState.jle != fs.jle) m_flagState.jle = kFlagIndeterminate;
		for (u32 i = 0; i < 64; i++) {
			u64 addr = 0;
			if (i < 16)      addr = m_flagState.knownAddresses[i&15];
			else if (i < 32) addr =          fs.knownAddresses[i&15];
			else if (i < 48) addr = m_flagState.knownRegs[i&15];
			else             addr =          fs.knownRegs[i&15];
			if (addr == 0) continue;
			i64 aVal, bVal;
			u8 aSz, bSz;
			bool aKnows = m_flagState.Knows(addr, aVal, aSz);
			bool bKnows = fs.Knows(addr, bVal, bSz);
			if (aKnows && bKnows && aVal == bVal) continue;
			m_flagState.Forget(addr);
		}
	}
};

void Decrypt(PEReader *pe, u8 *baseAddr) {
	auto &tlsDir = pe->GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	auto tlsData = (IMAGE_TLS_DIRECTORY *)(baseAddr + tlsDir.VirtualAddress);
	u8 *cb0 = *(u8 **)(tlsData->AddressOfCallBacks);

	u32 textSize;
	u8 *textPtr = pe->GetSectionPointer(".text", 0, &textSize);
	// Garbage sequences:
	// shl Xh, 0: flags unaffected
	// and Xh, 0ffh: cf <- 0, of <- 0
	// jnb (cf: 0)
	// jno (of: 0)
	// stc; mov Xh, Xh
	// jbe (cf:1 or zf:1)
	// clc; mov Xh, Xh
	// jnb (cf:0)
	//
	// jump targets may have a mov nop, and may have a Jcc of the same variety

	xed_tables_init();
	Disassembler dis;
	u32 cb0Rva = (u32)(cb0 - baseAddr);
	u8 *ip = pe->TranslateRVA(cb0Rva);
	dis.Init(ip, cb0Rva, 0x140000000, pe->GetMaxRVA());
	dis.Run();
	for (auto target : dis.raxLeaTargets) {
		if (target < 0x10000) {
			u8 *next = pe->TranslateRVA(target);
			dis.AddFunction(next);
			dis.Run();
			break;
		}
	}
	if (dis.callRvas.size() > 0) {
		u8 *next = pe->TranslateRVA(dis.callRvas[0]);
		dis.AddFunction(next);
		dis.Run();
	}
	dis.Replace();
	printf("Replaced jcc with jmp %lld times\n", dis.m_replacements);

	u8 *dataPtr = pe->GetSectionPointer(".data", 0, 0);
	u8 *padBuf = nullptr;

	// The following stuff is old and broken:
#if 0
	// Rebuild the import table:
	auto &importDir = pe->GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	u32 iatRva = importDir.Size;
	u8 *iatRvaDst = (u8 *)&iatRva;
	u32 *iatSize = (u32 *)&importDir.Size;
	u32 padIdx = 0;
	for (int i = 0; i < 4; i++) {
		iatRvaDst[i] ^= padBuf[padIdx++ & 0xff];
	}
	importDir.VirtualAddress = iatRva;
	*iatSize = 0x14;
	ImageImport *iid = (ImageImport *)(pe->TranslateRVA(iatRva));
	while (iid->OriginalFirstThunk) {
		u8 *iidDst = (u8 *)iid;
		for (int i = 0; i < 0x14; i++)
			iidDst[i] = iidDst[i] ^ padBuf[padIdx++ & 0xff];
		u8 *nameDst = (u8 *)(pe->TranslateRVA(iid->Name));
		for (int i = 0;; i++) {
			char c = nameDst[i] ^ padBuf[padIdx & 0xff];
			nameDst[i] = c;
			if (!c)
				break;
			padIdx++;
		}
		char *name = (char *)nameDst;
		uptr *oft = (uptr *)(pe->TranslateRVA(iid->OriginalFirstThunk));
		uptr *ft = (uptr *)(pe->TranslateRVA(iid->FirstThunk));
		while (*oft) {
			u8 *oftDst = (u8 *)oft;
			for (int i = 0; i < 8; i++)
				oftDst[i] = oftDst[i] ^ padBuf[padIdx++ & 0xff];
			uptr ordinal = *oft;
			if (ordinal & 0x8000000000000000) {
				// Note: ida handles ordinals just fine, so maybe we don't care
				u32 ord = (u32)(ordinal & 0x7fffffff);
				Print("## Not translating ordinal %x of lib %s\n", ord, name);
			}
			else {
				char *procDst = (char *)(pe->TranslateRVA(0x7fffffff & *oft) + 2);
				for (int i = 0;; i++) {
					char c = procDst[i] ^ padBuf[padIdx & 0xff];
					procDst[i] = c;
					if (!c)
						break;
					padIdx++;
				}
			}
			*ft = *oft;
			oft++;
			ft++;
		}
		iid++;
		*iatSize += 0x14;
	}

	// Decrypt .text section:
	u32 textSize;
	u8 *textPtr = pe->GetSectionPointer(".text", 0, &textSize);
	padIdx = 0;
	for (u32 i = 0; i < textSize; i += 0x1000) {
		u32 pageI = i >> 12;
		i64 hash = pageI;
		_mul128(hash, 0x469EE58469EE5847, &hash);
		u32 blockIdx = pageI - (0x1d * (hash >> 3));
		u8 *pagePad = padBuf + (0x100 * blockIdx);
		u32 pageLen = 0x1000;
		if (i + pageLen > textSize) pageLen = textSize - i;
		for (u32 j = 0; j < pageLen; j++) {
			textPtr[j + i] = textPtr[j + i] ^ pagePad[j & 0xff];
		}
	}

	// Decrypt xor-crypted strings in .data
	// test dword ptr cs:blah, 0ffffffh
	// f7 05 ?? ?? ?? ?? ff ff ff 00
	//       ^ rip-relative pointer to EncryptedString.len
	struct EncryptedString {
		u8 key[8];
		u8 len[3];
		u8 encrypted;
		char data[1];
	};
	int stringCount = 0;
	for (u32 i = 0; i < textSize; i++) {
		u8 *t = textPtr + i;
		if (t[0] != 0xf7) continue;
		if (t[1] != 5) continue;
		if (t[6] != 0xff) continue;
		if (t[7] != 0xff) continue;
		if (t[8] != 0xff) continue;
		if (t[9] != 0) continue;
		// assuming .text rva is 0x1000
		i32 offs = (i32)t[2] | (t[3] << 8) | (t[4] << 16) | (t[5] << 24);
		u32 rva = (u32)(offs + (0x1000 + i) + 10);
		auto &str = *(EncryptedString *)(pe->TranslateRVA(rva - 8));
		if (str.encrypted) {
			u32 len = (u32)str.len[0] | (str.len[1] << 8) | (str.len[2] << 16);
			for (int j = 0; j < len; j++) {
				str.data[j] = str.data[j] ^ str.key[j & 7];
			}
			str.encrypted = 0;
			stringCount++;
		}
	}
	printf("Decrypted %d strings\n", stringCount);
#endif

	// TODO: fix garbage code sequences from the decrypted .text section

#if PATCH_TO_RUN
	for (u32 i = 0; i < textSize; i++) {
		u8 *t = textPtr + i;
		if (t[0] != 0xff) continue;
		if (t[1] != 0x15) continue;
		if (t[6] != 0x85) continue;
		if (t[7] != 0xc0) continue;
		if (t[8] != 0x74) continue;
		if (t[9] != 0x29) continue;
		if (t[10] != 0x48) continue;
		if (t[11] != 0x8d) continue;
		t[8] = 0x75;
		printf("Patched IsDebuggerPresent\n");
	}
	for (u32 i = 0; i < textSize; i++) {
		u8 *t = textPtr + i;
		if (t[0] != 0x0f) continue;
		if (t[1] != 0x0b) continue;
		if (t[2] != 0xeb) continue;
		if (t[3] != 0x00) continue;
		if (t[4] != 0x48) continue;
		t[0] = 0x66;
		t[1] = 0x90;
		printf("Patched page crc generation\n");
	}
	const static u8 nsit1[] = {
		0x45, 0x33, 0xc9,
		0x45, 0x33, 0xc0,
		0x41, 0x8d, 0x51, 0x11,
		0x49, 0x8d, 0x49, 0xfe,
		0xff, 0xd0
	};
	const static u8 nsit2[] = {
		0x45, 0x33, 0xc9,
		0x45, 0x33, 0xc0,
		0x41, 0x8d, 0x51, 0x11,
		0xff, 0xd0
	};
	const static u8 nsit3[] = {
		0x45, 0x33, 0xc9,
		0x45, 0x33, 0xc0,
		0x41, 0x8d, 0x51, 0x11,
		0x49, 0x8b, 0xcc,
		0xff, 0xd0
	};
	for (u32 i = 0; i < textSize; i++) {
		u8 *t = textPtr + i;
		if (!memcmp(t, nsit1, sizeof(nsit1))) {
			t[sizeof(nsit1) - 2] = 0x90;
			t[sizeof(nsit1) - 1] = 0x90;
			printf("Patched NtSetInformationThread #1\n");
		}
		else if (!memcmp(t, nsit2, sizeof(nsit2))) {
			t[sizeof(nsit2) - 2] = 0x90;
			t[sizeof(nsit2) - 1] = 0x90;
			printf("Patched NtSetInformationThread #2\n");
		}
		else if (!memcmp(t, nsit3, sizeof(nsit3))) {
			t[sizeof(nsit3) - 2] = 0x90;
			t[sizeof(nsit3) - 1] = 0x90;
			printf("Patched NtSetInformationThread #3\n");
		}
	}

	auto &tlsDir = pe->GetNtHeader()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	tlsDir.VirtualAddress = 0;
	tlsDir.Size = 0;
	printf("Destroyed TLS directory\n");
#endif
}

int main(int argc, const char **argv) {
	if (argc < 2) {
		Print("Usage: %s <path to xxxx.exe>\n", argv[0]);
		return 0;
	}
	auto exeFile = fopen(argv[1], "rb");
	fseek(exeFile, 0, SEEK_END);
	u32 size = ftell(exeFile);
	u8 *exeBuf = new u8[0x1000 + size];
	u8 *exeData = (u8 *)((u64)exeBuf + 0xfff & (-0x1000));
	fseek(exeFile, 0, SEEK_SET);
	fread(exeData, size, 1, exeFile);
	fclose(exeFile);
	auto reader = PEReader{exeData};
	HMODULE hmod = LoadLibraryEx(argv[1], NULL, 0);
	u8 *baseAddr = (u8 *)((uptr)-8 & (uptr)hmod);
	Decrypt(&reader, baseAddr);
	auto outFile = fopen("xxx-64.decrypted.exe", "wb");
	fwrite(exeData, size, 1, outFile);
	fclose(outFile);
	return 0;
}