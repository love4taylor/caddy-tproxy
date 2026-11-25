//go:build !purego

#include "textflag.h"

// cpu.X86.HasAVX2 is checked first and includes OS support for the YMM state.
TEXT ·cpuHasVAES(SB), NOSPLIT, $0-1
	MOVL $7, AX
	XORL CX, CX
	CPUID
	SHRL $9, CX
	ANDL $1, CX
	MOVB CL, ret+0(FP)
	RET

// AES-256 alternates a rotated SubWord (with Rcon) and a plain SubWord.
#define EXPAND_HALF(dst, shuffle, offset) \
	PSHUFD $shuffle, X2, X2; \
	MOVAPS dst, X3; \
	PSLLO $4, X3; \
	PXOR X3, dst; \
	PSLLO $4, X3; \
	PXOR X3, dst; \
	PSLLO $4, X3; \
	PXOR X3, dst; \
	PXOR X2, dst; \
	MOVUPS dst, offset(DI)

#define EXPAND_PAIR(rcon, first, second) \
	AESKEYGENASSIST $rcon, X1, X2; \
	EXPAND_HALF(X0, 0xff, first); \
	AESKEYGENASSIST $0, X0, X2; \
	EXPAND_HALF(X1, 0xaa, second)

TEXT ·expandAES256(SB), NOSPLIT, $0-16
	MOVQ key+0(FP), SI
	MOVQ rounds+8(FP), DI
	MOVUPS (SI), X0
	MOVUPS 16(SI), X1
	MOVUPS X0, (DI)
	MOVUPS X1, 16(DI)
	EXPAND_PAIR(0x01, 32, 48)
	EXPAND_PAIR(0x02, 64, 80)
	EXPAND_PAIR(0x04, 96, 112)
	EXPAND_PAIR(0x08, 128, 144)
	EXPAND_PAIR(0x10, 160, 176)
	EXPAND_PAIR(0x20, 192, 208)
	AESKEYGENASSIST $0x40, X1, X2
	EXPAND_HALF(X0, 0xff, 224)
	RET

// Reverse the schedule in place and apply InvMixColumns to interior keys.
TEXT ·invertAES256(SB), NOSPLIT, $0-8
	MOVQ rounds+0(FP), SI
	LEAQ 224(SI), DI
	MOVUPS (SI), X0
	MOVUPS (DI), X1
	MOVUPS X0, (DI)
	MOVUPS X1, (SI)
invert:
	ADDQ $16, SI
	SUBQ $16, DI
	MOVUPS (SI), X0
	MOVUPS (DI), X1
	AESIMC X0, X0
	AESIMC X1, X1
	MOVUPS X0, (DI)
	MOVUPS X1, (SI)
	CMPQ SI, DI
	JNE invert
	RET

DATA reverseQwords<>+0(SB)/8, $0x0001020304050607
DATA reverseQwords<>+8(SB)/8, $0x08090a0b0c0d0e0f
GLOBL reverseQwords<>(SB), RODATA|NOPTR, $16

DATA counterStep<>+8(SB)/8, $2
GLOBL counterStep<>(SB), RODATA|NOPTR, $16

// Each YMM register carries two AES blocks. Keep eight independent vectors in
// flight and broadcast each round key to both lanes.
#define ROUND(op, key, pos, register) \
	VBROADCASTI128 pos(key), Y8; \
	op Y8, Y0, Y0; \
	op Y8, Y1, Y1; \
	op Y8, Y2, Y2; \
	op Y8, Y3, Y3; \
	op Y8, Y4, Y4; \
	op Y8, Y5, Y5; \
	op Y8, Y6, Y6; \
	op Y8, Y7, Y7

#define ROUNDS(round, xor, op, last, key) \
	round(xor, key, 0, Z16); \
	round(op, key, 16, Z17); \
	round(op, key, 32, Z18); \
	round(op, key, 48, Z19); \
	round(op, key, 64, Z20); \
	round(op, key, 80, Z21); \
	round(op, key, 96, Z22); \
	round(op, key, 112, Z23); \
	round(op, key, 128, Z24); \
	round(op, key, 144, Z25); \
	round(op, key, 160, Z26); \
	round(op, key, 176, Z27); \
	round(op, key, 192, Z28); \
	round(op, key, 208, Z29); \
	round(last, key, 224, Z30)

#define NEXT_COUNTER(dst) \
	VPSHUFB Y10, Y9, dst; \
	VPADDQ Y11, Y9, Y9

#define XOR_STORE(src, dst, vector, offset) \
	VPXOR offset(src), vector, vector; \
	VMOVDQU vector, offset(dst)

// size is a positive multiple of 256. The caller excludes counter carry.
TEXT ·xorVAESCTR(SB), NOSPLIT, $0-40
	MOVQ rounds+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ size+24(FP), CX
	MOVQ counters+32(FP), DX
	VMOVDQU (DX), Y9
	VBROADCASTI128 reverseQwords<>(SB), Y10
	VBROADCASTI128 counterStep<>(SB), Y11
ctr:
	NEXT_COUNTER(Y0)
	NEXT_COUNTER(Y1)
	NEXT_COUNTER(Y2)
	NEXT_COUNTER(Y3)
	NEXT_COUNTER(Y4)
	NEXT_COUNTER(Y5)
	NEXT_COUNTER(Y6)
	NEXT_COUNTER(Y7)
	ROUNDS(ROUND, VPXOR, VAESENC, VAESENCLAST, AX)
	XOR_STORE(SI, DI, Y0, 0)
	XOR_STORE(SI, DI, Y1, 32)
	XOR_STORE(SI, DI, Y2, 64)
	XOR_STORE(SI, DI, Y3, 96)
	XOR_STORE(SI, DI, Y4, 128)
	XOR_STORE(SI, DI, Y5, 160)
	XOR_STORE(SI, DI, Y6, 192)
	XOR_STORE(SI, DI, Y7, 224)
	ADDQ $256, SI
	ADDQ $256, DI
	SUBQ $256, CX
	JNZ ctr
	VZEROUPPER
	RET

#define CBC_STORE(vector, previous, output) \
	VPXOR previous(SI), vector, vector; \
	VMOVDQU vector, output(DI)

// Store in reverse order within each batch so in-place decryption continues
// to see the original ciphertext. Preserve the final ciphertext for the IV.
TEXT ·decryptVAESCBC(SB), NOSPLIT, $0-40
	MOVQ rounds+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ size+24(FP), CX
	MOVQ iv+32(FP), DX
	VMOVDQU (DX), X10
cbc:
	VINSERTI128 $1, (SI), Y10, Y10
	VMOVDQU 240(SI), X11
	VMOVDQU (SI), Y0
	VMOVDQU 32(SI), Y1
	VMOVDQU 64(SI), Y2
	VMOVDQU 96(SI), Y3
	VMOVDQU 128(SI), Y4
	VMOVDQU 160(SI), Y5
	VMOVDQU 192(SI), Y6
	VMOVDQU 224(SI), Y7
	ROUNDS(ROUND, VPXOR, VAESDEC, VAESDECLAST, AX)
	CBC_STORE(Y7, 208, 224)
	CBC_STORE(Y6, 176, 192)
	CBC_STORE(Y5, 144, 160)
	CBC_STORE(Y4, 112, 128)
	CBC_STORE(Y3, 80, 96)
	CBC_STORE(Y2, 48, 64)
	CBC_STORE(Y1, 16, 32)
	VPXOR Y10, Y0, Y0
	VMOVDQU Y0, (DI)
	VMOVDQA X11, X10
	ADDQ $256, SI
	ADDQ $256, DI
	SUBQ $256, CX
	JNZ cbc
	VMOVDQU X10, (DX)
	VZEROUPPER
	RET

DATA counterLanes512<>+24(SB)/8, $1
DATA counterLanes512<>+40(SB)/8, $2
DATA counterLanes512<>+56(SB)/8, $3
GLOBL counterLanes512<>(SB), RODATA|NOPTR, $64

DATA counterStep512<>+8(SB)/8, $4
GLOBL counterStep512<>(SB), RODATA|NOPTR, $16

// Broadcast each round key once per call. Four ZMM registers then hold the
// same sixteen AES blocks as a YMM batch without reloading round keys.
#define BROADCAST_ROUND512(load, key, pos, register) \
	load pos(key), register

#define LOAD_ROUNDS512(key) \
	ROUNDS(BROADCAST_ROUND512, VBROADCASTI32X4, VBROADCASTI32X4, VBROADCASTI32X4, key)

#define ROUND512(op, key, pos, register) \
	op register, Z0, Z0; \
	op register, Z1, Z1; \
	op register, Z2, Z2; \
	op register, Z3, Z3

#define ROUND512_SINGLE(op, key, pos, register) \
	op register, Z0, Z0

#define XOR_STORE512(vector, offset) \
	VPXORQ offset(SI), vector, vector; \
	VMOVDQU64 vector, offset(DI)

// size is a positive multiple of 256. The caller excludes counter carry.
TEXT ·xorVAESCTR512(SB), NOSPLIT, $0-40
	MOVQ rounds+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ size+24(FP), CX
	MOVQ counters+32(FP), DX
	VBROADCASTI32X4 (DX), Z9
	VPADDQ counterLanes512<>(SB), Z9, Z9
	VBROADCASTI32X4 reverseQwords<>(SB), Z10
	VBROADCASTI32X4 counterStep512<>(SB), Z11
	VPADDQ Z11, Z11, Z12
	VPADDQ Z11, Z12, Z13
	VPADDQ Z12, Z12, Z14
	LOAD_ROUNDS512(AX)
ctr512:
	// Form all four counter vectors from the same base counter.
	VPADDQ Z11, Z9, Z1
	VPADDQ Z12, Z9, Z2
	VPADDQ Z13, Z9, Z3
	VPSHUFB Z10, Z9, Z0
	VPSHUFB Z10, Z1, Z1
	VPSHUFB Z10, Z2, Z2
	VPSHUFB Z10, Z3, Z3
	VPADDQ Z14, Z9, Z9
	ROUNDS(ROUND512, VPXORQ, VAESENC, VAESENCLAST, AX)
	XOR_STORE512(Z0, 0)
	XOR_STORE512(Z1, 64)
	XOR_STORE512(Z2, 128)
	XOR_STORE512(Z3, 192)
	ADDQ $256, SI
	ADDQ $256, DI
	SUBQ $256, CX
	JNZ ctr512
	VZEROUPPER
	RET

// size is a positive multiple of 64.
TEXT ·decryptVAESCBC512(SB), NOSPLIT, $0-40
	MOVQ rounds+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ size+24(FP), CX
	MOVQ iv+32(FP), DX
	VPXORQ Z10, Z10, Z10
	VINSERTI32X4 $3, (DX), Z10, Z10
	LOAD_ROUNDS512(AX)
	CMPQ CX, $256
	JB cbc512tail
cbc512:
	VMOVDQU64 (SI), Z0
	VMOVDQU64 64(SI), Z1
	VMOVDQU64 128(SI), Z2
	VMOVDQU64 192(SI), Z3
	// Save the preceding ciphertext for each block before any in-place stores.
	VALIGNQ $6, Z10, Z0, Z11
	VALIGNQ $6, Z0, Z1, Z12
	VALIGNQ $6, Z1, Z2, Z13
	VALIGNQ $6, Z2, Z3, Z14
	VMOVDQA64 Z3, Z10
	ROUNDS(ROUND512, VPXORQ, VAESDEC, VAESDECLAST, AX)
	VPXORQ Z11, Z0, Z0
	VPXORQ Z12, Z1, Z1
	VPXORQ Z13, Z2, Z2
	VPXORQ Z14, Z3, Z3
	VMOVDQU64 Z0, (DI)
	VMOVDQU64 Z1, 64(DI)
	VMOVDQU64 Z2, 128(DI)
	VMOVDQU64 Z3, 192(DI)
	ADDQ $256, SI
	ADDQ $256, DI
	SUBQ $256, CX
	CMPQ CX, $256
	JAE cbc512
cbc512tail:
	TESTQ CX, CX
	JE cbc512done
cbc512group:
	VMOVDQU64 (SI), Z0
	VALIGNQ $6, Z10, Z0, Z11
	VMOVDQA64 Z0, Z10
	ROUNDS(ROUND512_SINGLE, VPXORQ, VAESDEC, VAESDECLAST, AX)
	VPXORQ Z11, Z0, Z0
	VMOVDQU64 Z0, (DI)
	ADDQ $64, SI
	ADDQ $64, DI
	SUBQ $64, CX
	JNZ cbc512group
cbc512done:
	VEXTRACTI32X4 $3, Z10, (DX)
	VZEROUPPER
	RET
