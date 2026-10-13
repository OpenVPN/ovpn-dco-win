OPTION	DOTNAME
.text$	SEGMENT ALIGN(256) 'CODE'

EXTERN	OPENSSL_ia32cap_P:NEAR

PUBLIC	poly1305_init

PUBLIC	poly1305_blocks

PUBLIC	poly1305_emit



ALIGN	32
poly1305_init	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_init::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	xor	rax,rax
	mov	QWORD PTR[rdi],rax
	mov	QWORD PTR[8+rdi],rax
	mov	QWORD PTR[16+rdi],rax

	cmp	rsi,0
	je	$L$no_key

	mov	rax,00ffffffc0fffffffh
	lea	rcx,QWORD PTR[((-3))+rax]
	and	rax,QWORD PTR[rsi]
	and	rcx,QWORD PTR[8+rsi]
	mov	QWORD PTR[24+rdi],rax
	mov	QWORD PTR[32+rdi],rcx
	mov	DWORD PTR[48+rdi],-1
	lea	r10,QWORD PTR[poly1305_blocks]
	lea	r11,QWORD PTR[poly1305_emit]
	mov	r9,QWORD PTR[((OPENSSL_ia32cap_P+4))]
	lea	rax,QWORD PTR[poly1305_blocks_avx]
	bt	r9,28
	cmovc	r10,rax
	lea	rax,QWORD PTR[poly1305_blocks_avx2]
	bt	r9,37
	cmovc	r10,rax
	mov	rax,2149580800
	shr	r9,32
	and	r9,rax
	cmp	r9,rax
	je	$L$init_base2_44
	mov	QWORD PTR[rdx],r10
	mov	QWORD PTR[8+rdx],r11
	mov	eax,1
$L$no_key::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_init::
poly1305_init	ENDP


ALIGN	32
poly1305_blocks	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks::


	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
$L$blocks::
	shr	rdx,4
	jz	$L$no_data

	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15

	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_body::

	mov	r15,rdx

	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]

	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	rbp,QWORD PTR[16+rdi]

	mov	eax,r14d
	mov	edx,DWORD PTR[4+rdi]
	mov	r8d,ebx
	mov	r10d,DWORD PTR[12+rdi]
	mov	r12d,ebp

	shl	rdx,26
	mov	r9,r8
	shl	r8,52
	add	rax,rdx
	shr	r9,12
	add	r8,rax
	adc	r9,0

	shl	r10,14
	mov	rax,r12
	shr	r12,24
	add	r9,r10
	shl	rax,40
	add	r9,rax
	adc	r12,0

	cmp	rbp,4

	cmova	r14,r8
	cmova	rbx,r9
	cmova	rbp,r12

	mov	r12,r13
	shr	r13,2
	mov	rax,r12
	add	r13,r12
	jmp	$L$oop

ALIGN	32
$L$oop::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	mul	r14
	mov	r9,rax
	mov	rax,r11
	mov	r10,rdx

	mul	r14
	mov	r14,rax
	mov	rax,r11
	mov	r8,rdx

	mul	rbx
	add	r9,rax
	mov	rax,r13
	adc	r10,rdx

	mul	rbx
	mov	rbx,rbp
	add	r14,rax
	adc	r8,rdx

	imul	rbx,r13
	add	r9,rbx
	mov	rbx,r8
	adc	r10,0

	imul	rbp,r11
	add	rbx,r9
	mov	rax,-4
	adc	r10,rbp

	and	rax,r10
	mov	rbp,r10
	shr	r10,2
	and	rbp,3
	add	rax,r10
	add	r14,rax
	adc	rbx,0
	adc	rbp,0
	mov	rax,r12
	dec	r15
	jnz	$L$oop

	mov	QWORD PTR[rdi],r14
	mov	QWORD PTR[8+rdi],rbx
	mov	QWORD PTR[16+rdi],rbp

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rsp,QWORD PTR[56+rsp]

$L$no_data::
$L$blocks_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks::
poly1305_blocks	ENDP


ALIGN	32
poly1305_emit	PROC PUBLIC
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_emit::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	eax,DWORD PTR[rdi]
	mov	ecx,DWORD PTR[4+rdi]
	mov	r8d,DWORD PTR[8+rdi]
	mov	r11d,DWORD PTR[12+rdi]
	mov	r10d,DWORD PTR[16+rdi]

	shl	rcx,26
	mov	r9,r8
	shl	r8,52
	add	rax,rcx
	shr	r9,12
	add	r8,rax
	adc	r9,0

	shl	r11,14
	mov	rax,r10
	shr	r10,24
	add	r9,r11
	mov	rcx,QWORD PTR[rdi]
	shl	rax,40
	mov	r11,QWORD PTR[8+rdi]
	add	r9,rax
	mov	rax,QWORD PTR[16+rdi]
	adc	r10,0

	cmp	rax,4

	cmovbe	r8,rcx
	cmovbe	r9,r11
	cmovbe	r10,rax

	mov	rax,r8
	add	r8,5
	mov	rcx,r9
	adc	r9,0
	adc	r10,0
	shr	r10,2
	cmovnz	rax,r8
	cmovnz	rcx,r9

	add	rax,QWORD PTR[rdx]
	adc	rcx,QWORD PTR[8+rdx]
	mov	QWORD PTR[rsi],rax
	mov	QWORD PTR[8+rsi],rcx

	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_emit::
poly1305_emit	ENDP

ALIGN	32
__poly1305_block	PROC PRIVATE
	DB	243,15,30,250

	mul	r14
	mov	r9,rax
	mov	rax,r11
	mov	r10,rdx

	mul	r14
	mov	r14,rax
	mov	rax,r11
	mov	r8,rdx

	mul	rbx
	add	r9,rax
	mov	rax,r13
	adc	r10,rdx

	mul	rbx
	mov	rbx,rbp
	add	r14,rax
	adc	r8,rdx

	imul	rbx,r13
	add	r9,rbx
	mov	rbx,r8
	adc	r10,0

	imul	rbp,r11
	add	rbx,r9
	mov	rax,-4
	adc	r10,rbp

	and	rax,r10
	mov	rbp,r10
	shr	r10,2
	and	rbp,3
	add	rax,r10
	add	r14,rax
	adc	rbx,0
	adc	rbp,0
	DB	0F3h,0C3h		;repret
__poly1305_block	ENDP


ALIGN	32
__poly1305_init_avx	PROC PRIVATE
	DB	243,15,30,250

	cmp	DWORD PTR[48+rdi],-1
	jne	$L$done_init_avx

	mov	r14,r11
	mov	rbx,r12
	xor	rbp,rbp

	lea	rdi,QWORD PTR[((48+64))+rdi]

	mov	rax,r12
	call	__poly1305_block

	mov	eax,03ffffffh
	mov	edx,03ffffffh
	mov	r8,r14
	and	eax,r14d
	mov	r9,r11
	and	edx,r11d
	mov	DWORD PTR[((-64))+rdi],eax
	shr	r8,26
	mov	DWORD PTR[((-60))+rdi],edx
	shr	r9,26

	mov	eax,03ffffffh
	mov	edx,03ffffffh
	and	eax,r8d
	and	edx,r9d
	mov	DWORD PTR[((-48))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[((-44))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[((-32))+rdi],eax
	shr	r8,26
	mov	DWORD PTR[((-28))+rdi],edx
	shr	r9,26

	mov	rax,rbx
	mov	rdx,r12
	shl	rax,12
	shl	rdx,12
	or	rax,r8
	or	rdx,r9
	and	eax,03ffffffh
	and	edx,03ffffffh
	mov	DWORD PTR[((-16))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[((-12))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[rdi],eax
	mov	r8,rbx
	mov	DWORD PTR[4+rdi],edx
	mov	r9,r12

	mov	eax,03ffffffh
	mov	edx,03ffffffh
	shr	r8,14
	shr	r9,14
	and	eax,r8d
	and	edx,r9d
	mov	DWORD PTR[16+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	DWORD PTR[20+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	mov	DWORD PTR[32+rdi],eax
	shr	r8,26
	mov	DWORD PTR[36+rdi],edx
	shr	r9,26

	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[48+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[52+rdi],r9d
	lea	r9,QWORD PTR[r9*4+r9]
	mov	DWORD PTR[64+rdi],r8d
	mov	DWORD PTR[68+rdi],r9d

	mov	rax,r12
	call	__poly1305_block

	mov	eax,03ffffffh
	mov	r8,r14
	and	eax,r14d
	shr	r8,26
	mov	DWORD PTR[((-52))+rdi],eax

	mov	edx,03ffffffh
	and	edx,r8d
	mov	DWORD PTR[((-36))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[((-20))+rdi],edx

	mov	rax,rbx
	shl	rax,12
	or	rax,r8
	and	eax,03ffffffh
	mov	DWORD PTR[((-4))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	r8,rbx
	mov	DWORD PTR[12+rdi],eax

	mov	edx,03ffffffh
	shr	r8,14
	and	edx,r8d
	mov	DWORD PTR[28+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[44+rdi],edx

	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[60+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[76+rdi],r8d

	mov	rax,r12
	call	__poly1305_block

	mov	eax,03ffffffh
	mov	r8,r14
	and	eax,r14d
	shr	r8,26
	mov	DWORD PTR[((-56))+rdi],eax

	mov	edx,03ffffffh
	and	edx,r8d
	mov	DWORD PTR[((-40))+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[((-24))+rdi],edx

	mov	rax,rbx
	shl	rax,12
	or	rax,r8
	and	eax,03ffffffh
	mov	DWORD PTR[((-8))+rdi],eax
	lea	eax,DWORD PTR[rax*4+rax]
	mov	r8,rbx
	mov	DWORD PTR[8+rdi],eax

	mov	edx,03ffffffh
	shr	r8,14
	and	edx,r8d
	mov	DWORD PTR[24+rdi],edx
	lea	edx,DWORD PTR[rdx*4+rdx]
	shr	r8,26
	mov	DWORD PTR[40+rdi],edx

	mov	rax,rbp
	shl	rax,24
	or	r8,rax
	mov	DWORD PTR[56+rdi],r8d
	lea	r8,QWORD PTR[r8*4+r8]
	mov	DWORD PTR[72+rdi],r8d

	lea	rdi,QWORD PTR[((-48-64))+rdi]
$L$done_init_avx::
	DB	0F3h,0C3h		;repret
__poly1305_init_avx	ENDP


ALIGN	32
poly1305_blocks_avx	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_avx::


	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8d,DWORD PTR[20+rdi]
	cmp	rdx,128
	jb	$L$blocks

	and	rdx,-16

	vzeroupper

	test	r8d,r8d
	jz	$L$base2_64_avx

	test	rdx,31
	jz	$L$even_avx

	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15

	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_avx_body::

	mov	r15,rdx

	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]

	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]


	mov	r14d,r8d
	and	r8,-2147483648
	mov	r12,r9
	mov	ebx,r9d
	and	r9,-2147483648

	shr	r8,6
	shl	r12,52
	add	r14,r8
	shr	rbx,12
	shr	r9,18
	add	r14,r12
	adc	rbx,r9

	mov	r8,rbp
	shl	r8,40
	shr	rbp,24
	add	rbx,r8
	adc	rbp,0

	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12

	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx

	call	__poly1305_block


	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r11,rbx
	mov	r12,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r11,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r11
	shl	rbp,24
	and	r14,03ffffffh
	shr	r12,40
	and	rbx,03ffffffh
	or	rbp,r12

	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp

	lea	rdx,QWORD PTR[((-16))+r15]

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_avx_epilogue::
	jmp	$L$do_avx


ALIGN	32
$L$base2_64_avx::

	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15

	lea	rsp,QWORD PTR[((-8))+rsp]

$L$base2_64_avx_body::

	mov	r15,rdx

	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]

	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]

	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12

	test	rdx,31
	jz	$L$init_avx

	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16

	call	__poly1305_block

$L$init_avx::

	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r8,rbx
	mov	r9,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r8,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r8
	shl	rbp,24
	and	r14,03ffffffh
	shr	r9,40
	and	rbx,03ffffffh
	or	rbp,r9

	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	mov	DWORD PTR[20+rdi],1

	call	__poly1305_init_avx

	mov	rdx,r15

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$base2_64_avx_epilogue::
	jmp	$L$do_avx


ALIGN	32
$L$even_avx::

	vmovd	xmm0,DWORD PTR[rdi]
	vmovd	xmm1,DWORD PTR[4+rdi]
	vmovd	xmm2,DWORD PTR[8+rdi]
	vmovd	xmm3,DWORD PTR[12+rdi]
	vmovd	xmm4,DWORD PTR[16+rdi]

$L$do_avx::
	lea	r11,QWORD PTR[((-248))+rsp]
	sub	rsp,0218h
	vmovdqa	XMMWORD PTR[80+r11],xmm6
	vmovdqa	XMMWORD PTR[96+r11],xmm7
	vmovdqa	XMMWORD PTR[112+r11],xmm8
	vmovdqa	XMMWORD PTR[128+r11],xmm9
	vmovdqa	XMMWORD PTR[144+r11],xmm10
	vmovdqa	XMMWORD PTR[160+r11],xmm11
	vmovdqa	XMMWORD PTR[176+r11],xmm12
	vmovdqa	XMMWORD PTR[192+r11],xmm13
	vmovdqa	XMMWORD PTR[208+r11],xmm14
	vmovdqa	XMMWORD PTR[224+r11],xmm15
$L$do_avx_body::
	sub	rdx,64
	lea	rax,QWORD PTR[((-32))+rsi]
	cmovc	rsi,rax

	vmovdqu	xmm14,XMMWORD PTR[48+rdi]
	lea	rdi,QWORD PTR[112+rdi]
	lea	rcx,QWORD PTR[$L$const]



	vmovdqu	xmm5,XMMWORD PTR[32+rsi]
	vmovdqu	xmm6,XMMWORD PTR[48+rsi]
	vmovdqa	xmm15,XMMWORD PTR[64+rcx]

	vpsrldq	xmm7,xmm5,6
	vpsrldq	xmm8,xmm6,6
	vpunpckhqdq	xmm9,xmm5,xmm6
	vpunpcklqdq	xmm5,xmm5,xmm6
	vpunpcklqdq	xmm8,xmm7,xmm8

	vpsrlq	xmm9,xmm9,40
	vpsrlq	xmm6,xmm5,26
	vpand	xmm5,xmm5,xmm15
	vpsrlq	xmm7,xmm8,4
	vpand	xmm6,xmm6,xmm15
	vpsrlq	xmm8,xmm8,30
	vpand	xmm7,xmm7,xmm15
	vpand	xmm8,xmm8,xmm15
	vpor	xmm9,xmm9,XMMWORD PTR[32+rcx]

	jbe	$L$skip_loop_avx


	vmovdqu	xmm11,XMMWORD PTR[((-48))+rdi]
	vmovdqu	xmm12,XMMWORD PTR[((-32))+rdi]
	vpshufd	xmm13,xmm14,0EEh
	vpshufd	xmm10,xmm14,044h
	vmovdqa	XMMWORD PTR[(-144)+r11],xmm13
	vmovdqa	XMMWORD PTR[rsp],xmm10
	vpshufd	xmm14,xmm11,0EEh
	vmovdqu	xmm10,XMMWORD PTR[((-16))+rdi]
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-128)+r11],xmm14
	vmovdqa	XMMWORD PTR[16+rsp],xmm11
	vpshufd	xmm13,xmm12,0EEh
	vmovdqu	xmm11,XMMWORD PTR[rdi]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-112)+r11],xmm13
	vmovdqa	XMMWORD PTR[32+rsp],xmm12
	vpshufd	xmm14,xmm10,0EEh
	vmovdqu	xmm12,XMMWORD PTR[16+rdi]
	vpshufd	xmm10,xmm10,044h
	vmovdqa	XMMWORD PTR[(-96)+r11],xmm14
	vmovdqa	XMMWORD PTR[48+rsp],xmm10
	vpshufd	xmm13,xmm11,0EEh
	vmovdqu	xmm10,XMMWORD PTR[32+rdi]
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-80)+r11],xmm13
	vmovdqa	XMMWORD PTR[64+rsp],xmm11
	vpshufd	xmm14,xmm12,0EEh
	vmovdqu	xmm11,XMMWORD PTR[48+rdi]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-64)+r11],xmm14
	vmovdqa	XMMWORD PTR[80+rsp],xmm12
	vpshufd	xmm13,xmm10,0EEh
	vmovdqu	xmm12,XMMWORD PTR[64+rdi]
	vpshufd	xmm10,xmm10,044h
	vmovdqa	XMMWORD PTR[(-48)+r11],xmm13
	vmovdqa	XMMWORD PTR[96+rsp],xmm10
	vpshufd	xmm14,xmm11,0EEh
	vpshufd	xmm11,xmm11,044h
	vmovdqa	XMMWORD PTR[(-32)+r11],xmm14
	vmovdqa	XMMWORD PTR[112+rsp],xmm11
	vpshufd	xmm13,xmm12,0EEh
	vmovdqa	xmm14,XMMWORD PTR[rsp]
	vpshufd	xmm12,xmm12,044h
	vmovdqa	XMMWORD PTR[(-16)+r11],xmm13
	vmovdqa	XMMWORD PTR[128+rsp],xmm12

	jmp	$L$oop_avx

ALIGN	32
$L$oop_avx::




















	vpmuludq	xmm10,xmm14,xmm5
	vpmuludq	xmm11,xmm14,xmm6
	vmovdqa	XMMWORD PTR[32+r11],xmm2
	vpmuludq	xmm12,xmm14,xmm7
	vmovdqa	xmm2,XMMWORD PTR[16+rsp]
	vpmuludq	xmm13,xmm14,xmm8
	vpmuludq	xmm14,xmm14,xmm9

	vmovdqa	XMMWORD PTR[r11],xmm0
	vpmuludq	xmm0,xmm9,XMMWORD PTR[32+rsp]
	vmovdqa	XMMWORD PTR[16+r11],xmm1
	vpmuludq	xmm1,xmm2,xmm8
	vpaddq	xmm10,xmm10,xmm0
	vpaddq	xmm14,xmm14,xmm1
	vmovdqa	XMMWORD PTR[48+r11],xmm3
	vpmuludq	xmm0,xmm2,xmm7
	vpmuludq	xmm1,xmm2,xmm6
	vpaddq	xmm13,xmm13,xmm0
	vmovdqa	xmm3,XMMWORD PTR[48+rsp]
	vpaddq	xmm12,xmm12,xmm1
	vmovdqa	XMMWORD PTR[64+r11],xmm4
	vpmuludq	xmm2,xmm2,xmm5
	vpmuludq	xmm0,xmm3,xmm7
	vpaddq	xmm11,xmm11,xmm2

	vmovdqa	xmm4,XMMWORD PTR[64+rsp]
	vpaddq	xmm14,xmm14,xmm0
	vpmuludq	xmm1,xmm3,xmm6
	vpmuludq	xmm3,xmm3,xmm5
	vpaddq	xmm13,xmm13,xmm1
	vmovdqa	xmm2,XMMWORD PTR[80+rsp]
	vpaddq	xmm12,xmm12,xmm3
	vpmuludq	xmm0,xmm4,xmm9
	vpmuludq	xmm4,xmm4,xmm8
	vpaddq	xmm11,xmm11,xmm0
	vmovdqa	xmm3,XMMWORD PTR[96+rsp]
	vpaddq	xmm10,xmm10,xmm4

	vmovdqa	xmm4,XMMWORD PTR[128+rsp]
	vpmuludq	xmm1,xmm2,xmm6
	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm14,xmm14,xmm1
	vpaddq	xmm13,xmm13,xmm2
	vpmuludq	xmm0,xmm3,xmm9
	vpmuludq	xmm1,xmm3,xmm8
	vpaddq	xmm12,xmm12,xmm0
	vmovdqu	xmm0,XMMWORD PTR[rsi]
	vpaddq	xmm11,xmm11,xmm1
	vpmuludq	xmm3,xmm3,xmm7
	vpmuludq	xmm7,xmm4,xmm7
	vpaddq	xmm10,xmm10,xmm3

	vmovdqu	xmm1,XMMWORD PTR[16+rsi]
	vpaddq	xmm11,xmm11,xmm7
	vpmuludq	xmm8,xmm4,xmm8
	vpmuludq	xmm9,xmm4,xmm9
	vpsrldq	xmm2,xmm0,6
	vpaddq	xmm12,xmm12,xmm8
	vpaddq	xmm13,xmm13,xmm9
	vpsrldq	xmm3,xmm1,6
	vpmuludq	xmm9,xmm5,XMMWORD PTR[112+rsp]
	vpmuludq	xmm5,xmm4,xmm6
	vpunpckhqdq	xmm4,xmm0,xmm1
	vpaddq	xmm14,xmm14,xmm9
	vmovdqa	xmm9,XMMWORD PTR[((-144))+r11]
	vpaddq	xmm10,xmm10,xmm5

	vpunpcklqdq	xmm0,xmm0,xmm1
	vpunpcklqdq	xmm3,xmm2,xmm3


	vpsrldq	xmm4,xmm4,5
	vpsrlq	xmm1,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpsrlq	xmm2,xmm3,4
	vpand	xmm1,xmm1,xmm15
	vpand	xmm4,xmm4,XMMWORD PTR[rcx]
	vpsrlq	xmm3,xmm3,30
	vpand	xmm2,xmm2,xmm15
	vpand	xmm3,xmm3,xmm15
	vpor	xmm4,xmm4,XMMWORD PTR[32+rcx]

	vpaddq	xmm0,xmm0,XMMWORD PTR[r11]
	vpaddq	xmm1,xmm1,XMMWORD PTR[16+r11]
	vpaddq	xmm2,xmm2,XMMWORD PTR[32+r11]
	vpaddq	xmm3,xmm3,XMMWORD PTR[48+r11]
	vpaddq	xmm4,xmm4,XMMWORD PTR[64+r11]

	lea	rax,QWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	sub	rdx,64
	cmovc	rsi,rax










	vpmuludq	xmm5,xmm9,xmm0
	vpmuludq	xmm6,xmm9,xmm1
	vpaddq	xmm10,xmm10,xmm5
	vpaddq	xmm11,xmm11,xmm6
	vmovdqa	xmm7,XMMWORD PTR[((-128))+r11]
	vpmuludq	xmm5,xmm9,xmm2
	vpmuludq	xmm6,xmm9,xmm3
	vpaddq	xmm12,xmm12,xmm5
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm9,xmm9,xmm4
	vpmuludq	xmm5,xmm4,XMMWORD PTR[((-112))+r11]
	vpaddq	xmm14,xmm14,xmm9

	vpaddq	xmm10,xmm10,xmm5
	vpmuludq	xmm6,xmm7,xmm2
	vpmuludq	xmm5,xmm7,xmm3
	vpaddq	xmm13,xmm13,xmm6
	vmovdqa	xmm8,XMMWORD PTR[((-96))+r11]
	vpaddq	xmm14,xmm14,xmm5
	vpmuludq	xmm6,xmm7,xmm1
	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm12,xmm12,xmm6
	vpaddq	xmm11,xmm11,xmm7

	vmovdqa	xmm9,XMMWORD PTR[((-80))+r11]
	vpmuludq	xmm5,xmm8,xmm2
	vpmuludq	xmm6,xmm8,xmm1
	vpaddq	xmm14,xmm14,xmm5
	vpaddq	xmm13,xmm13,xmm6
	vmovdqa	xmm7,XMMWORD PTR[((-64))+r11]
	vpmuludq	xmm8,xmm8,xmm0
	vpmuludq	xmm5,xmm9,xmm4
	vpaddq	xmm12,xmm12,xmm8
	vpaddq	xmm11,xmm11,xmm5
	vmovdqa	xmm8,XMMWORD PTR[((-48))+r11]
	vpmuludq	xmm9,xmm9,xmm3
	vpmuludq	xmm6,xmm7,xmm1
	vpaddq	xmm10,xmm10,xmm9

	vmovdqa	xmm9,XMMWORD PTR[((-16))+r11]
	vpaddq	xmm14,xmm14,xmm6
	vpmuludq	xmm7,xmm7,xmm0
	vpmuludq	xmm5,xmm8,xmm4
	vpaddq	xmm13,xmm13,xmm7
	vpaddq	xmm12,xmm12,xmm5
	vmovdqu	xmm5,XMMWORD PTR[32+rsi]
	vpmuludq	xmm7,xmm8,xmm3
	vpmuludq	xmm8,xmm8,xmm2
	vpaddq	xmm11,xmm11,xmm7
	vmovdqu	xmm6,XMMWORD PTR[48+rsi]
	vpaddq	xmm10,xmm10,xmm8

	vpmuludq	xmm2,xmm9,xmm2
	vpmuludq	xmm3,xmm9,xmm3
	vpsrldq	xmm7,xmm5,6
	vpaddq	xmm11,xmm11,xmm2
	vpmuludq	xmm4,xmm9,xmm4
	vpsrldq	xmm8,xmm6,6
	vpaddq	xmm2,xmm12,xmm3
	vpaddq	xmm3,xmm13,xmm4
	vpmuludq	xmm4,xmm0,XMMWORD PTR[((-32))+r11]
	vpmuludq	xmm0,xmm9,xmm1
	vpunpckhqdq	xmm9,xmm5,xmm6
	vpaddq	xmm4,xmm14,xmm4
	vpaddq	xmm0,xmm10,xmm0

	vpunpcklqdq	xmm5,xmm5,xmm6
	vpunpcklqdq	xmm8,xmm7,xmm8


	vpsrldq	xmm9,xmm9,5
	vpsrlq	xmm6,xmm5,26
	vmovdqa	xmm14,XMMWORD PTR[rsp]
	vpand	xmm5,xmm5,xmm15
	vpsrlq	xmm7,xmm8,4
	vpand	xmm6,xmm6,xmm15
	vpand	xmm9,xmm9,XMMWORD PTR[rcx]
	vpsrlq	xmm8,xmm8,30
	vpand	xmm7,xmm7,xmm15
	vpand	xmm8,xmm8,xmm15
	vpor	xmm9,xmm9,XMMWORD PTR[32+rcx]





	vpsrlq	xmm13,xmm3,26
	vpand	xmm3,xmm3,xmm15
	vpaddq	xmm4,xmm4,xmm13

	vpsrlq	xmm10,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpaddq	xmm1,xmm11,xmm10

	vpsrlq	xmm10,xmm4,26
	vpand	xmm4,xmm4,xmm15

	vpsrlq	xmm11,xmm1,26
	vpand	xmm1,xmm1,xmm15
	vpaddq	xmm2,xmm2,xmm11

	vpaddq	xmm0,xmm0,xmm10
	vpsllq	xmm10,xmm10,2
	vpaddq	xmm0,xmm0,xmm10

	vpsrlq	xmm12,xmm2,26
	vpand	xmm2,xmm2,xmm15
	vpaddq	xmm3,xmm3,xmm12

	vpsrlq	xmm10,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpaddq	xmm1,xmm1,xmm10

	vpsrlq	xmm13,xmm3,26
	vpand	xmm3,xmm3,xmm15
	vpaddq	xmm4,xmm4,xmm13

	ja	$L$oop_avx

$L$skip_loop_avx::



	vpshufd	xmm14,xmm14,010h
	add	rdx,32
	jnz	$L$ong_tail_avx

	vpaddq	xmm7,xmm7,xmm2
	vpaddq	xmm5,xmm5,xmm0
	vpaddq	xmm6,xmm6,xmm1
	vpaddq	xmm8,xmm8,xmm3
	vpaddq	xmm9,xmm9,xmm4

$L$ong_tail_avx::
	vmovdqa	XMMWORD PTR[32+r11],xmm2
	vmovdqa	XMMWORD PTR[r11],xmm0
	vmovdqa	XMMWORD PTR[16+r11],xmm1
	vmovdqa	XMMWORD PTR[48+r11],xmm3
	vmovdqa	XMMWORD PTR[64+r11],xmm4







	vpmuludq	xmm12,xmm14,xmm7
	vpmuludq	xmm10,xmm14,xmm5
	vpshufd	xmm2,XMMWORD PTR[((-48))+rdi],010h
	vpmuludq	xmm11,xmm14,xmm6
	vpmuludq	xmm13,xmm14,xmm8
	vpmuludq	xmm14,xmm14,xmm9

	vpmuludq	xmm0,xmm2,xmm8
	vpaddq	xmm14,xmm14,xmm0
	vpshufd	xmm3,XMMWORD PTR[((-32))+rdi],010h
	vpmuludq	xmm1,xmm2,xmm7
	vpaddq	xmm13,xmm13,xmm1
	vpshufd	xmm4,XMMWORD PTR[((-16))+rdi],010h
	vpmuludq	xmm0,xmm2,xmm6
	vpaddq	xmm12,xmm12,xmm0
	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm11,xmm11,xmm2
	vpmuludq	xmm3,xmm3,xmm9
	vpaddq	xmm10,xmm10,xmm3

	vpshufd	xmm2,XMMWORD PTR[rdi],010h
	vpmuludq	xmm1,xmm4,xmm7
	vpaddq	xmm14,xmm14,xmm1
	vpmuludq	xmm0,xmm4,xmm6
	vpaddq	xmm13,xmm13,xmm0
	vpshufd	xmm3,XMMWORD PTR[16+rdi],010h
	vpmuludq	xmm4,xmm4,xmm5
	vpaddq	xmm12,xmm12,xmm4
	vpmuludq	xmm1,xmm2,xmm9
	vpaddq	xmm11,xmm11,xmm1
	vpshufd	xmm4,XMMWORD PTR[32+rdi],010h
	vpmuludq	xmm2,xmm2,xmm8
	vpaddq	xmm10,xmm10,xmm2

	vpmuludq	xmm0,xmm3,xmm6
	vpaddq	xmm14,xmm14,xmm0
	vpmuludq	xmm3,xmm3,xmm5
	vpaddq	xmm13,xmm13,xmm3
	vpshufd	xmm2,XMMWORD PTR[48+rdi],010h
	vpmuludq	xmm1,xmm4,xmm9
	vpaddq	xmm12,xmm12,xmm1
	vpshufd	xmm3,XMMWORD PTR[64+rdi],010h
	vpmuludq	xmm0,xmm4,xmm8
	vpaddq	xmm11,xmm11,xmm0
	vpmuludq	xmm4,xmm4,xmm7
	vpaddq	xmm10,xmm10,xmm4

	vpmuludq	xmm2,xmm2,xmm5
	vpaddq	xmm14,xmm14,xmm2
	vpmuludq	xmm1,xmm3,xmm9
	vpaddq	xmm13,xmm13,xmm1
	vpmuludq	xmm0,xmm3,xmm8
	vpaddq	xmm12,xmm12,xmm0
	vpmuludq	xmm1,xmm3,xmm7
	vpaddq	xmm11,xmm11,xmm1
	vpmuludq	xmm3,xmm3,xmm6
	vpaddq	xmm10,xmm10,xmm3

	jz	$L$short_tail_avx

	vmovdqu	xmm0,XMMWORD PTR[rsi]
	vmovdqu	xmm1,XMMWORD PTR[16+rsi]

	vpsrldq	xmm2,xmm0,6
	vpsrldq	xmm3,xmm1,6
	vpunpckhqdq	xmm4,xmm0,xmm1
	vpunpcklqdq	xmm0,xmm0,xmm1
	vpunpcklqdq	xmm3,xmm2,xmm3

	vpsrlq	xmm4,xmm4,40
	vpsrlq	xmm1,xmm0,26
	vpand	xmm0,xmm0,xmm15
	vpsrlq	xmm2,xmm3,4
	vpand	xmm1,xmm1,xmm15
	vpsrlq	xmm3,xmm3,30
	vpand	xmm2,xmm2,xmm15
	vpand	xmm3,xmm3,xmm15
	vpor	xmm4,xmm4,XMMWORD PTR[32+rcx]

	vpshufd	xmm9,XMMWORD PTR[((-64))+rdi],032h
	vpaddq	xmm0,xmm0,XMMWORD PTR[r11]
	vpaddq	xmm1,xmm1,XMMWORD PTR[16+r11]
	vpaddq	xmm2,xmm2,XMMWORD PTR[32+r11]
	vpaddq	xmm3,xmm3,XMMWORD PTR[48+r11]
	vpaddq	xmm4,xmm4,XMMWORD PTR[64+r11]




	vpmuludq	xmm5,xmm9,xmm0
	vpaddq	xmm10,xmm10,xmm5
	vpmuludq	xmm6,xmm9,xmm1
	vpaddq	xmm11,xmm11,xmm6
	vpmuludq	xmm5,xmm9,xmm2
	vpaddq	xmm12,xmm12,xmm5
	vpshufd	xmm7,XMMWORD PTR[((-48))+rdi],032h
	vpmuludq	xmm6,xmm9,xmm3
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm9,xmm9,xmm4
	vpaddq	xmm14,xmm14,xmm9

	vpmuludq	xmm5,xmm7,xmm3
	vpaddq	xmm14,xmm14,xmm5
	vpshufd	xmm8,XMMWORD PTR[((-32))+rdi],032h
	vpmuludq	xmm6,xmm7,xmm2
	vpaddq	xmm13,xmm13,xmm6
	vpshufd	xmm9,XMMWORD PTR[((-16))+rdi],032h
	vpmuludq	xmm5,xmm7,xmm1
	vpaddq	xmm12,xmm12,xmm5
	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm11,xmm11,xmm7
	vpmuludq	xmm8,xmm8,xmm4
	vpaddq	xmm10,xmm10,xmm8

	vpshufd	xmm7,XMMWORD PTR[rdi],032h
	vpmuludq	xmm6,xmm9,xmm2
	vpaddq	xmm14,xmm14,xmm6
	vpmuludq	xmm5,xmm9,xmm1
	vpaddq	xmm13,xmm13,xmm5
	vpshufd	xmm8,XMMWORD PTR[16+rdi],032h
	vpmuludq	xmm9,xmm9,xmm0
	vpaddq	xmm12,xmm12,xmm9
	vpmuludq	xmm6,xmm7,xmm4
	vpaddq	xmm11,xmm11,xmm6
	vpshufd	xmm9,XMMWORD PTR[32+rdi],032h
	vpmuludq	xmm7,xmm7,xmm3
	vpaddq	xmm10,xmm10,xmm7

	vpmuludq	xmm5,xmm8,xmm1
	vpaddq	xmm14,xmm14,xmm5
	vpmuludq	xmm8,xmm8,xmm0
	vpaddq	xmm13,xmm13,xmm8
	vpshufd	xmm7,XMMWORD PTR[48+rdi],032h
	vpmuludq	xmm6,xmm9,xmm4
	vpaddq	xmm12,xmm12,xmm6
	vpshufd	xmm8,XMMWORD PTR[64+rdi],032h
	vpmuludq	xmm5,xmm9,xmm3
	vpaddq	xmm11,xmm11,xmm5
	vpmuludq	xmm9,xmm9,xmm2
	vpaddq	xmm10,xmm10,xmm9

	vpmuludq	xmm7,xmm7,xmm0
	vpaddq	xmm14,xmm14,xmm7
	vpmuludq	xmm6,xmm8,xmm4
	vpaddq	xmm13,xmm13,xmm6
	vpmuludq	xmm5,xmm8,xmm3
	vpaddq	xmm12,xmm12,xmm5
	vpmuludq	xmm6,xmm8,xmm2
	vpaddq	xmm11,xmm11,xmm6
	vpmuludq	xmm8,xmm8,xmm1
	vpaddq	xmm10,xmm10,xmm8

$L$short_tail_avx::



	vpsrldq	xmm9,xmm14,8
	vpsrldq	xmm8,xmm13,8
	vpsrldq	xmm6,xmm11,8
	vpsrldq	xmm5,xmm10,8
	vpsrldq	xmm7,xmm12,8
	vpaddq	xmm13,xmm13,xmm8
	vpaddq	xmm14,xmm14,xmm9
	vpaddq	xmm10,xmm10,xmm5
	vpaddq	xmm11,xmm11,xmm6
	vpaddq	xmm12,xmm12,xmm7




	vpsrlq	xmm3,xmm13,26
	vpand	xmm13,xmm13,xmm15
	vpaddq	xmm14,xmm14,xmm3

	vpsrlq	xmm0,xmm10,26
	vpand	xmm10,xmm10,xmm15
	vpaddq	xmm11,xmm11,xmm0

	vpsrlq	xmm4,xmm14,26
	vpand	xmm14,xmm14,xmm15

	vpsrlq	xmm1,xmm11,26
	vpand	xmm11,xmm11,xmm15
	vpaddq	xmm12,xmm12,xmm1

	vpaddq	xmm10,xmm10,xmm4
	vpsllq	xmm4,xmm4,2
	vpaddq	xmm10,xmm10,xmm4

	vpsrlq	xmm2,xmm12,26
	vpand	xmm12,xmm12,xmm15
	vpaddq	xmm13,xmm13,xmm2

	vpsrlq	xmm0,xmm10,26
	vpand	xmm10,xmm10,xmm15
	vpaddq	xmm11,xmm11,xmm0

	vpsrlq	xmm3,xmm13,26
	vpand	xmm13,xmm13,xmm15
	vpaddq	xmm14,xmm14,xmm3

	vmovd	DWORD PTR[(-112)+rdi],xmm10
	vmovd	DWORD PTR[(-108)+rdi],xmm11
	vmovd	DWORD PTR[(-104)+rdi],xmm12
	vmovd	DWORD PTR[(-100)+rdi],xmm13
	vmovd	DWORD PTR[(-96)+rdi],xmm14
	vmovdqa	xmm6,XMMWORD PTR[80+r11]
	vmovdqa	xmm7,XMMWORD PTR[96+r11]
	vmovdqa	xmm8,XMMWORD PTR[112+r11]
	vmovdqa	xmm9,XMMWORD PTR[128+r11]
	vmovdqa	xmm10,XMMWORD PTR[144+r11]
	vmovdqa	xmm11,XMMWORD PTR[160+r11]
	vmovdqa	xmm12,XMMWORD PTR[176+r11]
	vmovdqa	xmm13,XMMWORD PTR[192+r11]
	vmovdqa	xmm14,XMMWORD PTR[208+r11]
	vmovdqa	xmm15,XMMWORD PTR[224+r11]
	lea	rsp,QWORD PTR[248+r11]
$L$do_avx_epilogue::
	vzeroupper
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_avx::
poly1305_blocks_avx	ENDP

ALIGN	32
poly1305_blocks_avx2	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_avx2::


	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8d,DWORD PTR[20+rdi]
	cmp	rdx,128
	jb	$L$blocks

	and	rdx,-16

	vzeroupper

	test	r8d,r8d
	jz	$L$base2_64_avx2

	test	rdx,63
	jz	$L$even_avx2

	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15

	lea	rsp,QWORD PTR[((-8))+rsp]

$L$blocks_avx2_body::

	mov	r15,rdx

	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]

	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]


	mov	r14d,r8d
	and	r8,-2147483648
	mov	r12,r9
	mov	ebx,r9d
	and	r9,-2147483648

	shr	r8,6
	shl	r12,52
	add	r14,r8
	shr	rbx,12
	shr	r9,18
	add	r14,r12
	adc	rbx,r9

	mov	r8,rbp
	shl	r8,40
	shr	rbp,24
	add	rbx,r8
	adc	rbp,0

	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12

$L$base2_26_pre_avx2::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16

	call	__poly1305_block
	mov	rax,r12

	test	r15,63
	jnz	$L$base2_26_pre_avx2


	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r11,rbx
	mov	r12,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r11,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r11
	shl	rbp,24
	and	r14,03ffffffh
	shr	r12,40
	and	rbx,03ffffffh
	or	rbp,r12

	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp

	mov	rdx,r15

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_avx2_epilogue::
	jmp	$L$do_avx2


ALIGN	32
$L$base2_64_avx2::

	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15

	lea	rsp,QWORD PTR[((-8))+rsp]

$L$base2_64_avx2_body::

	mov	r15,rdx

	mov	r11,QWORD PTR[24+rdi]
	mov	r13,QWORD PTR[32+rdi]

	mov	r14,QWORD PTR[rdi]
	mov	rbx,QWORD PTR[8+rdi]
	mov	ebp,DWORD PTR[16+rdi]

	mov	r12,r13
	mov	rax,r13
	shr	r13,2
	add	r13,r12

	test	rdx,63
	jz	$L$init_avx2

$L$base2_64_pre_avx2::
	add	r14,QWORD PTR[rsi]
	adc	rbx,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]
	adc	rbp,rcx
	sub	r15,16

	call	__poly1305_block
	mov	rax,r12

	test	r15,63
	jnz	$L$base2_64_pre_avx2

$L$init_avx2::

	mov	rax,r14
	mov	rdx,r14
	shr	r14,52
	mov	r8,rbx
	mov	r9,rbx
	shr	rdx,26
	and	rax,03ffffffh
	shl	r8,12
	and	rdx,03ffffffh
	shr	rbx,14
	or	r14,r8
	shl	rbp,24
	and	r14,03ffffffh
	shr	r9,40
	and	rbx,03ffffffh
	or	rbp,r9

	vmovd	xmm0,eax
	vmovd	xmm1,edx
	vmovd	xmm2,r14d
	vmovd	xmm3,ebx
	vmovd	xmm4,ebp
	mov	DWORD PTR[20+rdi],1

	call	__poly1305_init_avx

	mov	rdx,r15

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rax,QWORD PTR[56+rsp]
	lea	rsp,QWORD PTR[56+rsp]

$L$base2_64_avx2_epilogue::
	jmp	$L$do_avx2


ALIGN	32
$L$even_avx2::

	vmovd	xmm0,DWORD PTR[rdi]
	vmovd	xmm1,DWORD PTR[4+rdi]
	vmovd	xmm2,DWORD PTR[8+rdi]
	vmovd	xmm3,DWORD PTR[12+rdi]
	vmovd	xmm4,DWORD PTR[16+rdi]

$L$do_avx2::
	mov	r10d,DWORD PTR[((OPENSSL_ia32cap_P+8))]
	cmp	rdx,512
	jb	$L$skip_avx512
	test	r10d,65536
	jnz	$L$blocks_avx512
$L$skip_avx512::
	lea	r11,QWORD PTR[((-248))+rsp]
	sub	rsp,01c8h
	vmovdqa	XMMWORD PTR[80+r11],xmm6
	vmovdqa	XMMWORD PTR[96+r11],xmm7
	vmovdqa	XMMWORD PTR[112+r11],xmm8
	vmovdqa	XMMWORD PTR[128+r11],xmm9
	vmovdqa	XMMWORD PTR[144+r11],xmm10
	vmovdqa	XMMWORD PTR[160+r11],xmm11
	vmovdqa	XMMWORD PTR[176+r11],xmm12
	vmovdqa	XMMWORD PTR[192+r11],xmm13
	vmovdqa	XMMWORD PTR[208+r11],xmm14
	vmovdqa	XMMWORD PTR[224+r11],xmm15
$L$do_avx2_body::
	lea	rcx,QWORD PTR[$L$const]
	lea	rdi,QWORD PTR[((48+64))+rdi]
	vmovdqa	ymm7,YMMWORD PTR[96+rcx]


	vmovdqu	xmm9,XMMWORD PTR[((-64))+rdi]
	and	rsp,-512
	vmovdqu	xmm10,XMMWORD PTR[((-48))+rdi]
	vmovdqu	xmm6,XMMWORD PTR[((-32))+rdi]
	vmovdqu	xmm11,XMMWORD PTR[((-16))+rdi]
	vmovdqu	xmm12,XMMWORD PTR[rdi]
	vmovdqu	xmm13,XMMWORD PTR[16+rdi]
	lea	rax,QWORD PTR[144+rsp]
	vmovdqu	xmm14,XMMWORD PTR[32+rdi]
	vpermd	ymm9,ymm7,ymm9
	vmovdqu	xmm15,XMMWORD PTR[48+rdi]
	vpermd	ymm10,ymm7,ymm10
	vmovdqu	xmm5,XMMWORD PTR[64+rdi]
	vpermd	ymm6,ymm7,ymm6
	vmovdqa	YMMWORD PTR[rsp],ymm9
	vpermd	ymm11,ymm7,ymm11
	vmovdqa	YMMWORD PTR[(32-144)+rax],ymm10
	vpermd	ymm12,ymm7,ymm12
	vmovdqa	YMMWORD PTR[(64-144)+rax],ymm6
	vpermd	ymm13,ymm7,ymm13
	vmovdqa	YMMWORD PTR[(96-144)+rax],ymm11
	vpermd	ymm14,ymm7,ymm14
	vmovdqa	YMMWORD PTR[(128-144)+rax],ymm12
	vpermd	ymm15,ymm7,ymm15
	vmovdqa	YMMWORD PTR[(160-144)+rax],ymm13
	vpermd	ymm5,ymm7,ymm5
	vmovdqa	YMMWORD PTR[(192-144)+rax],ymm14
	vmovdqa	YMMWORD PTR[(224-144)+rax],ymm15
	vmovdqa	YMMWORD PTR[(256-144)+rax],ymm5
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]



	vmovdqu	xmm7,XMMWORD PTR[rsi]
	vmovdqu	xmm8,XMMWORD PTR[16+rsi]
	vinserti128	ymm7,ymm7,XMMWORD PTR[32+rsi],1
	vinserti128	ymm8,ymm8,XMMWORD PTR[48+rsi],1
	lea	rsi,QWORD PTR[64+rsi]

	vpsrldq	ymm9,ymm7,6
	vpsrldq	ymm10,ymm8,6
	vpunpckhqdq	ymm6,ymm7,ymm8
	vpunpcklqdq	ymm9,ymm9,ymm10
	vpunpcklqdq	ymm7,ymm7,ymm8

	vpsrlq	ymm10,ymm9,30
	vpsrlq	ymm9,ymm9,4
	vpsrlq	ymm8,ymm7,26
	vpsrlq	ymm6,ymm6,40
	vpand	ymm9,ymm9,ymm5
	vpand	ymm7,ymm7,ymm5
	vpand	ymm8,ymm8,ymm5
	vpand	ymm10,ymm10,ymm5
	vpor	ymm6,ymm6,YMMWORD PTR[32+rcx]

	vpaddq	ymm2,ymm9,ymm2
	sub	rdx,64
	jz	$L$tail_avx2
	jmp	$L$oop_avx2

ALIGN	32
$L$oop_avx2::








	vpaddq	ymm0,ymm7,ymm0
	vmovdqa	ymm7,YMMWORD PTR[rsp]
	vpaddq	ymm1,ymm8,ymm1
	vmovdqa	ymm8,YMMWORD PTR[32+rsp]
	vpaddq	ymm3,ymm10,ymm3
	vmovdqa	ymm9,YMMWORD PTR[96+rsp]
	vpaddq	ymm4,ymm6,ymm4
	vmovdqa	ymm10,YMMWORD PTR[48+rax]
	vmovdqa	ymm5,YMMWORD PTR[112+rax]
















	vpmuludq	ymm13,ymm7,ymm2
	vpmuludq	ymm14,ymm8,ymm2
	vpmuludq	ymm15,ymm9,ymm2
	vpmuludq	ymm11,ymm10,ymm2
	vpmuludq	ymm12,ymm5,ymm2

	vpmuludq	ymm6,ymm8,ymm0
	vpmuludq	ymm2,ymm8,ymm1
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm4,YMMWORD PTR[64+rsp]
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm11,ymm11,ymm2
	vmovdqa	ymm8,YMMWORD PTR[((-16))+rax]

	vpmuludq	ymm6,ymm7,ymm0
	vpmuludq	ymm2,ymm7,ymm1
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vpmuludq	ymm6,ymm7,ymm3
	vpmuludq	ymm2,ymm7,ymm4
	vmovdqu	xmm7,XMMWORD PTR[rsi]
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm15,ymm15,ymm2
	vinserti128	ymm7,ymm7,XMMWORD PTR[32+rsi],1

	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm8,ymm4
	vmovdqu	xmm8,XMMWORD PTR[16+rsi]
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vmovdqa	ymm2,YMMWORD PTR[16+rax]
	vpmuludq	ymm6,ymm9,ymm1
	vpmuludq	ymm9,ymm9,ymm0
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm13,ymm13,ymm9
	vinserti128	ymm8,ymm8,XMMWORD PTR[48+rsi],1
	lea	rsi,QWORD PTR[64+rsi]

	vpmuludq	ymm6,ymm2,ymm1
	vpmuludq	ymm2,ymm2,ymm0
	vpsrldq	ymm9,ymm7,6
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm14,ymm14,ymm2
	vpmuludq	ymm6,ymm10,ymm3
	vpmuludq	ymm2,ymm10,ymm4
	vpsrldq	ymm10,ymm8,6
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpunpckhqdq	ymm6,ymm7,ymm8

	vpmuludq	ymm3,ymm5,ymm3
	vpmuludq	ymm4,ymm5,ymm4
	vpunpcklqdq	ymm7,ymm7,ymm8
	vpaddq	ymm2,ymm13,ymm3
	vpaddq	ymm3,ymm14,ymm4
	vpunpcklqdq	ymm10,ymm9,ymm10
	vpmuludq	ymm4,ymm0,YMMWORD PTR[80+rax]
	vpmuludq	ymm0,ymm5,ymm1
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]
	vpaddq	ymm4,ymm15,ymm4
	vpaddq	ymm0,ymm11,ymm0




	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm12,ymm11

	vpsrlq	ymm15,ymm4,26
	vpand	ymm4,ymm4,ymm5

	vpsrlq	ymm9,ymm10,4

	vpsrlq	ymm12,ymm1,26
	vpand	ymm1,ymm1,ymm5
	vpaddq	ymm2,ymm2,ymm12

	vpaddq	ymm0,ymm0,ymm15
	vpsllq	ymm15,ymm15,2
	vpaddq	ymm0,ymm0,ymm15

	vpand	ymm9,ymm9,ymm5
	vpsrlq	ymm8,ymm7,26

	vpsrlq	ymm13,ymm2,26
	vpand	ymm2,ymm2,ymm5
	vpaddq	ymm3,ymm3,ymm13

	vpaddq	ymm2,ymm2,ymm9
	vpsrlq	ymm10,ymm10,30

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm1,ymm11

	vpsrlq	ymm6,ymm6,40

	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14

	vpand	ymm7,ymm7,ymm5
	vpand	ymm8,ymm8,ymm5
	vpand	ymm10,ymm10,ymm5
	vpor	ymm6,ymm6,YMMWORD PTR[32+rcx]

	sub	rdx,64
	jnz	$L$oop_avx2

DB	066h,090h
$L$tail_avx2::







	vpaddq	ymm0,ymm7,ymm0
	vmovdqu	ymm7,YMMWORD PTR[4+rsp]
	vpaddq	ymm1,ymm8,ymm1
	vmovdqu	ymm8,YMMWORD PTR[36+rsp]
	vpaddq	ymm3,ymm10,ymm3
	vmovdqu	ymm9,YMMWORD PTR[100+rsp]
	vpaddq	ymm4,ymm6,ymm4
	vmovdqu	ymm10,YMMWORD PTR[52+rax]
	vmovdqu	ymm5,YMMWORD PTR[116+rax]

	vpmuludq	ymm13,ymm7,ymm2
	vpmuludq	ymm14,ymm8,ymm2
	vpmuludq	ymm15,ymm9,ymm2
	vpmuludq	ymm11,ymm10,ymm2
	vpmuludq	ymm12,ymm5,ymm2

	vpmuludq	ymm6,ymm8,ymm0
	vpmuludq	ymm2,ymm8,ymm1
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2
	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm4,YMMWORD PTR[68+rsp]
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm11,ymm11,ymm2

	vpmuludq	ymm6,ymm7,ymm0
	vpmuludq	ymm2,ymm7,ymm1
	vpaddq	ymm11,ymm11,ymm6
	vmovdqu	ymm8,YMMWORD PTR[((-12))+rax]
	vpaddq	ymm12,ymm12,ymm2
	vpmuludq	ymm6,ymm7,ymm3
	vpmuludq	ymm2,ymm7,ymm4
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm15,ymm15,ymm2

	vpmuludq	ymm6,ymm8,ymm3
	vpmuludq	ymm2,ymm8,ymm4
	vpaddq	ymm11,ymm11,ymm6
	vpaddq	ymm12,ymm12,ymm2
	vmovdqu	ymm2,YMMWORD PTR[20+rax]
	vpmuludq	ymm6,ymm9,ymm1
	vpmuludq	ymm9,ymm9,ymm0
	vpaddq	ymm14,ymm14,ymm6
	vpaddq	ymm13,ymm13,ymm9

	vpmuludq	ymm6,ymm2,ymm1
	vpmuludq	ymm2,ymm2,ymm0
	vpaddq	ymm15,ymm15,ymm6
	vpaddq	ymm14,ymm14,ymm2
	vpmuludq	ymm6,ymm10,ymm3
	vpmuludq	ymm2,ymm10,ymm4
	vpaddq	ymm12,ymm12,ymm6
	vpaddq	ymm13,ymm13,ymm2

	vpmuludq	ymm3,ymm5,ymm3
	vpmuludq	ymm4,ymm5,ymm4
	vpaddq	ymm2,ymm13,ymm3
	vpaddq	ymm3,ymm14,ymm4
	vpmuludq	ymm4,ymm0,YMMWORD PTR[84+rax]
	vpmuludq	ymm0,ymm5,ymm1
	vmovdqa	ymm5,YMMWORD PTR[64+rcx]
	vpaddq	ymm4,ymm15,ymm4
	vpaddq	ymm0,ymm11,ymm0




	vpsrldq	ymm8,ymm12,8
	vpsrldq	ymm9,ymm2,8
	vpsrldq	ymm10,ymm3,8
	vpsrldq	ymm6,ymm4,8
	vpsrldq	ymm7,ymm0,8
	vpaddq	ymm12,ymm12,ymm8
	vpaddq	ymm2,ymm2,ymm9
	vpaddq	ymm3,ymm3,ymm10
	vpaddq	ymm4,ymm4,ymm6
	vpaddq	ymm0,ymm0,ymm7

	vpermq	ymm10,ymm3,02h
	vpermq	ymm6,ymm4,02h
	vpermq	ymm7,ymm0,02h
	vpermq	ymm8,ymm12,02h
	vpermq	ymm9,ymm2,02h
	vpaddq	ymm3,ymm3,ymm10
	vpaddq	ymm4,ymm4,ymm6
	vpaddq	ymm0,ymm0,ymm7
	vpaddq	ymm12,ymm12,ymm8
	vpaddq	ymm2,ymm2,ymm9




	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm12,ymm11

	vpsrlq	ymm15,ymm4,26
	vpand	ymm4,ymm4,ymm5

	vpsrlq	ymm12,ymm1,26
	vpand	ymm1,ymm1,ymm5
	vpaddq	ymm2,ymm2,ymm12

	vpaddq	ymm0,ymm0,ymm15
	vpsllq	ymm15,ymm15,2
	vpaddq	ymm0,ymm0,ymm15

	vpsrlq	ymm13,ymm2,26
	vpand	ymm2,ymm2,ymm5
	vpaddq	ymm3,ymm3,ymm13

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm1,ymm1,ymm11

	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpaddq	ymm4,ymm4,ymm14

	vmovd	DWORD PTR[(-112)+rdi],xmm0
	vmovd	DWORD PTR[(-108)+rdi],xmm1
	vmovd	DWORD PTR[(-104)+rdi],xmm2
	vmovd	DWORD PTR[(-100)+rdi],xmm3
	vmovd	DWORD PTR[(-96)+rdi],xmm4
	vmovdqa	xmm6,XMMWORD PTR[80+r11]
	vmovdqa	xmm7,XMMWORD PTR[96+r11]
	vmovdqa	xmm8,XMMWORD PTR[112+r11]
	vmovdqa	xmm9,XMMWORD PTR[128+r11]
	vmovdqa	xmm10,XMMWORD PTR[144+r11]
	vmovdqa	xmm11,XMMWORD PTR[160+r11]
	vmovdqa	xmm12,XMMWORD PTR[176+r11]
	vmovdqa	xmm13,XMMWORD PTR[192+r11]
	vmovdqa	xmm14,XMMWORD PTR[208+r11]
	vmovdqa	xmm15,XMMWORD PTR[224+r11]
	lea	rsp,QWORD PTR[248+r11]
$L$do_avx2_epilogue::
	vzeroupper
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_avx2::
poly1305_blocks_avx2	ENDP

ALIGN	32
poly1305_blocks_avx512	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_avx512::


	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
$L$blocks_avx512::
	mov	eax,15
	kmovw	k2,eax
	lea	r11,QWORD PTR[((-248))+rsp]
	sub	rsp,01c8h
	vmovdqa	XMMWORD PTR[80+r11],xmm6
	vmovdqa	XMMWORD PTR[96+r11],xmm7
	vmovdqa	XMMWORD PTR[112+r11],xmm8
	vmovdqa	XMMWORD PTR[128+r11],xmm9
	vmovdqa	XMMWORD PTR[144+r11],xmm10
	vmovdqa	XMMWORD PTR[160+r11],xmm11
	vmovdqa	XMMWORD PTR[176+r11],xmm12
	vmovdqa	XMMWORD PTR[192+r11],xmm13
	vmovdqa	XMMWORD PTR[208+r11],xmm14
	vmovdqa	XMMWORD PTR[224+r11],xmm15
$L$do_avx512_body::
	lea	rcx,QWORD PTR[$L$const]
	lea	rdi,QWORD PTR[((48+64))+rdi]
	vmovdqa	ymm9,YMMWORD PTR[96+rcx]


	vmovdqu	xmm11,XMMWORD PTR[((-64))+rdi]
	and	rsp,-512
	vmovdqu	xmm12,XMMWORD PTR[((-48))+rdi]
	mov	rax,020h
	vmovdqu	xmm7,XMMWORD PTR[((-32))+rdi]
	vmovdqu	xmm13,XMMWORD PTR[((-16))+rdi]
	vmovdqu	xmm8,XMMWORD PTR[rdi]
	vmovdqu	xmm14,XMMWORD PTR[16+rdi]
	vmovdqu	xmm10,XMMWORD PTR[32+rdi]
	vmovdqu	xmm15,XMMWORD PTR[48+rdi]
	vmovdqu	xmm6,XMMWORD PTR[64+rdi]
	vpermd	zmm16,zmm9,zmm11
	vpbroadcastq	zmm5,QWORD PTR[64+rcx]
	vpermd	zmm17,zmm9,zmm12
	vpermd	zmm21,zmm9,zmm7
	vpermd	zmm18,zmm9,zmm13
	vmovdqa64	ZMMWORD PTR[rsp]{k2},zmm16
	vpsrlq	zmm7,zmm16,32
	vpermd	zmm22,zmm9,zmm8
	vmovdqu64	ZMMWORD PTR[rax*1+rsp]{k2},zmm17
	vpsrlq	zmm8,zmm17,32
	vpermd	zmm19,zmm9,zmm14
	vmovdqa64	ZMMWORD PTR[64+rsp]{k2},zmm21
	vpermd	zmm23,zmm9,zmm10
	vpermd	zmm20,zmm9,zmm15
	vmovdqu64	ZMMWORD PTR[64+rax*1+rsp]{k2},zmm18
	vpermd	zmm24,zmm9,zmm6
	vmovdqa64	ZMMWORD PTR[128+rsp]{k2},zmm22
	vmovdqu64	ZMMWORD PTR[128+rax*1+rsp]{k2},zmm19
	vmovdqa64	ZMMWORD PTR[192+rsp]{k2},zmm23
	vmovdqu64	ZMMWORD PTR[192+rax*1+rsp]{k2},zmm20
	vmovdqa64	ZMMWORD PTR[256+rsp]{k2},zmm24










	vpmuludq	zmm11,zmm16,zmm7
	vpmuludq	zmm12,zmm17,zmm7
	vpmuludq	zmm13,zmm18,zmm7
	vpmuludq	zmm14,zmm19,zmm7
	vpmuludq	zmm15,zmm20,zmm7
	vpsrlq	zmm9,zmm18,32

	vpmuludq	zmm25,zmm24,zmm8
	vpmuludq	zmm26,zmm16,zmm8
	vpmuludq	zmm27,zmm17,zmm8
	vpmuludq	zmm28,zmm18,zmm8
	vpmuludq	zmm29,zmm19,zmm8
	vpsrlq	zmm10,zmm19,32
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29

	vpmuludq	zmm25,zmm23,zmm9
	vpmuludq	zmm26,zmm24,zmm9
	vpmuludq	zmm28,zmm17,zmm9
	vpmuludq	zmm29,zmm18,zmm9
	vpmuludq	zmm27,zmm16,zmm9
	vpsrlq	zmm6,zmm20,32
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm13,zmm13,zmm27

	vpmuludq	zmm25,zmm22,zmm10
	vpmuludq	zmm28,zmm16,zmm10
	vpmuludq	zmm29,zmm17,zmm10
	vpmuludq	zmm26,zmm23,zmm10
	vpmuludq	zmm27,zmm24,zmm10
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27

	vpmuludq	zmm28,zmm24,zmm6
	vpmuludq	zmm29,zmm16,zmm6
	vpmuludq	zmm25,zmm21,zmm6
	vpmuludq	zmm26,zmm22,zmm6
	vpmuludq	zmm27,zmm23,zmm6
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27



	vmovdqu64	zmm10,ZMMWORD PTR[rsi]
	vmovdqu64	zmm6,ZMMWORD PTR[64+rsi]
	lea	rsi,QWORD PTR[128+rsi]




	vpsrlq	zmm28,zmm14,26
	vpandq	zmm14,zmm14,zmm5
	vpaddq	zmm15,zmm15,zmm28

	vpsrlq	zmm25,zmm11,26
	vpandq	zmm11,zmm11,zmm5
	vpaddq	zmm12,zmm12,zmm25

	vpsrlq	zmm29,zmm15,26
	vpandq	zmm15,zmm15,zmm5

	vpsrlq	zmm26,zmm12,26
	vpandq	zmm12,zmm12,zmm5
	vpaddq	zmm13,zmm13,zmm26

	vpaddq	zmm11,zmm11,zmm29
	vpsllq	zmm29,zmm29,2
	vpaddq	zmm11,zmm11,zmm29

	vpsrlq	zmm27,zmm13,26
	vpandq	zmm13,zmm13,zmm5
	vpaddq	zmm14,zmm14,zmm27

	vpsrlq	zmm25,zmm11,26
	vpandq	zmm11,zmm11,zmm5
	vpaddq	zmm12,zmm12,zmm25

	vpsrlq	zmm28,zmm14,26
	vpandq	zmm14,zmm14,zmm5
	vpaddq	zmm15,zmm15,zmm28





	vpunpcklqdq	zmm7,zmm10,zmm6
	vpunpckhqdq	zmm6,zmm10,zmm6






	vmovdqa32	zmm25,ZMMWORD PTR[128+rcx]
	mov	eax,07777h
	kmovw	k1,eax

	vpermd	zmm16,zmm25,zmm16
	vpermd	zmm17,zmm25,zmm17
	vpermd	zmm18,zmm25,zmm18
	vpermd	zmm19,zmm25,zmm19
	vpermd	zmm20,zmm25,zmm20

	vpermd	zmm16{k1},zmm25,zmm11
	vpermd	zmm17{k1},zmm25,zmm12
	vpermd	zmm18{k1},zmm25,zmm13
	vpermd	zmm19{k1},zmm25,zmm14
	vpermd	zmm20{k1},zmm25,zmm15

	vpslld	zmm21,zmm17,2
	vpslld	zmm22,zmm18,2
	vpslld	zmm23,zmm19,2
	vpslld	zmm24,zmm20,2
	vpaddd	zmm21,zmm21,zmm17
	vpaddd	zmm22,zmm22,zmm18
	vpaddd	zmm23,zmm23,zmm19
	vpaddd	zmm24,zmm24,zmm20

	vpbroadcastq	zmm30,QWORD PTR[32+rcx]

	vpsrlq	zmm9,zmm7,52
	vpsllq	zmm10,zmm6,12
	vporq	zmm9,zmm9,zmm10
	vpsrlq	zmm8,zmm7,26
	vpsrlq	zmm10,zmm6,14
	vpsrlq	zmm6,zmm6,40
	vpandq	zmm9,zmm9,zmm5
	vpandq	zmm7,zmm7,zmm5




	vpaddq	zmm2,zmm9,zmm2
	sub	rdx,192
	jbe	$L$tail_avx512
	jmp	$L$oop_avx512

ALIGN	32
$L$oop_avx512::




























	vpmuludq	zmm14,zmm17,zmm2
	vpaddq	zmm0,zmm7,zmm0
	vpmuludq	zmm15,zmm18,zmm2
	vpandq	zmm8,zmm8,zmm5
	vpmuludq	zmm11,zmm23,zmm2
	vpandq	zmm10,zmm10,zmm5
	vpmuludq	zmm12,zmm24,zmm2
	vporq	zmm6,zmm6,zmm30
	vpmuludq	zmm13,zmm16,zmm2
	vpaddq	zmm1,zmm8,zmm1
	vpaddq	zmm3,zmm10,zmm3
	vpaddq	zmm4,zmm6,zmm4

	vmovdqu64	zmm10,ZMMWORD PTR[rsi]
	vmovdqu64	zmm6,ZMMWORD PTR[64+rsi]
	lea	rsi,QWORD PTR[128+rsi]
	vpmuludq	zmm28,zmm19,zmm0
	vpmuludq	zmm29,zmm20,zmm0
	vpmuludq	zmm25,zmm16,zmm0
	vpmuludq	zmm26,zmm17,zmm0
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26

	vpmuludq	zmm28,zmm18,zmm1
	vpmuludq	zmm29,zmm19,zmm1
	vpmuludq	zmm25,zmm24,zmm1
	vpmuludq	zmm27,zmm18,zmm0
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm13,zmm13,zmm27

	vpunpcklqdq	zmm7,zmm10,zmm6
	vpunpckhqdq	zmm6,zmm10,zmm6

	vpmuludq	zmm28,zmm16,zmm3
	vpmuludq	zmm29,zmm17,zmm3
	vpmuludq	zmm26,zmm16,zmm1
	vpmuludq	zmm27,zmm17,zmm1
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27

	vpmuludq	zmm28,zmm24,zmm4
	vpmuludq	zmm29,zmm16,zmm4
	vpmuludq	zmm25,zmm22,zmm3
	vpmuludq	zmm26,zmm23,zmm3
	vpaddq	zmm14,zmm14,zmm28
	vpmuludq	zmm27,zmm24,zmm3
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27

	vpmuludq	zmm25,zmm21,zmm4
	vpmuludq	zmm26,zmm22,zmm4
	vpmuludq	zmm27,zmm23,zmm4
	vpaddq	zmm0,zmm11,zmm25
	vpaddq	zmm1,zmm12,zmm26
	vpaddq	zmm2,zmm13,zmm27




	vpsrlq	zmm9,zmm7,52
	vpsllq	zmm10,zmm6,12

	vpsrlq	zmm3,zmm14,26
	vpandq	zmm14,zmm14,zmm5
	vpaddq	zmm4,zmm15,zmm3

	vporq	zmm9,zmm9,zmm10

	vpsrlq	zmm11,zmm0,26
	vpandq	zmm0,zmm0,zmm5
	vpaddq	zmm1,zmm1,zmm11

	vpandq	zmm9,zmm9,zmm5

	vpsrlq	zmm15,zmm4,26
	vpandq	zmm4,zmm4,zmm5

	vpsrlq	zmm12,zmm1,26
	vpandq	zmm1,zmm1,zmm5
	vpaddq	zmm2,zmm2,zmm12

	vpaddq	zmm0,zmm0,zmm15
	vpsllq	zmm15,zmm15,2
	vpaddq	zmm0,zmm0,zmm15

	vpaddq	zmm2,zmm2,zmm9
	vpsrlq	zmm8,zmm7,26

	vpsrlq	zmm13,zmm2,26
	vpandq	zmm2,zmm2,zmm5
	vpaddq	zmm3,zmm14,zmm13

	vpsrlq	zmm10,zmm6,14

	vpsrlq	zmm11,zmm0,26
	vpandq	zmm0,zmm0,zmm5
	vpaddq	zmm1,zmm1,zmm11

	vpsrlq	zmm6,zmm6,40

	vpsrlq	zmm14,zmm3,26
	vpandq	zmm3,zmm3,zmm5
	vpaddq	zmm4,zmm4,zmm14

	vpandq	zmm7,zmm7,zmm5




	sub	rdx,128
	ja	$L$oop_avx512

$L$tail_avx512::





	vpsrlq	zmm16,zmm16,32
	vpsrlq	zmm17,zmm17,32
	vpsrlq	zmm18,zmm18,32
	vpsrlq	zmm23,zmm23,32
	vpsrlq	zmm24,zmm24,32
	vpsrlq	zmm19,zmm19,32
	vpsrlq	zmm20,zmm20,32
	vpsrlq	zmm21,zmm21,32
	vpsrlq	zmm22,zmm22,32



	lea	rsi,QWORD PTR[rdx*1+rsi]


	vpaddq	zmm0,zmm7,zmm0

	vpmuludq	zmm14,zmm17,zmm2
	vpmuludq	zmm15,zmm18,zmm2
	vpmuludq	zmm11,zmm23,zmm2
	vpandq	zmm8,zmm8,zmm5
	vpmuludq	zmm12,zmm24,zmm2
	vpandq	zmm10,zmm10,zmm5
	vpmuludq	zmm13,zmm16,zmm2
	vporq	zmm6,zmm6,zmm30
	vpaddq	zmm1,zmm8,zmm1
	vpaddq	zmm3,zmm10,zmm3
	vpaddq	zmm4,zmm6,zmm4

	vmovdqu	xmm7,XMMWORD PTR[rsi]
	vpmuludq	zmm28,zmm19,zmm0
	vpmuludq	zmm29,zmm20,zmm0
	vpmuludq	zmm25,zmm16,zmm0
	vpmuludq	zmm26,zmm17,zmm0
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26

	vmovdqu	xmm8,XMMWORD PTR[16+rsi]
	vpmuludq	zmm28,zmm18,zmm1
	vpmuludq	zmm29,zmm19,zmm1
	vpmuludq	zmm25,zmm24,zmm1
	vpmuludq	zmm27,zmm18,zmm0
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm13,zmm13,zmm27

	vinserti128	ymm7,ymm7,XMMWORD PTR[32+rsi],1
	vpmuludq	zmm28,zmm16,zmm3
	vpmuludq	zmm29,zmm17,zmm3
	vpmuludq	zmm26,zmm16,zmm1
	vpmuludq	zmm27,zmm17,zmm1
	vpaddq	zmm14,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27

	vinserti128	ymm8,ymm8,XMMWORD PTR[48+rsi],1
	vpmuludq	zmm28,zmm24,zmm4
	vpmuludq	zmm29,zmm16,zmm4
	vpmuludq	zmm25,zmm22,zmm3
	vpmuludq	zmm26,zmm23,zmm3
	vpmuludq	zmm27,zmm24,zmm3
	vpaddq	zmm3,zmm14,zmm28
	vpaddq	zmm15,zmm15,zmm29
	vpaddq	zmm11,zmm11,zmm25
	vpaddq	zmm12,zmm12,zmm26
	vpaddq	zmm13,zmm13,zmm27

	vpmuludq	zmm25,zmm21,zmm4
	vpmuludq	zmm26,zmm22,zmm4
	vpmuludq	zmm27,zmm23,zmm4
	vpaddq	zmm0,zmm11,zmm25
	vpaddq	zmm1,zmm12,zmm26
	vpaddq	zmm2,zmm13,zmm27




	mov	eax,1
	vpermq	zmm14,zmm3,0b1h
	vpermq	zmm4,zmm15,0b1h
	vpermq	zmm11,zmm0,0b1h
	vpermq	zmm12,zmm1,0b1h
	vpermq	zmm13,zmm2,0b1h
	vpaddq	zmm3,zmm3,zmm14
	vpaddq	zmm4,zmm4,zmm15
	vpaddq	zmm0,zmm0,zmm11
	vpaddq	zmm1,zmm1,zmm12
	vpaddq	zmm2,zmm2,zmm13

	kmovw	k3,eax
	vpermq	zmm14,zmm3,02h
	vpermq	zmm15,zmm4,02h
	vpermq	zmm11,zmm0,02h
	vpermq	zmm12,zmm1,02h
	vpermq	zmm13,zmm2,02h
	vpaddq	zmm3,zmm3,zmm14
	vpaddq	zmm4,zmm4,zmm15
	vpaddq	zmm0,zmm0,zmm11
	vpaddq	zmm1,zmm1,zmm12
	vpaddq	zmm2,zmm2,zmm13

	vextracti64x4	ymm14,zmm3,01h
	vextracti64x4	ymm15,zmm4,01h
	vextracti64x4	ymm11,zmm0,01h
	vextracti64x4	ymm12,zmm1,01h
	vextracti64x4	ymm13,zmm2,01h
	vpaddq	zmm3{k3}{z},zmm3,zmm14
	vpaddq	zmm4{k3}{z},zmm4,zmm15
	vpaddq	zmm0{k3}{z},zmm0,zmm11
	vpaddq	zmm1{k3}{z},zmm1,zmm12
	vpaddq	zmm2{k3}{z},zmm2,zmm13



	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpsrldq	ymm9,ymm7,6
	vpsrldq	ymm10,ymm8,6
	vpunpckhqdq	ymm6,ymm7,ymm8
	vpaddq	ymm4,ymm4,ymm14

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpunpcklqdq	ymm9,ymm9,ymm10
	vpunpcklqdq	ymm7,ymm7,ymm8
	vpaddq	ymm1,ymm1,ymm11

	vpsrlq	ymm15,ymm4,26
	vpand	ymm4,ymm4,ymm5

	vpsrlq	ymm12,ymm1,26
	vpand	ymm1,ymm1,ymm5
	vpsrlq	ymm10,ymm9,30
	vpsrlq	ymm9,ymm9,4
	vpaddq	ymm2,ymm2,ymm12

	vpaddq	ymm0,ymm0,ymm15
	vpsllq	ymm15,ymm15,2
	vpsrlq	ymm8,ymm7,26
	vpsrlq	ymm6,ymm6,40
	vpaddq	ymm0,ymm0,ymm15

	vpsrlq	ymm13,ymm2,26
	vpand	ymm2,ymm2,ymm5
	vpand	ymm9,ymm9,ymm5
	vpand	ymm7,ymm7,ymm5
	vpaddq	ymm3,ymm3,ymm13

	vpsrlq	ymm11,ymm0,26
	vpand	ymm0,ymm0,ymm5
	vpaddq	ymm2,ymm9,ymm2
	vpand	ymm8,ymm8,ymm5
	vpaddq	ymm1,ymm1,ymm11

	vpsrlq	ymm14,ymm3,26
	vpand	ymm3,ymm3,ymm5
	vpand	ymm10,ymm10,ymm5
	vpor	ymm6,ymm6,YMMWORD PTR[32+rcx]
	vpaddq	ymm4,ymm4,ymm14

	lea	rax,QWORD PTR[144+rsp]
	add	rdx,64
	jnz	$L$tail_avx2

	vpsubq	ymm2,ymm2,ymm9
	vmovd	DWORD PTR[(-112)+rdi],xmm0
	vmovd	DWORD PTR[(-108)+rdi],xmm1
	vmovd	DWORD PTR[(-104)+rdi],xmm2
	vmovd	DWORD PTR[(-100)+rdi],xmm3
	vmovd	DWORD PTR[(-96)+rdi],xmm4
	vzeroall
	movdqa	xmm6,XMMWORD PTR[80+r11]
	movdqa	xmm7,XMMWORD PTR[96+r11]
	movdqa	xmm8,XMMWORD PTR[112+r11]
	movdqa	xmm9,XMMWORD PTR[128+r11]
	movdqa	xmm10,XMMWORD PTR[144+r11]
	movdqa	xmm11,XMMWORD PTR[160+r11]
	movdqa	xmm12,XMMWORD PTR[176+r11]
	movdqa	xmm13,XMMWORD PTR[192+r11]
	movdqa	xmm14,XMMWORD PTR[208+r11]
	movdqa	xmm15,XMMWORD PTR[224+r11]
	lea	rsp,QWORD PTR[248+r11]
$L$do_avx512_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_avx512::
poly1305_blocks_avx512	ENDP

ALIGN	32
poly1305_init_base2_44	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_init_base2_44::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	xor	rax,rax
	mov	QWORD PTR[rdi],rax
	mov	QWORD PTR[8+rdi],rax
	mov	QWORD PTR[16+rdi],rax

	cmp	rsi,0
	je	$L$no_key_base2_44

$L$init_base2_44::
	mov	rax,00ffffffc0fffffffh
	mov	rcx,00ffffffc0ffffffch
	and	rax,QWORD PTR[rsi]
	mov	r8,000000fffffffffffh
	and	rcx,QWORD PTR[8+rsi]
	mov	r9,000000fffffffffffh
	and	r8,rax
	shrd	rax,rcx,44
	mov	QWORD PTR[40+rdi],r8
	and	rax,r9
	shr	rcx,24
	mov	QWORD PTR[48+rdi],rax
	lea	rax,QWORD PTR[rax*4+rax]
	mov	QWORD PTR[56+rdi],rcx
	shl	rax,2
	lea	rcx,QWORD PTR[rcx*4+rcx]
	shl	rcx,2
	mov	QWORD PTR[24+rdi],rax
	mov	QWORD PTR[32+rdi],rcx
	mov	QWORD PTR[64+rdi],-1
	lea	r10,QWORD PTR[poly1305_blocks_vpmadd52]
	lea	r11,QWORD PTR[poly1305_emit_base2_44]
	mov	QWORD PTR[rdx],r10
	mov	QWORD PTR[8+rdx],r11
	mov	eax,1
$L$no_key_base2_44::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_init_base2_44::
poly1305_init_base2_44	ENDP

ALIGN	32
poly1305_blocks_base2_44	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_base2_44::


	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
$L$blocks_base2_44::
	push	rbx

	push	rbp

	push	r12

	push	r13

	push	r14

	push	r15


	and	rdx,-16
	add	rdx,rsi
	shl	rcx,40
	push	rdx

$L$blocks_base2_44_body::

	mov	rdx,QWORD PTR[rdi]
	mov	r8,QWORD PTR[8+rdi]
	mov	r9,QWORD PTR[16+rdi]

	mov	r13,QWORD PTR[40+rdi]
	mov	r14,QWORD PTR[48+rdi]
	mov	r15,QWORD PTR[32+rdi]
	mov	rax,0fffff00000000000h
	jmp	$L$oop_base2_44
	ud2

ALIGN	32
$L$oop_base2_44::
	mov	r11,QWORD PTR[rsi]
	mov	r12,QWORD PTR[8+rsi]
	lea	rsi,QWORD PTR[16+rsi]

	andn	r10,rax,r11
	shrd	r11,r12,44
	add	rdx,r10
	shr	r12,24
	andn	r11,rax,r11
	add	r9,rcx

	add	r8,r11
	add	r9,r12


	mulx	rbx,r10,r13
	mulx	rcx,r11,r14
	mulx	rbp,r12,QWORD PTR[56+rdi]

	mov	rdx,r8
	mulx	r8,rax,r15
	add	r10,rax
	adc	r8,rbx
	mulx	rbx,rax,r13
	add	r11,rax
	adc	rcx,rbx
	mulx	rbx,rax,r14
	mov	rdx,r9
	add	r12,rax
	adc	rbp,rbx

	mulx	rbx,rax,QWORD PTR[24+rdi]
	add	r10,rax
	adc	r8,rbx
	mulx	r9,rax,r15
	add	r11,rax
	adc	r9,rcx
	mulx	rbx,rax,r13
	add	r12,rax
	adc	rbp,rbx

	mov	rax,0fffff00000000000h
	andn	rdx,rax,r10
	shrd	r10,r8,44
	add	r11,r10
	adc	r9,0
	andn	r8,rax,r11
	shrd	r11,r9,44
	mov	r9,003ffffffffffh
	add	r12,r11
	adc	rbp,0
	and	r9,r12
	shrd	r12,rbp,42

	mov	rcx,010000000000h
	lea	r12,QWORD PTR[r12*4+r12]
	add	rdx,r12

	cmp	rsi,QWORD PTR[rsp]
	jb	$L$oop_base2_44

	mov	QWORD PTR[rdi],rdx
	mov	QWORD PTR[8+rdi],r8
	mov	QWORD PTR[16+rdi],r9

	mov	r15,QWORD PTR[8+rsp]

	mov	r14,QWORD PTR[16+rsp]

	mov	r13,QWORD PTR[24+rsp]

	mov	r12,QWORD PTR[32+rsp]

	mov	rbp,QWORD PTR[40+rsp]

	mov	rbx,QWORD PTR[48+rsp]

	lea	rsp,QWORD PTR[56+rsp]

$L$blocks_base2_44_epilogue::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret

$L$SEH_end_poly1305_blocks_base2_44::
poly1305_blocks_base2_44	ENDP

ALIGN	32
poly1305_blocks_vpmadd52	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_vpmadd52::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	and	rdx,-16
	jz	$L$no_data_vpmadd52

	mov	r8,QWORD PTR[64+rdi]






	mov	r9,030h
	mov	r10,010h
	cmp	rdx,040h
	cmovae	r9,r10
	test	r8,r8
	cmovns	r9,r10

	and	r9,rdx
	jz	$L$blocks_vpmadd52_4x

	sub	rdx,r9
	cmovz	rdx,r9
	jz	$L$blocks_base2_44


	mov	r10d,7
	mov	r11d,1
	shl	rcx,40
	kmovw	k7,r10d
	lea	r10,QWORD PTR[$L$2_44_inp_permd]
	kmovw	k1,r11d

	vmovq	xmm21,rcx
	shr	rcx,40
	vmovdqa64	ymm19,YMMWORD PTR[r10]
	vmovdqa64	ymm20,YMMWORD PTR[32+r10]
	vpermq	ymm21,ymm21,0cfh
	vmovdqa64	ymm22,YMMWORD PTR[64+r10]

	vmovdqu64	ymm16{k7}{z},[rdi]
	vmovdqu64	ymm3{k7}{z},[40+rdi]
	vmovdqu64	ymm4{k7}{z},[32+rdi]
	vmovdqu64	ymm5{k7}{z},[24+rdi]

	vmovdqa64	ymm23,YMMWORD PTR[96+r10]
	vmovdqa64	ymm24,YMMWORD PTR[128+r10]

	vmovdqu32	xmm18,XMMWORD PTR[rsi]
	lea	rsi,QWORD PTR[16+rsi]

	vpermd	ymm18,ymm19,ymm18
	vpsrlvq	ymm18,ymm18,ymm20
	vpandq	ymm18,ymm18,ymm22
	vporq	ymm18,ymm18,ymm21

	vpaddq	ymm16,ymm16,ymm18
	vpxord	ymm27,ymm27,ymm27
	vpxord	ymm28,ymm28,ymm28

	vpermq	ymm0{k7}{z},ymm16,0
	vpermq	ymm1{k7}{z},ymm16,85
	vpermq	ymm2{k7}{z},ymm16,170

	vpxord	ymm18,ymm18,ymm18
	vpxord	ymm26,ymm26,ymm26
	vpmadd52luq	ymm27,ymm0,ymm3
	vpmadd52huq	ymm28,ymm0,ymm3

	vpxord	ymm16,ymm16,ymm16
	vpxord	ymm17,ymm17,ymm17
	vpmadd52luq	ymm18,ymm1,ymm4
	vpmadd52huq	ymm26,ymm1,ymm4

	vpmadd52luq	ymm16,ymm2,ymm5
	vpmadd52huq	ymm17,ymm2,ymm5

	vpaddq	ymm27,ymm27,ymm18
	vpaddq	ymm28,ymm28,ymm26
	vpaddq	ymm16,ymm16,ymm27
	vpaddq	ymm17,ymm17,ymm28

	vpsrlvq	ymm18,ymm16,ymm23
	vpsllvq	ymm17,ymm17,ymm24
	vpandq	ymm16,ymm16,ymm22

	vpaddq	ymm17,ymm17,ymm18

	vpermq	ymm17,ymm17,147

	vpaddq	ymm16,ymm16,ymm17

	vpsrlvq	ymm18,ymm16,ymm23
	vpandq	ymm16,ymm16,ymm22

	vpermq	ymm18,ymm18,147

	vpaddq	ymm16,ymm16,ymm18

	vpermq	ymm18{k1}{z},ymm16,147

	vpaddq	ymm16,ymm16,ymm18
	vpsllq	ymm18,ymm18,2

	vpaddq	ymm16,ymm16,ymm18

	vmovdqu64	YMMWORD PTR[rdi]{k7},ymm16

	jmp	$L$blocks_vpmadd52_4x

$L$no_data_vpmadd52::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_blocks_vpmadd52::
poly1305_blocks_vpmadd52	ENDP

ALIGN	32
poly1305_blocks_vpmadd52_4x	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_blocks_vpmadd52_4x::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	and	rdx,-16
	jz	$L$no_data_vpmadd52_4x

	mov	r8,QWORD PTR[64+rdi]

$L$blocks_vpmadd52_4x::
	shl	rcx,40
	shr	rdx,4
	vpbroadcastq	ymm31,rcx

	vmovdqa64	ymm30,YMMWORD PTR[$L$x_mask44]
	mov	eax,5
	kmovw	k1,eax

	test	r8,r8
	js	$L$init_vpmadd52

	vmovq	xmm0,QWORD PTR[rdi]
	vmovq	xmm1,QWORD PTR[8+rdi]
	vmovq	xmm2,QWORD PTR[16+rdi]

	test	rdx,3
	jnz	$L$blocks_vpmadd52_2x_do

$L$blocks_vpmadd52_4x_do::
	vpbroadcastq	ymm3,QWORD PTR[64+rdi]
	vpbroadcastq	ymm4,QWORD PTR[96+rdi]
	vpbroadcastq	ymm5,QWORD PTR[128+rdi]
	vpbroadcastq	ymm16,QWORD PTR[160+rdi]

$L$blocks_vpmadd52_4x_key_loaded::
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm17,ymm17,2




	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vmovdqu64	ymm27,YMMWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]

	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27



	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm2,ymm2,ymm26
	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30

	sub	rdx,4
	jz	$L$tail_vpmadd52_4x
	jmp	$L$oop_vpmadd52_4x
	ud2

ALIGN	32
$L$init_vpmadd52::
	vmovq	xmm16,QWORD PTR[24+rdi]
	vmovq	xmm2,QWORD PTR[56+rdi]
	vmovq	xmm17,QWORD PTR[32+rdi]
	vmovq	xmm3,QWORD PTR[40+rdi]
	vmovq	xmm4,QWORD PTR[48+rdi]

	vmovdqa	ymm0,ymm3
	vmovdqa	ymm1,ymm4
	vmovdqa	ymm5,ymm2

	mov	eax,2

$L$mul_init_vpmadd52::
	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2

	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0

	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29



	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29

	vpaddq	ymm20,ymm20,ymm19

	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29

	vpaddq	ymm22,ymm22,ymm21

	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29

	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2

	vpaddq	ymm0,ymm0,ymm23

	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30

	vpaddq	ymm1,ymm1,ymm29

	dec	eax
	jz	$L$done_init_vpmadd52

	vpunpcklqdq	ymm4,ymm1,ymm4
	vpbroadcastq	xmm1,xmm1
	vpunpcklqdq	ymm5,ymm2,ymm5
	vpbroadcastq	xmm2,xmm2
	vpunpcklqdq	ymm3,ymm0,ymm3
	vpbroadcastq	xmm0,xmm0

	vpsllq	ymm16,ymm4,2
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm16,ymm16,ymm4
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm16,ymm16,2
	vpsllq	ymm17,ymm17,2

	jmp	$L$mul_init_vpmadd52
	ud2

ALIGN	32
$L$done_init_vpmadd52::
	vinserti128	ymm4,ymm1,xmm4,1
	vinserti128	ymm5,ymm2,xmm5,1
	vinserti128	ymm3,ymm0,xmm3,1

	vpermq	ymm4,ymm4,216
	vpermq	ymm5,ymm5,216
	vpermq	ymm3,ymm3,216

	vpsllq	ymm16,ymm4,2
	vpaddq	ymm16,ymm16,ymm4
	vpsllq	ymm16,ymm16,2

	vmovq	xmm0,QWORD PTR[rdi]
	vmovq	xmm1,QWORD PTR[8+rdi]
	vmovq	xmm2,QWORD PTR[16+rdi]

	test	rdx,3
	jnz	$L$done_init_vpmadd52_2x

	vmovdqu64	YMMWORD PTR[64+rdi],ymm3
	vpbroadcastq	ymm3,xmm3
	vmovdqu64	YMMWORD PTR[96+rdi],ymm4
	vpbroadcastq	ymm4,xmm4
	vmovdqu64	YMMWORD PTR[128+rdi],ymm5
	vpbroadcastq	ymm5,xmm5
	vmovdqu64	YMMWORD PTR[160+rdi],ymm16
	vpbroadcastq	ymm16,xmm16

	jmp	$L$blocks_vpmadd52_4x_key_loaded
	ud2

ALIGN	32
$L$done_init_vpmadd52_2x::
	vmovdqu64	YMMWORD PTR[64+rdi],ymm3
	vpsrldq	ymm3,ymm3,8
	vmovdqu64	YMMWORD PTR[96+rdi],ymm4
	vpsrldq	ymm4,ymm4,8
	vmovdqu64	YMMWORD PTR[128+rdi],ymm5
	vpsrldq	ymm5,ymm5,8
	vmovdqu64	YMMWORD PTR[160+rdi],ymm16
	vpsrldq	ymm16,ymm16,8
	jmp	$L$blocks_vpmadd52_2x_key_loaded
	ud2

ALIGN	32
$L$blocks_vpmadd52_2x_do::
	vmovdqu64	ymm5{k1}{z},[((128+8))+rdi]
	vmovdqu64	ymm16{k1}{z},[((160+8))+rdi]
	vmovdqu64	ymm3{k1}{z},[((64+8))+rdi]
	vmovdqu64	ymm4{k1}{z},[((96+8))+rdi]

$L$blocks_vpmadd52_2x_key_loaded::
	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vpxorq	ymm27,ymm27,ymm27
	lea	rsi,QWORD PTR[32+rsi]

	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27



	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm2,ymm2,ymm26
	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30

	jmp	$L$tail_vpmadd52_2x
	ud2

ALIGN	32
$L$oop_vpmadd52_4x::

	vpaddq	ymm0,ymm0,ymm24
	vpaddq	ymm1,ymm1,ymm25

	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2

	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0

	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29

	vmovdqu64	ymm26,YMMWORD PTR[rsi]
	vmovdqu64	ymm27,YMMWORD PTR[32+rsi]
	lea	rsi,QWORD PTR[64+rsi]
	vpunpcklqdq	ymm25,ymm26,ymm27
	vpunpckhqdq	ymm27,ymm26,ymm27



	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29

	vpsrlq	ymm26,ymm27,24
	vporq	ymm26,ymm26,ymm31
	vpaddq	ymm20,ymm20,ymm19

	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29

	vpandq	ymm24,ymm25,ymm30
	vpsrlq	ymm25,ymm25,44
	vpsllq	ymm27,ymm27,20
	vpaddq	ymm22,ymm22,ymm21

	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29

	vpaddq	ymm2,ymm2,ymm26
	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2

	vpaddq	ymm0,ymm0,ymm23
	vporq	ymm25,ymm25,ymm27
	vpandq	ymm25,ymm25,ymm30

	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30

	vpaddq	ymm1,ymm1,ymm29

	sub	rdx,4
	jnz	$L$oop_vpmadd52_4x

$L$tail_vpmadd52_4x::
	vmovdqu64	ymm5,YMMWORD PTR[128+rdi]
	vmovdqu64	ymm16,YMMWORD PTR[160+rdi]
	vmovdqu64	ymm3,YMMWORD PTR[64+rdi]
	vmovdqu64	ymm4,YMMWORD PTR[96+rdi]

$L$tail_vpmadd52_2x::
	vpsllq	ymm17,ymm5,2
	vpaddq	ymm17,ymm17,ymm5
	vpsllq	ymm17,ymm17,2


	vpaddq	ymm0,ymm0,ymm24
	vpaddq	ymm1,ymm1,ymm25

	vpxorq	ymm18,ymm18,ymm18
	vpxorq	ymm19,ymm19,ymm19
	vpxorq	ymm20,ymm20,ymm20
	vpxorq	ymm21,ymm21,ymm21
	vpxorq	ymm22,ymm22,ymm22
	vpxorq	ymm23,ymm23,ymm23
	vpmadd52luq	ymm18,ymm16,ymm2
	vpxorq	ymm24,ymm24,ymm24
	vpxorq	ymm25,ymm25,ymm25
	vpmadd52huq	ymm19,ymm16,ymm2
	vpxorq	ymm26,ymm26,ymm26
	vpxorq	ymm27,ymm27,ymm27
	vpmadd52luq	ymm20,ymm17,ymm2
	vpxorq	ymm28,ymm28,ymm28
	vpxorq	ymm29,ymm29,ymm29
	vpmadd52huq	ymm21,ymm17,ymm2
	vpmadd52luq	ymm22,ymm3,ymm2
	vpmadd52huq	ymm23,ymm3,ymm2

	vpmadd52luq	ymm24,ymm3,ymm0
	vpmadd52huq	ymm25,ymm3,ymm0
	vpmadd52luq	ymm26,ymm4,ymm0
	vpmadd52huq	ymm27,ymm4,ymm0
	vpmadd52luq	ymm28,ymm5,ymm0
	vpmadd52huq	ymm29,ymm5,ymm0

	vpmadd52luq	ymm18,ymm17,ymm1
	vpmadd52huq	ymm19,ymm17,ymm1
	vpmadd52luq	ymm20,ymm3,ymm1
	vpmadd52huq	ymm21,ymm3,ymm1
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm25
	vpmadd52luq	ymm22,ymm4,ymm1
	vpaddq	ymm20,ymm20,ymm26
	vpaddq	ymm21,ymm21,ymm27
	vpmadd52huq	ymm23,ymm4,ymm1
	vpaddq	ymm22,ymm22,ymm28
	vpaddq	ymm23,ymm23,ymm29




	mov	eax,1
	kmovw	k1,eax
	vpsrldq	ymm24,ymm18,8
	vpsrldq	ymm0,ymm19,8
	vpsrldq	ymm25,ymm20,8
	vpsrldq	ymm1,ymm21,8
	vpaddq	ymm18,ymm18,ymm24
	vpaddq	ymm19,ymm19,ymm0
	vpsrldq	ymm26,ymm22,8
	vpsrldq	ymm2,ymm23,8
	vpaddq	ymm20,ymm20,ymm25
	vpaddq	ymm21,ymm21,ymm1
	vpermq	ymm24,ymm18,02h
	vpermq	ymm0,ymm19,02h
	vpaddq	ymm22,ymm22,ymm26
	vpaddq	ymm23,ymm23,ymm2

	vpermq	ymm25,ymm20,02h
	vpermq	ymm1,ymm21,02h
	vpaddq	ymm18{k1}{z},ymm18,ymm24
	vpaddq	ymm19{k1}{z},ymm19,ymm0
	vpermq	ymm26,ymm22,02h
	vpermq	ymm2,ymm23,02h
	vpaddq	ymm20{k1}{z},ymm20,ymm25
	vpaddq	ymm21{k1}{z},ymm21,ymm1
	vpaddq	ymm22{k1}{z},ymm22,ymm26
	vpaddq	ymm23{k1}{z},ymm23,ymm2



	vpsrlq	ymm29,ymm18,44
	vpsllq	ymm19,ymm19,8
	vpandq	ymm0,ymm18,ymm30
	vpaddq	ymm19,ymm19,ymm29

	vpaddq	ymm20,ymm20,ymm19

	vpsrlq	ymm29,ymm20,44
	vpsllq	ymm21,ymm21,8
	vpandq	ymm1,ymm20,ymm30
	vpaddq	ymm21,ymm21,ymm29

	vpaddq	ymm22,ymm22,ymm21

	vpsrlq	ymm29,ymm22,42
	vpsllq	ymm23,ymm23,10
	vpandq	ymm2,ymm22,YMMWORD PTR[$L$x_mask42]
	vpaddq	ymm23,ymm23,ymm29

	vpaddq	ymm0,ymm0,ymm23
	vpsllq	ymm23,ymm23,2

	vpaddq	ymm0,ymm0,ymm23

	vpsrlq	ymm29,ymm0,44
	vpandq	ymm0,ymm0,ymm30

	vpaddq	ymm1,ymm1,ymm29


	sub	rdx,2
	ja	$L$blocks_vpmadd52_4x_do

	vmovq	QWORD PTR[rdi],xmm0
	vmovq	QWORD PTR[8+rdi],xmm1
	vmovq	QWORD PTR[16+rdi],xmm2
	vzeroupper

$L$no_data_vpmadd52_4x::
	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_blocks_vpmadd52_4x::
poly1305_blocks_vpmadd52_4x	ENDP

ALIGN	32
poly1305_emit_base2_44	PROC PRIVATE
	DB	243,15,30,250
	mov	QWORD PTR[8+rsp],rdi	;WIN64 prologue
	mov	QWORD PTR[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_poly1305_emit_base2_44::

	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	r8,QWORD PTR[rdi]
	mov	r9,QWORD PTR[8+rdi]
	mov	r10,QWORD PTR[16+rdi]

	mov	rax,r9
	shr	r9,20
	shl	rax,44
	mov	rcx,r10
	shr	r10,40
	shl	rcx,24

	add	r8,rax
	adc	r9,rcx
	adc	r10,0

	mov	rax,r8
	add	r8,5
	mov	rcx,r9
	adc	r9,0
	adc	r10,0
	shr	r10,2
	cmovnz	rax,r8
	cmovnz	rcx,r9

	add	rax,QWORD PTR[rdx]
	adc	rcx,QWORD PTR[8+rdx]
	mov	QWORD PTR[rsi],rax
	mov	QWORD PTR[8+rsi],rcx

	mov	rdi,QWORD PTR[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD PTR[16+rsp]
	DB	0F3h,0C3h		;repret
$L$SEH_end_poly1305_emit_base2_44::
poly1305_emit_base2_44	ENDP
ALIGN	64
$L$const::
$L$mask24::
	DD	00ffffffh,0,00ffffffh,0,00ffffffh,0,00ffffffh,0
$L$129::
	DD	16777216,0,16777216,0,16777216,0,16777216,0
$L$mask26::
	DD	03ffffffh,0,03ffffffh,0,03ffffffh,0,03ffffffh,0
$L$permd_avx2::
	DD	2,2,2,3,2,0,2,1
$L$permd_avx512::
	DD	0,0,0,1,0,2,0,3,0,4,0,5,0,6,0,7

$L$2_44_inp_permd::
	DD	0,1,1,2,2,3,7,7
$L$2_44_inp_shift::
	DQ	0,12,24,64
$L$2_44_mask::
	DQ	0fffffffffffh,0fffffffffffh,03ffffffffffh,0ffffffffffffffffh
$L$2_44_shift_rgt::
	DQ	44,44,42,64
$L$2_44_shift_lft::
	DQ	8,8,10,64

ALIGN	64
$L$x_mask44::
	DQ	0fffffffffffh,0fffffffffffh,0fffffffffffh,0fffffffffffh
	DQ	0fffffffffffh,0fffffffffffh,0fffffffffffh,0fffffffffffh
$L$x_mask42::
	DQ	03ffffffffffh,03ffffffffffh,03ffffffffffh,03ffffffffffh
	DQ	03ffffffffffh,03ffffffffffh,03ffffffffffh,03ffffffffffh
DB	80,111,108,121,49,51,48,53,32,102,111,114,32,120,56,54
DB	95,54,52,44,32,67,82,89,80,84,79,71,65,77,83,32
DB	98,121,32,64,100,111,116,45,97,115,109,0
ALIGN	16
PUBLIC	xor128_encrypt_n_pad

ALIGN	16
xor128_encrypt_n_pad	PROC PUBLIC
	DB	243,15,30,250

	sub	rdx,r8
	sub	rcx,r8
	mov	r10,r9
	shr	r9,4
	jz	$L$tail_enc
	nop
$L$oop_enc_xmm::
	movdqu	xmm0,XMMWORD PTR[r8*1+rdx]
	pxor	xmm0,XMMWORD PTR[r8]
	movdqu	XMMWORD PTR[r8*1+rcx],xmm0
	movdqa	XMMWORD PTR[r8],xmm0
	lea	r8,QWORD PTR[16+r8]
	dec	r9
	jnz	$L$oop_enc_xmm

	and	r10,15
	jz	$L$done_enc

$L$tail_enc::
	mov	r9,16
	sub	r9,r10
	xor	eax,eax
$L$oop_enc_byte::
	mov	al,BYTE PTR[r8*1+rdx]
	xor	al,BYTE PTR[r8]
	mov	BYTE PTR[r8*1+rcx],al
	mov	BYTE PTR[r8],al
	lea	r8,QWORD PTR[1+r8]
	dec	r10
	jnz	$L$oop_enc_byte

	xor	eax,eax
$L$oop_enc_pad::
	mov	BYTE PTR[r8],al
	lea	r8,QWORD PTR[1+r8]
	dec	r9
	jnz	$L$oop_enc_pad

$L$done_enc::
	mov	rax,r8
	DB	0F3h,0C3h		;repret
xor128_encrypt_n_pad	ENDP

PUBLIC	xor128_decrypt_n_pad

ALIGN	16
xor128_decrypt_n_pad	PROC PUBLIC
	DB	243,15,30,250

	sub	rdx,r8
	sub	rcx,r8
	mov	r10,r9
	shr	r9,4
	jz	$L$tail_dec
	nop
$L$oop_dec_xmm::
	movdqu	xmm0,XMMWORD PTR[r8*1+rdx]
	movdqa	xmm1,XMMWORD PTR[r8]
	pxor	xmm1,xmm0
	movdqu	XMMWORD PTR[r8*1+rcx],xmm1
	movdqa	XMMWORD PTR[r8],xmm0
	lea	r8,QWORD PTR[16+r8]
	dec	r9
	jnz	$L$oop_dec_xmm

	pxor	xmm1,xmm1
	and	r10,15
	jz	$L$done_dec

$L$tail_dec::
	mov	r9,16
	sub	r9,r10
	xor	eax,eax
	xor	r11,r11
$L$oop_dec_byte::
	mov	r11b,BYTE PTR[r8*1+rdx]
	mov	al,BYTE PTR[r8]
	xor	al,r11b
	mov	BYTE PTR[r8*1+rcx],al
	mov	BYTE PTR[r8],r11b
	lea	r8,QWORD PTR[1+r8]
	dec	r10
	jnz	$L$oop_dec_byte

	xor	eax,eax
$L$oop_dec_pad::
	mov	BYTE PTR[r8],al
	lea	r8,QWORD PTR[1+r8]
	dec	r9
	jnz	$L$oop_dec_pad

$L$done_dec::
	mov	rax,r8
	DB	0F3h,0C3h		;repret
xor128_decrypt_n_pad	ENDP
EXTERN	__imp_RtlVirtualUnwind:NEAR

ALIGN	16
se_handler	PROC PRIVATE
	DB	243,15,30,250

	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64

	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]

	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]

	mov	r10d,DWORD PTR[r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jb	$L$common_seh_tail

	mov	rax,QWORD PTR[152+r8]

	mov	r10d,DWORD PTR[4+r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jae	$L$common_seh_tail

	lea	rax,QWORD PTR[56+rax]

	mov	rbx,QWORD PTR[((-8))+rax]
	mov	rbp,QWORD PTR[((-16))+rax]
	mov	r12,QWORD PTR[((-24))+rax]
	mov	r13,QWORD PTR[((-32))+rax]
	mov	r14,QWORD PTR[((-40))+rax]
	mov	r15,QWORD PTR[((-48))+rax]
	mov	QWORD PTR[144+r8],rbx
	mov	QWORD PTR[160+r8],rbp
	mov	QWORD PTR[216+r8],r12
	mov	QWORD PTR[224+r8],r13
	mov	QWORD PTR[232+r8],r14
	mov	QWORD PTR[240+r8],r15

	jmp	$L$common_seh_tail
se_handler	ENDP


ALIGN	16
avx_handler	PROC PRIVATE
	DB	243,15,30,250

	push	rsi
	push	rdi
	push	rbx
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	pushfq
	sub	rsp,64

	mov	rax,QWORD PTR[120+r8]
	mov	rbx,QWORD PTR[248+r8]

	mov	rsi,QWORD PTR[8+r9]
	mov	r11,QWORD PTR[56+r9]

	mov	r10d,DWORD PTR[r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jb	$L$common_seh_tail

	mov	rax,QWORD PTR[152+r8]

	mov	r10d,DWORD PTR[4+r11]
	lea	r10,QWORD PTR[r10*1+rsi]
	cmp	rbx,r10
	jae	$L$common_seh_tail

	mov	rax,QWORD PTR[208+r8]

	lea	rsi,QWORD PTR[80+rax]
	lea	rax,QWORD PTR[248+rax]
	lea	rdi,QWORD PTR[512+r8]
	mov	ecx,20
	DD	0a548f3fch

$L$common_seh_tail::
	mov	rdi,QWORD PTR[8+rax]
	mov	rsi,QWORD PTR[16+rax]
	mov	QWORD PTR[152+r8],rax
	mov	QWORD PTR[168+r8],rsi
	mov	QWORD PTR[176+r8],rdi

	mov	rdi,QWORD PTR[40+r9]
	mov	rsi,r8
	mov	ecx,154
	DD	0a548f3fch

	mov	rsi,r9
	xor	rcx,rcx
	mov	rdx,QWORD PTR[8+rsi]
	mov	r8,QWORD PTR[rsi]
	mov	r9,QWORD PTR[16+rsi]
	mov	r10,QWORD PTR[40+rsi]
	lea	r11,QWORD PTR[56+rsi]
	lea	r12,QWORD PTR[24+rsi]
	mov	QWORD PTR[32+rsp],r10
	mov	QWORD PTR[40+rsp],r11
	mov	QWORD PTR[48+rsp],r12
	mov	QWORD PTR[56+rsp],rcx
	call	QWORD PTR[__imp_RtlVirtualUnwind]

	mov	eax,1
	add	rsp,64
	popfq
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	pop	rbx
	pop	rdi
	pop	rsi
	DB	0F3h,0C3h		;repret
avx_handler	ENDP

.text$	ENDS
.pdata	SEGMENT READONLY ALIGN(4)
ALIGN	4
	DD	imagerel $L$SEH_begin_poly1305_init
	DD	imagerel $L$SEH_end_poly1305_init
	DD	imagerel $L$SEH_info_poly1305_init

	DD	imagerel $L$SEH_begin_poly1305_blocks
	DD	imagerel $L$SEH_end_poly1305_blocks
	DD	imagerel $L$SEH_info_poly1305_blocks

	DD	imagerel $L$SEH_begin_poly1305_emit
	DD	imagerel $L$SEH_end_poly1305_emit
	DD	imagerel $L$SEH_info_poly1305_emit
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx
	DD	imagerel $L$base2_64_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_1

	DD	imagerel $L$base2_64_avx
	DD	imagerel $L$even_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_2

	DD	imagerel $L$even_avx
	DD	imagerel $L$SEH_end_poly1305_blocks_avx
	DD	imagerel $L$SEH_info_poly1305_blocks_avx_3
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx2
	DD	imagerel $L$base2_64_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_1

	DD	imagerel $L$base2_64_avx2
	DD	imagerel $L$even_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_2

	DD	imagerel $L$even_avx2
	DD	imagerel $L$SEH_end_poly1305_blocks_avx2
	DD	imagerel $L$SEH_info_poly1305_blocks_avx2_3
	DD	imagerel $L$SEH_begin_poly1305_blocks_avx512
	DD	imagerel $L$SEH_end_poly1305_blocks_avx512
	DD	imagerel $L$SEH_info_poly1305_blocks_avx512
	DD	imagerel $L$SEH_begin_poly1305_init_base2_44
	DD	imagerel $L$SEH_end_poly1305_init_base2_44
	DD	imagerel $L$SEH_info_poly1305_init_base2_44

	DD	imagerel $L$SEH_begin_poly1305_blocks_base2_44
	DD	imagerel $L$SEH_end_poly1305_blocks_base2_44
	DD	imagerel $L$SEH_info_poly1305_blocks_base2_44

	DD	imagerel $L$SEH_begin_poly1305_blocks_vpmadd52
	DD	imagerel $L$SEH_end_poly1305_blocks_vpmadd52
	DD	imagerel $L$SEH_info_poly1305_blocks_vpmadd52

	DD	imagerel $L$SEH_begin_poly1305_blocks_vpmadd52_4x
	DD	imagerel $L$SEH_end_poly1305_blocks_vpmadd52_4x
	DD	imagerel $L$SEH_info_poly1305_blocks_vpmadd52_4x

	DD	imagerel $L$SEH_begin_poly1305_emit_base2_44
	DD	imagerel $L$SEH_end_poly1305_emit_base2_44
	DD	imagerel $L$SEH_info_poly1305_emit_base2_44
.pdata	ENDS
.xdata	SEGMENT READONLY ALIGN(8)
ALIGN	8
$L$SEH_info_poly1305_init::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$blocks_body,imagerel $L$blocks_epilogue

$L$SEH_info_poly1305_emit::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0
$L$SEH_info_poly1305_blocks_avx_1::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$blocks_avx_body,imagerel $L$blocks_avx_epilogue

$L$SEH_info_poly1305_blocks_avx_2::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$base2_64_avx_body,imagerel $L$base2_64_avx_epilogue

$L$SEH_info_poly1305_blocks_avx_3::
DB	9,0,0,0
	DD	imagerel avx_handler
	DD	imagerel $L$do_avx_body,imagerel $L$do_avx_epilogue
$L$SEH_info_poly1305_blocks_avx2_1::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$blocks_avx2_body,imagerel $L$blocks_avx2_epilogue

$L$SEH_info_poly1305_blocks_avx2_2::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$base2_64_avx2_body,imagerel $L$base2_64_avx2_epilogue

$L$SEH_info_poly1305_blocks_avx2_3::
DB	9,0,0,0
	DD	imagerel avx_handler
	DD	imagerel $L$do_avx2_body,imagerel $L$do_avx2_epilogue
$L$SEH_info_poly1305_blocks_avx512::
DB	9,0,0,0
	DD	imagerel avx_handler
	DD	imagerel $L$do_avx512_body,imagerel $L$do_avx512_epilogue
$L$SEH_info_poly1305_init_base2_44::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks_base2_44::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	imagerel $L$blocks_base2_44_body,imagerel $L$blocks_base2_44_epilogue

$L$SEH_info_poly1305_blocks_vpmadd52::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0

$L$SEH_info_poly1305_blocks_vpmadd52_4x::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0

$L$SEH_info_poly1305_emit_base2_44::
DB	9,0,0,0
	DD	imagerel se_handler
	DD	0,0

.xdata	ENDS
END
