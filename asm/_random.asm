IFDEF _WIN32
.model tiny
ENDIF

.code

; _GenerateSeed@0 proc
;   ; pop ebx               ; get return address
;   ; push ebx              ; restore stack
;   add eax, ebx          ; add return address
;   add eax, [esp+8]      ; add data from stack
;   imul eax, esp         ; eax * esp
; 
;   add eax, ebx
;   ror eax, 4
;   add eax, ecx
;   ror eax, 6
;   add eax, edx
;   ror eax, 7
;   add eax, edi
;   ror eax, 9
;   add eax, esi
;   ror eax, 3
;   add eax, ebp
;   ror eax, 3
;   add eax, esp
;   ror eax, 12
;   ret
; _GenerateSeed@0 endp

GenerateSeed proc
  sub rsp, 8            ; alloc stack for store rax     
  mov [rsp], rax        ; save rax to stack
  pop rax               ; get return address
  push rax              ; restore return address
  add rax, [rsp]        ; add old rax and return address
  add rsp, 8            ; restore stack

  ror rax, 32           ; shift rax
  add rax, rbx          ; add rbx address
  add rax, [rsp+8]      ; add data from stack
  imul rax, rsp         ; rax * rsp
  add rax, rsp          ; add rsp

  ; add and ror rax
  add rax, rbx
  ror rax, 16
  add rax, rcx
  ror rax, 15
  add rax, rdx
  ror rax, 14
  add rax, rdi
  ror rax, 13
  add rax, rsi
  ror rax, 12
  add rax, rbp
  ror rax, 11
  add rax, rsp

  add rax, r8
  ror rax, 8
  add rax, r9
  ror rax, 16
  add rax, r10
  ror rax, 24
  add rax, r11
  ror rax, 32
  add rax, r12
  ror rax, 4
  add rax, r13
  ror rax, 8
  add rax, r14
  ror rax, 12
  add rax, r15
  ror rax, 16

  ; change registers for loop
  add rax, 1024
  mov rcx, rax
  add rax, 2048
  mov rdx, rax
  add rax, 4096
  mov r8, rax 
  add rax, 8192
  mov r9, rax 

  ; XOR shift
  mov rcx, rax
  rol rax, 13
  xor rax, rcx
  mov rcx, rax
  ror rax, 17
  xor rax, rcx
  mov rcx, rax
  rol rax, 5
  xor rax, rcx

  ret
GenerateSeed endp

end
