IFDEF _WIN32
.model tiny
ENDIF

; total offset of the shellcode tail is (32 + 8 + (4+4) + (4+12)) = 64 bytes

; +---------+----------+-----------+----------+----------+
; |   key   | num args | args size | arg size | arg data |
; +---------+----------+-----------+----------+----------+
; | 32 byte |  uint32  |  uint32   |  uint32  |   var    |
; +---------+----------+-----------+----------+----------+

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
ELSE
  Argument_Stub proc
ENDIF

  ; 32 bytes decrypt key
  db 0BBh, 0DEh, 0F5h, 00Ah
  db 0E1h, 0CFh, 0B8h, 022h
  db 06Dh, 065h, 0CCh, 06Dh
  db 067h, 0FFh, 0F5h, 0EBh
  db 02Ah, 095h, 0A2h, 0F3h
  db 025h, 09Ah, 055h, 0B7h
  db 03Eh, 051h, 0F8h, 005h
  db 03Ah, 0F5h, 076h, 00Eh

  ; record the number of the arguments
  db 002h, 000h, 000h, 000h
  ; record the total argument data size
  db 018h, 000h, 000h, 000h

  ; record the size of the argument-1
  db 040h, 0DAh, 0F5h, 00Ah
  ; argument-1 data
  db 099h, 0E1h, 0DAh, 004h

  ; record the size of the argument-2
  db 073h, 069h, 0CCh, 06Dh
  ; argument-2 data
  db 006h, 0FFh, 0F5h, 0EBh
  db 029h, 095h, 0A2h, 0F3h
  db 024h, 09Ah, 055h, 0D4h

IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
