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
  db 0B3h, 0D9h, 0CDh, 034h
  db 0AAh, 09Dh, 066h, 06Dh
  db 03Eh, 08Eh, 047h, 056h
  db 043h, 000h, 046h, 0BBh
  db 0A2h, 014h, 03Dh, 040h
  db 097h, 090h, 02Eh, 0F7h
  db 032h, 008h, 0BAh, 0CCh
  db 031h, 0FDh, 0F8h, 060h

  ; record the number of the arguments
  db 002h, 000h, 000h, 000h
  ; record the total argument data size
  db 018h, 000h, 000h, 000h

  ; record the size of the argument-1
  db 0B7h, 0D9h, 0CDh, 034h
  ; argument-1 data
  db 0D2h, 0CBh, 052h, 07Fh

  ; record the size of the argument-2
  db 032h, 08Eh, 047h, 056h
  ; argument-2 data
  db 022h, 061h, 027h, 0DAh
  db 0C0h, 076h, 05Fh, 022h
  db 0F4h, 0F3h, 04Dh, 0F7h

IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
