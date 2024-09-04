IFDEF _WIN32
.model tiny
ENDIF

; +---------+----------+----------+-----------+----------+----------+
; |   key   | checksum | num args | args size | arg size | arg data |
; +---------+----------+----------+-----------+----------+----------+
; | 32 byte |  uint32  |  uint32  |  uint32   |  uint32  |   var    |
; +---------+----------+----------+-----------+----------+----------+

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
ELSE
  Argument_Stub proc
ENDIF

  ; 32 bytes decrypt key
  db 01Dh, 08Ch, 017h, 045h
  db 07Dh, 0B7h, 003h, 0DEh
  db 050h, 000h, 0F9h, 081h
  db 037h, 01Dh, 0BDh, 0B3h
  db 057h, 073h, 031h, 092h
  db 04Fh, 076h, 082h, 020h
  db 0E4h, 065h, 0CCh, 068h
  db 082h, 03Dh, 035h, 0EEh

  ; 4 bytes checksum
  db 0E9h, 018h, 0D6h, 091h

  ; record the number of the arguments
  db 003h, 000h, 000h, 000h
  ; record the total argument data size
  db 01Ch, 000h, 000h, 000h

  ; record the size of the argument-1
  db 0E6h, 088h, 017h, 045h
  ; argument-1 data
  db 005h, 099h, 061h, 0F8h

  ; record the size of the argument-2
  db 04Eh, 00Ch, 0F9h, 081h
  ; argument-2 data
  db 056h, 01Dh, 0BDh, 0B3h
  db 054h, 073h, 031h, 092h
  db 04Eh, 076h, 082h, 043h

  ; record the size of the argument-3
  db 0E4h, 065h, 0CCh, 068h
  ; argument-3 data(empty)

IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
