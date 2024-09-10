IFDEF _WIN32
.model tiny
ENDIF

; +---------+----------+-----------+----------+-----------+-----------+
; |   key   | num args | args size | checksum | arg1 size | arg1 data |
; +---------+----------+-----------+----------+-----------+-----------+
; | 32 byte |  uint32  |  uint32   |  uint32  |  uint32   |    var    |
; +---------+----------+-----------+----------+-----------+-----------+

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
ELSE
  Argument_Stub proc
ENDIF

  ; 32 bytes decrypt key
  db 068h, 005h, 015h, 066h
  db 0C7h, 099h, 007h, 00Bh
  db 0BDh, 0D0h, 0F1h, 0E1h
  db 0ADh, 07Dh, 08Bh, 0F8h
  db 061h, 07Bh, 07Bh, 0BAh
  db 03Ch, 05Eh, 04Eh, 035h
  db 018h, 0AEh, 0BAh, 094h
  db 080h, 005h, 057h, 0B3h

  ; record the number of the arguments
  db 003h, 000h, 000h, 000h

  ; record the total argument data size
  db 01Ch, 000h, 000h, 000h

  ; 4 bytes checksum for check header
  db 054h, 064h, 09Bh, 081h

  ; record the size of the argument-1
  db 093h, 001h, 015h, 066h
  ; argument-1 data
  db 0BFh, 0B7h, 065h, 02Dh

  ; record the size of the argument-2
  db 0A3h, 0DCh, 0F1h, 0E1h
  ; argument-2 data
  db 0CCh, 07Dh, 08Bh, 0F8h
  db 062h, 07Bh, 07Bh, 0BAh
  db 03Dh, 05Eh, 04Eh, 056h

  ; record the size of the argument-3
  db 018h, 0AEh, 0BAh, 094h
  ; argument-3 data(empty)

IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
