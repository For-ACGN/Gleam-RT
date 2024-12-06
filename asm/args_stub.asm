IFDEF _WIN32
.model flat
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

  db 0E7h, 09Fh, 03Eh, 006h    ; 32 bytes decrypt key
  db 0F6h, 0A5h, 08Bh, 06Eh
  db 020h, 022h, 0F4h, 03Eh
  db 0E9h, 0B5h, 00Bh, 08Ah
  db 0E6h, 0ABh, 016h, 035h
  db 010h, 0BBh, 038h, 0A6h
  db 0CDh, 0A8h, 0B6h, 0C1h
  db 0CDh, 00Ah, 0B0h, 015h
  db 003h, 000h, 000h, 000h    ; record the number of the arguments
  db 01Ch, 000h, 000h, 000h    ; record the total argument data size
  db 073h, 0A7h, 036h, 0A4h    ; 4 bytes checksum for check header
  db 061h, 00Bh, 00Bh, 003h    ; record the size of the argument-1
  db 03Dh, 0FFh, 0F9h, 013h    ; argument-1 data
  db 035h, 040h, 029h, 00Bh    ; record the size of the argument-2
  db 016h, 029h, 047h, 04Ah    ; argument-2 data
  db 08Fh, 0B4h, 053h, 001h
  db 07Fh, 039h, 0F1h, 024h
  db 0FAh, 009h, 017h, 00Eh    ; record the size of the argument-3
                               ; argument-3 data (empty)
IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
