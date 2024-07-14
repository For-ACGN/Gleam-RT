IFDEF _WIN32
.model tiny
ENDIF

; +----------+----------+----------+----------+
; |    key   | num args | arg size | arg data |
; +----------+----------+----------+----------+
; | 32 bytes |  uint32  |  uint32  |    var   |
; +----------+----------+----------+----------+

.code

args_stub proc
  db 11h, 11h, 11h, 11h  ; 32 bytes decrypt key
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h

  db 02h, 00h, 00h, 00h  ; record the number of the arguments

  db 04h, 00h, 00h, 00h  ; record the size of the argument-1
  db 78h, 56h, 34h, 12h  ; argument-1 data

  db 09h, 00h, 00h, 00h  ; record the size of the argument-2
  db "abcdefgh", 00h     ; argument-2 data

args_stub endp

end
