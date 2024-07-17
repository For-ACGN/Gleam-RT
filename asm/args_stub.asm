IFDEF _WIN32
.model tiny
ENDIF

; total size(offset) is (32 + 8 * 4) = 64 bytes

; +----------+----------+----------+----------+----------+
; |    key   |   size   | num args | arg size | arg data |
; +----------+----------+----------+----------+----------+
; | 32 bytes |  uint32  |  uint32  |  uint32  |    var   |
; +----------+----------+----------+----------+----------+

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
ELSE
  Argument_Stub proc
ENDIF

  db 11h, 11h, 11h, 11h  ; 32 bytes decrypt key
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h
  db 11h, 11h, 11h, 11h

  db 18h, 00h, 00h, 00h  ; total cipher data size

  db 02h, 00h, 00h, 00h  ; record the number of the arguments

  db 04h, 00h, 00h, 00h  ; record the size of the argument-1
  db 78h, 56h, 34h, 12h  ; argument-1 data

  db 09h, 00h, 00h, 00h  ; record the size of the argument-2
  db "aaaabbbbccc", 00h  ; argument-2 data

IFDEF _WIN32
  _Argument_Stub@0 endp
ELSE
  Argument_Stub endp
ENDIF

end
