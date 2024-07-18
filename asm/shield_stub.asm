IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  _Shield_Stub@0 proc
ELSE
  Shield_Stub proc
ENDIF

  ; reverse 512 bytes for store generated stub
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h
  db 00h, 00h, 00h, 00h, 00h, 00h, 00h, 00h

IFDEF _WIN32
  _Shield_Stub@0 endp
ELSE
  Shield_Stub endp
ENDIF

end
