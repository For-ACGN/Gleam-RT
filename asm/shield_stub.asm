IFDEF _WIN32
.model tiny
ENDIF

.code

; reverse 512 bytes for store generated stub
Shield_Stub proc
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
Shield_Stub endp

end
