IFDEF _WIN32
.model tiny
ENDIF

.code

; reverse 512 bytes for store generated stub
shield_stub proc
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
shield_stub endp

end
