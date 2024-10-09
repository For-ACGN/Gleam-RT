IFDEF _WIN32
.model flat
ENDIF

.code

IFDEF _WIN32
  _Align_Stub@0 proc
  db 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh
  db 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh
  _Align_Stub@0 endp
ELSE
  Align_Stub proc
  db 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh
  db 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh, 0FFh
  Align_Stub endp
ENDIF

end
