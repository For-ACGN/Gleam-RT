IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  _Epilogue@0 proc
ELSE
  Epilogue proc
ENDIF

  ret

IFDEF _WIN32
  _Epilogue@0 endp
ELSE
  Epilogue endp
ENDIF

end
