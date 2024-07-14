IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  _Epilogue@0 proc
    ret
  _Epilogue@0 endp
ELSE
  Epilogue proc
    ret
  Epilogue endp
ENDIF

end
