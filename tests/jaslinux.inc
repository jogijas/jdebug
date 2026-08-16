macro create ptrfname,mode,hfile
	    {
	      mov ebx,ptrfname
	      mov ecx,mode
	      mov eax,8
	      int 80h
	      mov [hfile], eax
	   } 
macro close hfile
	    {
	    mov ebx,[hfile]
	    mov eax,6
	    int 80h
	    }
macro exit
	    {
	    xor	ebx,ebx
	    mov	eax,1
	    int	80h
	    }
macro write hfile,msg,msg_len
	    {
	    mov ecx,msg
	    mov ebx,[hfile]
	    mov edx,msg_len
	    mov eax,4
	    int 80h

	    }
