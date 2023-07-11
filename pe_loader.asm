; 2022.
; Simple PE Loader.
;

	format PE GUI 4.0
	entry start

	include '..\..\include\win32a.inc'

	buf_size 			equ 260			; размер буфера для сохранения информации о файле (путь, имя, расширение).
	MEMSIZE 			equ 65535		; размер выделенной памяти.
	PE 					equ 0x4550
	E_LFANEW 			equ 0x3C
	SECTIONALIGMENT 	equ 0x38		; from NT head.
	FILEALIGNMENT 		equ 0x3C		; from NT head.
	SIZEOFIMAGE 		equ 0x50		; from NT head.
	IMAGEBASE 			equ 0x34		; from NT head.
	ENTRYPOINT 			equ 0x28		; from NT head.
	NUMBEROFSECTION 	equ 0x06		; from NT head. 
	SIZEOFHEADER 		equ 0x54		; from NT head.
	DATADIRECTORY 		equ 0x78		; from NT head.
	IMPORTTABLE 		equ 0x08 		; from DataDirectory.
	RELOCTABLE 			equ 0x28 		; from DataDirectory.

	SIZEIMAGE_IMPORT 	equ 0x14  		; 20 bytes size _IMAGE_IMPORT_DESCRIPTOR
	RVAFIRSTTHUNK 		equ 0x10	    ; 16 byte offset _First_Thunk_ in _IMAGE_IMPORT_DESCRIPTOR
	RVANAME 			equ 0xC			; 12 byte offset _Name_ in _IMAGE_IMPORT_DESCRIPTOR

	ADDRESSOFFUNCTION 	equ 0x1c 		; from _IMAGE_IMPORT_DIRECTORY_

section '.data' data readable writeable

	mesText  db 'Signature PE',0
	mesText2 db 'Can not load DLL',0                
	mesText3 db 'Signature PE DLL',0
	mesText4 db 'Can not find fun in DLL',0
	mesTitle db "Error",0

	Filter du 'PE files', 00, '*.exe', 00, 00
  
	Handler dd ?						; дискриптор основного модуля.	
	buf_file db buf_size dup (0x41)	; буффер где сохраниться открытый файл (путь, имя, расширение).  
	hwnd dd ?							; дискриптор второго окна.

	filehwnd dd ?						; дискриптор созданного/открытого файла. 
	hMemory dd ?						; Идентификатоp выделенного блока памяти.
	addrPE dd ?							; дискриптор фиксированного учаска памяти.
	name_open du 'Simple PE Loadre. Import, Export, Reloc tables.', 00      ; заголовок окна открытия файла.
 
	SizeReadWrite dd ?					; число прочитаных/записанных байт.
   
    ofn OPENFILENAME <>
	
	addrPEImage dd ? 					; адрес выделнной памяти для PE 
	
	elfanew 			dd ?
	sectionAlignmentRVA dd ? 	
	fileAlignmentRVA 	dd ? 		
	sizeOfImage 		dd ? 			
	numberOfSection 	dw ?
	sizeOfHeader 		dd ?
	imageBase 			dd ?
	entryPointRVA 		dd ?
  	  	
	dataDirectory 		dd ? 
	importTableRVA 		dd ?
	relocTableRVA 		dd ?
	    
section '.code' code readable executable

  start:
	invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,MEMSIZE
	mov [hMemory],eax
	invoke GlobalLock, [hMemory]
	mov [addrPE],eax
	
	mov [ofn.lStructSize], sizeof.OPENFILENAME
	mov [ofn.hInstance], 0
	mov [ofn.lpstrFilter], Filter
	mov [ofn.lpstrFile],buf_file
	mov [ofn.nMaxFile],buf_size
	mov [ofn.lpstrTitle], name_open	
	mov [ofn.Flags], OFN_FILEMUSTEXIST or \
      			       OFN_PATHMUSTEXIST or OFN_LONGNAMES or \
       			       OFN_EXPLORER or OFN_HIDEREADONLY
	invoke GetOpenFileName, ofn
	invoke CreateFile, buf_file, GENERIC_READ or GENERIC_WRITE ,\
							 	FILE_SHARE_READ or FILE_SHARE_WRITE,0,\
								OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0
	mov [filehwnd],eax	
	invoke ReadFile, [filehwnd], [addrPE], MEMSIZE-1, SizeReadWrite, 0
	invoke CloseHandle,[filehwnd]
	
	push dword [addrPE]
	call GetNTHead						; return eax = ADDR NThead.
	mov ebx, mesText
	test eax, eax 
	jz finish	

	mov ebx, [eax + SECTIONALIGMENT]
	mov [sectionAlignmentRVA], ebx

	;get fileAlignment
	mov ebx, [eax + FILEALIGNMENT]
	mov [fileAlignmentRVA], ebx

	;get imageBase 
	mov ebx, [eax + IMAGEBASE]
	mov [imageBase], ebx

	;get entryPoint
	mov ebx, [eax + ENTRYPOINT]
	mov [entryPointRVA], ebx

	;get numberOfSection
	mov ebx, [eax + NUMBEROFSECTION]
	mov [numberOfSection], bx

	; get sizeOfHeader
	mov ebx, [eax + SIZEOFHEADER]
	mov [sizeOfHeader], ebx

	;get dataDirectory
	mov ebx, [eax + DATADIRECTORY]
	mov [dataDirectory], ebx

	;get importTable
	mov ebx, [eax + DATADIRECTORY + IMPORTTABLE]
	mov [importTableRVA], ebx

	;get relocTable
	mov ebx, [eax + DATADIRECTORY + RELOCTABLE]
	mov [relocTableRVA], ebx

	;get sizeOfImage
	mov ebx, [eax + SIZEOFIMAGE]
	mov [sizeOfImage], ebx

	invoke	VirtualAlloc, NULL, ebx, MEM_COMMIT, PAGE_EXECUTE_READWRITE ; ebx = sizeOfImage.                PAGE_READWRITE
	mov [addrPEImage], eax 			; save addr PE IMAGE.
	push [addrPEImage] 				; copy TO.
	push [sizeOfHeader] 			; size
	push [addrPE]     				; copy FROM. 
	call copySection	
	
	xor edx, edx
	mov dx, [numberOfSection]		; counter. edx = number Of Section.
    mov ebx, [addrPE]
	add ebx, [sizeOfHeader]     	; get first section after head.
m1:
	add eax,[sectionAlignmentRVA]  	; addr memory for section.
	push eax 						; copy TO.
	push [fileAlignmentRVA] 		; size	
	push ebx      			    	; copy FROM.
	call copySection	

	add ebx, [fileAlignmentRVA]		; get second section.
	
	dec edx
	test edx, edx
	jnz m1

	mov eax, [addrPEImage]
	add eax, [importTableRVA]
	push eax						; address of ImportTable.
	call importTableAnaliz
	
	mov eax, [addrPEImage]
	add eax, [relocTableRVA]
	push eax						; address of relocTable.
	call relocTableAnalize
	
	mov eax, [addrPEImage]			;
	add eax, [entryPointRVA]		;
	jmp eax							; jmp to ENTRYPOINT.
		
importTableAnaliz:
;
; in:
;
; 	ADDR ImportTable.
;
; local:
;
; 	ADDR FIRST_THUNK_     	dword.  4 
; 	ADDR RVA_NAMEFUN		dword.  8 
; 	ADDR NAMEDLL			dword. 	12 
; 	ADDR DLL				dword.	16 
;
		push ebp
		mov ebp, esp
		sub esp, 0x18   				
		
		mov eax, [ebp+8]			; eax = ADDR of ImportTable.
i:		add eax, RVAFIRSTTHUNK     ; eax = ADDR of _FIRST_THUNK_.
		mov dword [ebp-4], eax      ; save ADDR FIRST_THUNK_ of _IMAGE_IMPORT_DESCRIPTOR.
		xor ebx, ebx				;
		cmp ebx, [eax]				; last FIRST_THUNK = 0x0.
		jz ex						; 
		
		; save ADDR RVA_NAMEFUN
		mov ebx, [eax]
		add ebx, [addrPEImage]
		mov dword [ebp-8], ebx		; save ADDR RVA_NAMEFUN.
		
		; Get DLL name
		mov ebx, [eax-4]			; eax-4 = ADDR RVA_NAMEDLL 
		add ebx, [addrPEImage]		; ebx = ADDR NAMEDLL
		mov dword [ebp-12], ebx     ; save ADDR NAMEDLL.	
		
		; Load DLL
		invoke LoadLibrary, ebx		;
		mov ebx, mesText2			; prepair the err message...
		test eax, eax				; and go to FINISH...
		jz finish					; if can not load DLL.		
		mov dword[ebp-16], eax		; save ADDR DLL.
		
		; check _IMAGE_THUNK_DATA = 0	
		mov ebx, dword [ebp-8] 		; eax = ADDR RVA_NAMEFUN.	
i2:		xor ecx, ecx
		mov eax, dword [ebp-4]		; restore eax = ADDR FIRST_THUNK_.
		add eax, 4					; set eax on next _IMAGE_IMPORT_DESCRIPTOR.
		cmp [ebx], ecx			    ; last IMAGE_THUNK_DATA = 0x0.
		jz i						; 
		
		mov eax, [ebx]
		add eax, [addrPEImage]		; eax = ADDR NAMEDLL		
		add eax, 2					; first two zero in message.
		push eax					; ADDR NAMEFUN.    
		push dword[ebp-16]			; ADDR DLL.
		call exportTableAnalize		; return eax = ADDR FUN in DLL.

		mov ebx, dword [ebp-8]		; ebx = ADDR RVA_NAMEFUN.
		mov [ebx], eax				; ebx = ADDR RVA_NAMEFUN.
		add ebx, 4
		mov dword [ebp-8], ebx		; go to next ADDR RVA_NAMEFUN.
		jmp i2		
ex:		
		mov esp, ebp
		pop ebp
		ret 4

exportTableAnalize:
;
; in:
; 
; 	ADDR DLL		8
; 	ADDR NAMEFUN   12
;
; out:
; 
; 	eax = ADDR FUN in DLL or 0
;
; local:
;
;	AddressOfFunctions       4
;	AddresOfNames		     8
; 	AddresOfNamesOrdinals    12
;
	push ebp
	mov ebp, esp
	sub esp, 0xC
	
	push dword [ebp+8]
	call GetNTHead					; eax = ADDR NTHead or 0.
	mov ebx, mesText3
	test eax, eax 			
	jz exExportTable	
	
	;get dataDirectory[0](ExportTable)
	mov ebx, [eax + DATADIRECTORY] 	; ebx = RVA ExportTable.
	mov eax, [ebp+8]
	add eax, ebx					; eax = ADDR ExportTable in DLL.
	
	add eax, ADDRESSOFFUNCTION
	mov ebx, [eax]
	mov dword [ebp-4], ebx    		; save RVA AddressOfFunctions(dword).	
	mov ebx, [eax+4]
	mov dword [ebp-8], ebx   		; save RVA AddresOfNames(dword).	
	mov ebx, [eax+8]
	mov dword [ebp-12], ebx   		; save RVA AddresOfNamesOrdinals(word).
		
	mov ebx, [eax-4]
	mov ecx, ebx					; loop = NumbersOfNames	

	; AddresOfNames in dll.
	xor edx, edx
	mov eax, [ebp+8]
	add eax, dword [ebp-8]			; eax = ADDR array RVA AddresOfNames.
findNext:
	mov ebx, [eax]					; ebx = RVA NAME FUN. from ADDR DLL.
	add ebx, [ebp+8]				; ebx = ADDR NAME FUN in DLL.
	; find need function in dll. out: edx = index.	
	cld
	mov esi, dword [ebp+12]			; ADDR NAMEFUN.
	mov edi, ebx					; ADDR NAME FUN in DLL.
e2:	cmpsb
	je e1
	add eax, 4
	inc edx							; index.
	loop findNext	
	mov ebx, mesText4				; 
	jmp finish						; if can not find need fun in DLL.			
e1:	mov bl, byte[esi]
	test bl, bl
	jnz e2

	; AddresOfNamesOrdinals in dll.	
	mov eax, 2
	mul edx						; eax = index in AddresOfNamesOrdinals.
	mov ebx, dword [ebp-12]   	; RVA AddresOfNamesOrdinals.
	add ebx, [ebp+8]			; ADDR AddresOfNamesOrdinals.
	add ebx, eax				; + index.
	mov ax, word [ebx]			; ax = index for array AddressOfFunctions.

	;AddressOfFunctions in dll.
	mov ebx, dword [ebp-4]
	add ebx, [ebp+8]			; ADDR AddressOfFunctions.
	mov dx, 4
	mul dx
	add ebx, eax
	mov ebx, [ebx]				; ebx = RVA ADDR function in DLL from ADDR DLL.
	mov eax, [ebp+8]
	add eax, ebx				; ADDRESS OF NEED FUNCTION IN DLL.
		
exExportTable:	
	mov esp, ebp
	pop ebp
	ret 8

relocTableAnalize:
;
; in:
; 
; 	ADDR RELOC TABLE 	8	  
;
; out:
; 
; 	eax =  or 0
;
; local:
;
;	 RVAOfSection      	4
;	 SizeOfBlock	    8
; 	 ADDRfixUP			12
;	 ADDRFF15			16	
;	 ADDRrelocTable					16	
;
	push ebp
	mov ebp, esp
	sub esp, 10

	mov eax, [ebp+8]			; eax = ADDR RELOC TABLE	
	
	mov edx, [eax]
	mov [ebp-4], edx			; save RVAOfSection.
							
	mov ecx, [eax+4]			; set counter = SizeOfBlock.
	sub ecx, 0x08				; sub Head Block.	
	
	add eax, 8
r:	mov [ebp-12], eax			; save ADDRfixUP.
	
	mov ebx, [ebp-12]			; ebx = ADDRfixUP
	xor edx, edx
	mov dx, word [ebx]			; dx = fixUp.
	and dx, 0x0FFF				; get offset (12 byte) of call FF15 in section code.
	mov ebx, [ebp-4]			; ebx = RVAOfSection.
	add ebx, edx				; ebx = RVA FF15 in code. 
	add ebx, [addrPEImage]
	mov [ebp-16], ebx			; save ADDRFF15.
	
	mov eax, dword [ebp-16]		; eax = ADDR function of DLL in importTable.
	mov eax, [eax]				; get old CALL FF15.
	sub eax, [imageBase]		; eax = offset ADDR function of DLL from [addrPEImage].
	
	add eax, [addrPEImage]		; eax = ADDR function in DLL.
	
	mov ebx, dword [ebp-16]		;
	mov [ebx], eax				; correcting CALL FF15.
	
	mov eax, [ebp-12]
	add eax, 2					; get next FixUP.
	dec ecx						; correcting counter becouse size of FixUp is word.
	loop r						; go to next FixUP.
	
	mov esp, ebp
	pop ebp
	ret 4
	
copySection:
;
; in:
;
; 	copy TO.
; 	size.
; 	copy FROM.
;
	push ebp
	mov ebp, esp

	mov ecx, [ebp+8]  			; copy FROM.
	mov esi, ecx
	mov ecx, [ebp+12] 			; size.
	mov edi, [ebp+16] 			; copy TO.
	push ds
	pop es
	rep movsb	
	
	mov esp, ebp
	pop ebp
	ret 12

GetNTHead:
;
; in:
;
; 	ADDR PE.
;
; out:
;
;	eax = ADDR NTHead or 0
;
	push ebp
	mov ebp, esp

	mov eax,[ebp+8]				; eax = addr PE.
	mov edx,[eax + E_LFANEW]   	; edx = RVA NT head.
	add eax, edx 				; eax = addr NT head in PE.

	;check magic-PE
	cmp word [eax], PE
	jz exGetNTHead
	xor eax, eax				; err. return eax = 0.
	
exGetNTHead:
	mov esp, ebp
	pop ebp
	ret 4
	
finish:
	invoke GlobalUnlock, addrPE 
	invoke GlobalFree,hMemory
	invoke MessageBox, NULL, ebx, mesTitle, MB_OK
    invoke ExitProcess, 0

section '.idata' import data readable writeable

  library kernel,'KERNEL32.DLL',\
	  user,'USER32.DLL',\
	  Comdlg,'Comdlg32.dll'

    import kernel,\
	ExitProcess,'ExitProcess',\
	VirtualAlloc,'VirtualAlloc',\
	CreateFile,'CreateFileW',\
	ReadFile,'ReadFile',\
	CloseHandle,'CloseHandle',\
	GlobalAlloc,'GlobalAlloc',\
	GlobalLock,'GlobalLock',\
	GlobalUnlock,'GlobalUnlock',\
	GlobalFree,'GlobalFree',\
	LoadLibrary,'LoadLibraryA'
	
	import user,\
	MessageBox,'MessageBoxA'
	  
	import Comdlg,\
	GetOpenFileName,'GetOpenFileNameW'

