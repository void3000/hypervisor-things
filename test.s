; Launguage: nasm
; Commands: nasm -f bin test.s -l test.lst
[bits 32]
[org 0]

entry:
		cld				; set direction flag register to increment
		lea si, msg
		mov cx, len
		; often used for the port 0xE9 Hack. Used on some emulators to directly 
		; send text to the hosts' console.
		mov dx, 0xe9
again:
		lodsb
		out dx, al
		loop again
		hlt
msg 	db "Hello World!", 0x0a
len 	equ $-msg
