
; fasm demonstration of writing simple ELF executable

format ELF executable 3
entry start
include  'jaslinux.inc'
segment readable executable

start:
	create filename,422,hndfile
	write hndfile,catalog,catalog_len
	close hndfile
	exit

segment readable writeable
    filename db 'jas.pdf',0
    catalog db '1 0 obj',0dh,'<</Type /Catalog /Pages 2 0 R>>',0dh,'endobj',0dh
    catalog_len = $-catalog
    hndfile dd ?
