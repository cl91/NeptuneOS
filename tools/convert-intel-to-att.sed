#\
#       @(#)as386.sed	1.1 - 86/11/17\
#\
# This is a sed script which converts Intel 386 assembly code to Unix\
# 386 assembly code\
#\
# This script does not attempt to convert 100% of the ASM386 source code,\
# it cannot handle the following constructs:\
#\
# - strange segmentation schemes\
# - data declarations beyond the simple db/dw/dd with simple init list\
# - ascii strings\
# - structure template addressing (i.e., [ebp].foo)\
# - complex expressions (parenthesis and operators other than +-*/)\
# - immediate operands that are not simple constants\
# - immediate operands with automatically typed memory operands\
# - source files in upper case\
# - source files with continued lines\
#\
# A typical way to use this sed script is:\
# tr "[A-Z]" "[a-z]" <infile | sed -f this-script >outfile\
#\
#\
# Meaning of labels:\
#\
# cmpress	preserve comments, insert tabs, change '?' to '_'\
# control	convert '$' control lines\
# segment	convert segmentation directives\
# equate	convert 'equ' directives\
# data		convert db/dw/dd data declarations\
# modifer	delete address/type modifiers\
# registr	convert register names\
# bincons	convert binary/octal/hex conatants\
# address	regularize addess expressions, delete unneeded tabs\
# normliz	normalize instruction formats (name-tab-opcode-tab-operands)\
# operand	swap operands, convert scale/index/base address format\
# opcode	append b/w to opcode for byte/word register operands\
# comment	restore preserved comments\

:cmpress
h
s/;.*$//
s/[ 	]*$/	/
s/[ 	][ 	]*/	/g
s/\([][)(.,:*/+-]\)/	\1	/g
s/	?	/	0	/g
s/?/_/g
s/[ 	][ 	]*/	/g

:control
s/^\$[	]*include	(	\([^	.)]*\)[^)]*)/#include	"\1.h"/
s/^\$[	]*eject	/;	/
/^\$/ s/^/;/

:segment
/	segment	e[or]	/ s/^/	.text	;/
/	segment	ro	/ s/^/	.text	;/
/	segment	rw	/ s/^/	.data	;/
/	ends	/ s/^/;/
/	stackseg	/ s/^/;/
s/^[	]*name	\([^	]*\)/	.file	"\1"/
/^[	]*end	/ s/^/;/
/^[	]*assume	/ s/^/;/
/^[	]*extrn	/ s/^/;/
/^[	]*public	[^	,]*	,	/ {
s/^[	]*public	/	.globl	/
s/	,	.*$//
G
s/\n\([ 	]*\)public\([ 	]\)[^,]*,/\
\1public\2/
P
D
}
s/^[	]*public	/	.globl	/
s/^[	]*comm	/	.comm	/
s/^\([^	][^	]*\)	proc	/\1	:	;proc	/
/	endp	/ s/^/;/
s/^\([^	][^	]*\)	label	/\1	:	;label	/
s/^[	]*even	/	.even	/

:equate
s/^\([^	]*\)	equ	\(.*\)	$/#define	:	\1	\2	/

:data
s/^[	]*db	/	.byte	/
s/^\([^	][^	]*\)	db	/\1	:	.byte	/
s/^[	]*dw	/	.value	/
s/^\([^	][^	]*\)	dw	/\1	:	.value	/
s/^[	]*dd	/	.long	/
s/^\([^	][^	]*\)	dd	/\1	:	.long	/
/^[	]*dp	/ {
s/^[	]*dp	/	.value	/
s/$/\/selector of dp pointer/
G
s/\n\([ 	]*\)dp\([ 	]\)/\
\1dd\2/
P
D
}
/^\([^	][^	]*\)	dp	/ {
s/^\([^	][^	]*\)	dp	/\1:	.value	/
s/$/\/selector of dp pointer/
G
s/\n[^ 	]*\([ 	]*\)dp\([ 	]\)/\
\1dd\2/
P
D
}
s/^\([^	][^	]*\)	struc	/\1	:	;struc	/
s/^\([^	][^	]*\)	record	/\1	:	;record	/

:modifer
s/	:	near	/	/g
s/	:	far	/	/g
s/	:	byte	/	/g
s/	:	word	/	/g
s/	:	dword	/	/g
s/	short	/	/g
s/	offset	/	$/g
/	byte	ptr	/ s/$/?%al?/
s/	byte	ptr	/	/g
/	word	ptr	/ s/$/?%ax?/
s/	word	ptr	/	/g
s/	dword	ptr	/	/g
s/	pword	ptr	/	/g

:registr
s/	e\([abcd]\)x	/	%e\1x	/g
s/	\([abcd]\)\([hlx]\)	/	%\1\2	/g
s/	e\([ds]\)i	/	%e\1i	/g
s/	\([ds]\)i	/	%\1i	/g
s/	e\([bs]\)p	/	%e\1p	/g
s/	\([bs]\)p	/	%\1p	/g
s/	\([cdefgs]\)s	/	%\1s	/g

:bincons
s/	\([01][01]*\)b	/	0b\1	/g
s/	\([0-7][0-7]*\)[oq]	/	0\1	/g
s/	\([0-9][0-9a-f]*\)h	/	0x\1	/g

t address
:address
s/\[/+/g
/;/ !s/	]	\.	/	+	/g
s/	]//g
s/	%\([^	]*\)	\*	\([248]\)	+	\([^	%][^	]*\)/	\3	+	%\1	*	\2/g
s/	%\([^	]*\)	+	\([^	%][^	]*\)/	\2	+	%\1/g
s/	%\([^	]*\)	\*	\([248]\)	-	\([^	%][^	]*\)/	-	\3	+	%\1	*	\2/g
s/	%\([^	]*\)	-	\([^	%][^	]*\)/	-	\2	+	%\1/g
s/	+	-	/	-	/g
t address
s/	\([)(,*/+-]\)/\1/g
s/\([)(,*/+-]\)	/\1/g
s/	:/:/g
s/%\([cdefgs]\)s:	/%\1s:/g

:normliz
/:	/ !s/^\([^	;#][^	]*\)/	\1/
/:	/ !s/^	\([^	+,-]*\)\([+-]\)/	\1	\2/g
/:	/ !s/^	\([^	+,]*\)+%/	\1	+%/g
/:	/ s/^\([^	]*\)	\([^	+,-]*\)\([+-]\)/\1	\2	\3/g
/:	/ s/^\([^	]*\)	\([^	+,]*\)+%/\1	\2	+%/g
s/+%\([^	,]*\)/(%\1)/g
s/	+/	/g
s/\([:,]\)+/\1/g

:operand
/[.;#]/ !s/^	\([^	]*\)	\([^,]*\),\([^	]*\)/	\1	\3,\2/
/[.;#]/ !s/^\([^	][^	]*\)	\([^	]*\)	\([^,]*\),\([^	]*\)/\1	\2	\4,\3/
/[.;#]/ !s/^	\([^	]*\)	\([0-9][0-9a-fx]*\)\([	,]\)/	\1	$\2\3/
/[.;#]/ !s/^\([^	][^	]*\)	\([^	]*\)	\([0-9][0-9a-fx]*\)\([	,]\)/\1	\2	$\3\4/
s/(%\([^)+*]*\)+%\([^)*]*\)\*\([248]\))/(%\1,%\2,\3)/g
s/(%\([^)+*]*\)\*\([248]\)+%\([^)]*\))/(%\3,%\1,\2)/g
s/(%\([^)+*]*\)+%\([^)]*\))/(%\1,%\2)/g
s/(%\([^)+*]*\)\*\([248]\))/(,%\1,\2)/g

:opcode
/[	,]%[abcd][hl]/ s/$/?%al?/
/[	,]%[abcd]x/ s/$/?%ax?/
/[	,]%[ds]i/ s/$/?%ax?/
/[	,]%[bs]p/ s/$/?%ax?/
/?%al?/ s/^\([^	]*\)	\([^	]*\)	/\1	\2b	/
/?%ax?/ s/^\([^	]*\)	\([^	]*\)	/\1	\2w	/
s/^#define:/#define/
s/?%a[xl]?//g

:comment
s/	*$//
x
/;/ !s/^.*$//
s/\([ 	]*\);/;\1;/
s/^[^;]*;//
x
G
s/\n//
s/;/\//
