;                       Some Miscellaneous Equates

PATSIZ   EQU     $1          ; PATCH AREA SIZE
ZICB     EQU     $20         ; zero PageIOCB
ZPG1     EQU     $80         ; beginning of BASIC's zero page
MISCR1   EQU     $480        ; syntax check, etc.
MISCRAM  EQU     $500        ; OTHER ram USAGE

CIO      EQU     $E456       ; in OS ROMs
IOCBORG  EQU     $340        ; where IOCBs start
DCBORG   EQU     $300        ; where DCB (for SIO) is

ROM      EQU     $A000       ; begin code here
ZFP      EQU     $D2         ; begin fltg point work area

CR       EQU     $9B         ; ATASCII end of line

LMADR    EQU     $2E7        ; system lo mem
HMADR    EQU     $2E5        ; system high mem
HIMEM    EQU     HMADR

FPORG    EQU     $D800       ; fltg point in OS ROMs
BRKBYT   EQU     $11
WARMFL   EQU     $08         ; warmstart flag
RNDLOC   EQU     $D20A       ; get a random byte here
CRTGI    EQU     $BFFC-3     ; cartridge init vector
EPCHAR   EQU     $5D         ; the "?" for INPUT statement
BYELOC   EQU     $E471       ; where to go for BYE
DOSLOC   EQU     $0A         ; via here to exit to DOS
SCRX     EQU     $55         ; X AXIS
SCRY     EQU     $54         ; Y AXIS
CREGS    EQU     $2C4        ; COLOR REGISTER
SVCOLOR  EQU     $2FB        ; SAVE COLOR FOR CIO
SREG1    EQU     $D208       ; SOUND REG 1
SREG2    EQU     $D200       ; SOUND REG 2
SREG3    EQU     $D201       ; SOUND REG 3
SKCTL    EQU     $D20F       ; sound control
GRFBAS   EQU     $270        ; 1ST GRAPHICS FUNCTION ADDRESS
DSPFLG   EQU     $2FE        ; ATARI DISPLAY FLAG
APHM     EQU     $E          ; APPLICATION HIGH MEMORY


;ZERO PAGE

;RAM Table Pointers

LOMEM     = $80; LOW MEMORY POINTER
ARGSTK	  = $80
OUTBUFF   = $80; SYNTAX OUTPUT BUFFER
VNTP      = $82; VARIABLE NAME POINTER
VNTD      = $84; VARIABLE NAME TABLE DUMMY END
VVTP      = $86; VARIABLE VALUE TABLE POINTER
ENDVVT    = $88; END VARIABLE VALUE TABLE
STMTAB    = $88; STATEMENT TABLE [PROGRAM] ;

STMCUR    = $8A; CURRENT PGM PTR
STARP     = $8C; STRING/ARRAY TABLE POINTER
ENDSTAR   = $8E; END STRING/ARRAY SPACE
RUNSTK    = $8E; RUN TIME STACK
TOPRSTK   = $90; END RUN TIME STACK
MEMTOP    = $90; TOP OF USED MEMORY
MEOLFLG   = $92; MODIFIED EOL FLAG


;                 USED FOR FREQUENTLY USED VALUES
;                 TO DECLARE ROM SIZE AND INCREASE
;                 EXECUTION SPEED.  ALSO USED FOR VARIOUS
;                 INDIRECT ADDRESS POINTERS.

COX       = $94; CURRENT OUTPUT INDEX
POKEADR   = $95; POKE ADDRESS
SCRADR    = $95; SEARCH ADDRESS
INDEX2    = $97; ARRAY INDEX 2
SVESA     = $97; SAVE EXPAND START ADR
MVFA      = $99; MOVE FROM ADR
MVTA      = $9B; MOVE TO ADR
CPC       = $9D; CUR SYNTAX PGM COUNTER
WVVTPT    = $9D; WORKING VAR TABLE PTR VALUE
MAXCIX    = $9F; MAX SYNTAX CIX
LLNGTH    = $9F; LINE LENGTH
TELNUM    = $A0; TEST LINE NO
MVLNG     = $A2; MOVE LENGTH
ECSIZE    = $A4; MOVE SIZE
DIRFLG    = $A6; DIRECT EXECUTE FLAG
STMLBD    = $A7; STMT LENGTH BYTE DISPL
NXTSTD    = $A7; NEXT STMT DISPL
STMSTRT   = $A8; STMT START CIX
STINDEX   = $A8; CURR STMT INDEX
STKLVL    = $A9; SYNTAX STACK LEVEL
IBUFFX    = $A9; INPUT BUFFER INDEX
OPSTKX    = $A9; OPERATOR STACK INDEX
ARSLVL    = $AA
SRCSKP    = $AA; SEARCH SKIP FACTOR
ARSTKX    = $AA; ARG STACK INDEX
TSCOX     = $AB; TSCOW LENGTH PTR
EXSVOP    = $AB; SAVED OPERATOR
TVSCIX    = $AC; SAVE CIX FOR TVAT
EXSVPR    = $AC; SAVED OPERATOR PRECEDENCE
SVVNTP    = $AD; SAVE VAR NAME TBL PTR
LELNUM    = $AD; LIST END LINE 4
ATEMP     = $AF; TEMP FOR ARRAYS
STENUM    = $AF; SEARCH TABLE ENTRY NUMBER
SCANT     = $AF; LIST SCAN COUNTER
SVONTC    = $B0; SAVE ONT SRC CODE
COMCNT    = $B0; COMMA COUNT FOR EXEXOR
SVVVTE    = $B1; SAVE VAR VALUE EXP SIZE
ADFLAG    = $B1; ASSIGN/DIM FLAG
SVONTL    = $B2; SAVE ONT SRC ARG LEN
SVDISP    = $B2; DISPL INTO LINE OF FOR/GOSUB TOKEN
ONLOOP    = $B3; LOOP CONTROL FOR OP
SVONTX    = $B3; SAVE ONT SRC INDEX
SAVDEX    = $B3; SAVE INDEX INTO STMT
ENTDTD    = $B4; ENTER DEVICE TB
LISTDTD   = $B5; LIST DEVICE TBL
DATAD     = $B6; DATA DISPL
DATALN    = $B7; DATA LINNO
ERRNUM    = $B9; ERROR #
STOPLN    = $BA; LINE # STOPPED AR [FOR CON]
TRAPLN    = $BC; TRAP LINE # [FOR ERROR]
SAVCUR    = $BE; SAVE CURRENT LINE ADDR
IOCMD     = $C0; I/O COMMAND
IODVC     = $C1; I/O DEVICE
PROMPT    = $C2; PROMPT CHAR
ERRSAV    = $C3; ERROR # FOR USER
TEMPA     = $C4; TEMP ADDR CELL
ZTEMP2    = $C6; TEMP
COLOR     = $C8; SET COLOR FOR BASE
PTABW     = $C9; PRINT TAB WIDTH
LOADFLG   = $CA; LOAD IN PROGROSS FLAG


;                  Argument Work Area(AWA)
;Floating Point Work Area

00CB  = 00D2          ORG       ZFP
00D2              TVTYPE                        ; VARIABLE TYPE
00D2  = 0001      VTYPE     DS     1            ; VARIABLE TYPE
00D3  =           TVNUM                         ; VARIABLE NUMBER
00D3  = 0001      VNUM      DS     1            ; VARIABLE NUMBER
      = 0006      FPREC     EQU     6
      = 0005      FMPREC    EQU     FPREC-1     ; LENGTH OF FLOATING POINT
                                                ; MANTISSA
00D4              BININT                        ; FP REGO
00D4  = 0001      FR0       DS     1            ; FP REG0
00D5  = 0005      FR0M      DS     FPREC-1      ; FP REG0 MANTISSA

00DA  = 0006      FRE       DS     FPREC        ; FP REG0 EXP

00E0  = 0001      FRE1      DS     1            ; FP REG 1
00E1  = 0005      FR1M      DS     FPREC-1      ; FP REG1 MANTISSA

00E6  = 0006      FR2       DS     FPREC        ; FP REG 2
00EC  = 0001      FRX       DS     1            ; FP SPARE

;RAM for ASCII to Floating Point Conversion

00ED  = 0001      EEXP      DS     1            ; VALUE OF E
00EE              FRSIGN                        ; FP SIGN
00EE  = 0001      NSIGN     DS     1            ; SIGN OF #
00EF              SQRCNT
00EF              PLYCNT
00EF  = 0001      ESIGN     DS     1            ; SIGN OF EXPONENT
00F0              SGNFLG
00F0  = 0001      FCHRFLG   DS     1            ; 1ST CHAR FLAG
00F1              XFMFLG
00F1  = 0001      DIGRT     DS     1            ; # OF DIGITS RIGHT OF DECIMAL

;Input Buffer Controls

00F2  = 0001      CIX       DS     1            ; CURRENT INPUT INDEX
00F3  = 0002      INBUFF    DS     2            ; LINE INPUT BUFFER

;Temps

00F5  = 0002      ZTEMP1    DS     2            ; LOW LEVEL ZERO PageTEMPS
00F7  = 0002      ZTEMP4    DS     2
00F9  = 0002      ZTEMP3    DS     2

;Miscellany

00FB              DEGFLG
00FB  = 0001      RADFLG    DS     1            ; 0=RADIANS, 6=DEGREES
      = 0000      RADON     EQU     0           ; INDICATE RADIANS
      = 0006      DEGON     EQU     6           ; INDICATES DEGREES
00FC  = 0002      FLPTR     DS     2            ; POLYNOMIAL POINTERS
00FE  = 0002      FPTR2     DS     2

;Miscellaneous Non-Zero Page RAM
                 ;                  USED FOR VALUES NOT ACCESSED FREQUENTLY
0100  = 0480         ORG        MISCR1
      = 0480     STACK      EQU     *           ; SYNTAX STACK
0480  = 0001     SIX        DS     1            ; INPUT INDEX
0481  = 0001     SOX        DS     1            ; OUTPUT INDEX
0482  = 0002     SPC        DS     2            ; PGM COUNTER
0484  = 057E         ORG        STACK+254
057E  = 0001     LBPR1      DS     1            ; LBUFF PREFIX 1
057F  = 0001     LBPR2      DS     1            ; BLUFF PREFIX 2
0580  = 0080     LBUFF      DS     128          ; LINE BUFFER

;-----------145

0600  = 05E0         ORG     LBUFF+$60
05E0  = 0006     PLYARG  DS     FPREC
05E6  = 0006     FPSCR   DS     FPREC
05EC  = 0006     FPSCR1  DS     FPREC
      = 05E6     FSCR    EQU    FPSCR
      = 05EC     FSCR1   EQU    FPSCR1

;IOCB Area

05F2  = 0340         ORG     IOCBORG

;IOCB-I/O Control Block

                 ;               THERE ARE 8 I/O CONTROL BLOCKS
                 ;               1 IOCB IS REQUIRED FOR EACH
                 ;               CURRENTLY OPEN DEVICE OR FILE
                 ;
0340             IOCB
0340  = 0001     ICHID   DS     1            ; DEVICE HANDLER ID
0341  = 0001     ICDNO   DS     1            ; DEVICE NUMBER
0342  = 0001     ICCOM   DS     1            ; I/O COMMAND
0343  = 0001     ICSTA   DS     1            ; I/O STATUS
0344  = 0001     ICBAL   DS     1
0345  = 0001     ICBAH   DS     1            ; BUFFER ADR [H,L]
0346  = 0002     ICPUT   DS     2            ; PUT A BYTE VIA THIS
0348  = 0001     ICBLL   DS     1
0349  = 0001     ICBLH   DS     1            ; BUFFER LENGTH [H,L]
034A  = 0001     ICAUX1  DS     1            ; AUXILIARY 1
034B  = 0001     ICAUX2  DS     1            ; AUXILIARY 2
034C  = 0001     ICAUX3  DS     1            ; AUXILIARY 3
034D  = 0001     ICAUX4  DS     1            ; AUXILIARY 4
034E  = 0001     ICAUX5  DS     1            ; AUXILIARY 5
034F  = 0001         DS     1                ; SPARE
      = 0010     ICLEN   EQU     *-IOCB
                 ;
0350  = 0070         DS     ICLEN*7          ; SPACE FOR 7 MORE IOCBS

;ICCOM Value Equates

      = 0001     ICOIN   EQU     $01         ; OPEN INPUT
      = 0002     ICOOUT  EQU     $02         ; OPEN OUTPUT
      = 0003     ICOIO   EQU     $03         ; OPEN UN/OUT
      = 0004     ICGBR   EQU     $04         ; GET BINARY RECORD
      = 0005     ICGTR   EQU     $05         ; GET TEXT RECORDS
      = 0006     ICGBC   EQU     $06         ; GET BINARY CHAR
      = 0007     ICGTC   EQU     $07         ; GET TEXT CHAR
      = 0008     ICPBR   EQU     $08         ; PUT BINARY RECORD
      = 0009     ICPTR   EQU     $09         ; PUT TEXT RECORD
      = 000A     ICPBC   EQU     $0A         ; PUT BINARY CHAR
      = 000B     ICPTC   EQU     $0B         ; PUT TEXT CHAR
      = 000C     ICCLOSE EQU     $0C         ; CLOSE FILE
      = 000D     ICSTAT  EQU     $0D         ; GET STATUS
      = 000E     ICDCC   EQU     $0E         ; DEVICE DEPENDENT
      = 000E     ICMAX   EQU     $0E         ; MAX VALUE
      = 00FF     ICFREE  EQU     $FF         ; IOCB FREE INDICATOR
      = 001C     ICGR    EQU     $1C         ; OPEN GRAPHICS
      = 0011     ICDRAM  EQU     $11         ; DRAW TO

;ICSTA Value Equates

      = 0001     ICSOK   EQU     $01         ; STATUS GOOD, NO ERRORS
      = 0002     ICSTR   EQU     $02         ; TRUNCATED RECORD
      = 0003     ICSEOF  EQU     $03         ; END OF FILE
      = 0080     ICSBRK  EQU     $80         ; BREAK KEY ABORT
      = 0081     ICSDNR  EQU     $81         ; DEVICE NOT READY
      = 0082     ICSNED  EQU     $82         ; NON-EXISTENT DEVICE
      = 0083     ICSDER  EQU     $83         ; DATA ERROR
      = 0084     ICSIVC  EQU     $84         ; INVALID COMMAND
      = 0085     ICSNOP  EQU     $85         ; DEVICE/FILE NOT OPEN
      = 0086     ICSIVN  EQU     $86         ; INVALID IOCB NUMBER
      = 0087     ICSWPE  EQU     $87         ; WRITE PROTECTION


;-----------146

;Equates for Variables
                 ;               -IN VARIABLE VALUE TABLE
                 ;               -ON ARGUMENT STACK
                 ;
      = 0000     EVTYPE  EQU     0           ; VALUE TYPE CODE
      = 0080     EVSTR   EQU     $80         ; - STRING
      = 0040     EVARRAY EQU     $40         ; - ARRAY
      = 0002     EVSDTA  EQU     $02         ; - ON IF EVSADR IS ABS ADR
      = 0001     EVDIM   EQU     $01         ; ON IF HAS BEEN DIM
      = 0000     EVSCALER EQU    $00         ; -SCALER
                 ;
      = 0001     EVNUM   EQU     1           ; VARIABLE NUMBER [83 -FF]
                 ;
      = 0002     EVVALUE EQU     2           ; SCALAR VALUE [6 BYTES]
                 ;
      = 0002     EVSADR  EQU     2           ; STRING DISPL [2]
      = 0004     EVSLEN  EQU     4           ; STRING LENGTH [2]
      = 0006     EVSDIM  EQU     6           ; STRING DIM [2]
                 ;
      = 0002     EVAADR  EQU     2           ; ARRAY DISPL [2]
      = 0004     EVAD1   EQU     4           ; ARRAY DIM 1 [2]
      = 0006     EVAD2   EQU     6           ; ARRAY DIM 2 [2]

;Equates for Run Stack

      = 0004     GFHEAD  EQU     4           ; LENGTH OF HEADER FOR FOR/GOSUB
      = 000C     FBODY   EQU     12          ; LENGTH OF BODY OF FOR ELEMENT
      = 0003     GFDISP  EQU     3           ; DISP TO SAVED LINE DISP
      = 0001     GFLNO   EQU     1           ; DISPL TO LINE # IN HEADER
      = 0000     GFTYPE  EQU     0           ; DISPL TO TYPE IN HEADER
      = 0006     FSTEP   EQU     6           ; DISPL TO STEP IN FOR ELEMENT


                  ;               ROM Start
;Cold Start
                  ;       COLD START - REINITIALIZES ALL MEMORY
                  ;                    WIPES OUT ANY EXISTING PROGRAM
A000              COLDSTART
A000  A5CA            LDA     LOADFLG         ;Y IN MIDDLE OF LOAD
A002  D004 ^A008      BNE     COLD1           ;DO COLDSTART
A004  A508            LDA     WARMFLG         ; IF WARM START
A006  D045 ^A04D      BNE     WARMSTART       ; THEN BRANCH
A008              COLD1
A008  A2FF            LDX     #$FF            ; SET ENTRY STACK
A00A  9A              TXS                     ; TO TOS
A00B  D8              CLD                     ; CLEAR DECIMAL MODE
A00C              XNEW
A00C  AEE702          LDX     LMADR           ; LOAD NEW
A00F  ACE 802         LDY     LMADR+1         ; MEM VALUE
A012  8680            STX     LOMEM           ; SET LOMEM
A014  8481            STY     LOMEM+1
A016  A900            LDY     #0              ; RESET MODIFIED
A018  8592            STA     MEOLFLG         ; EOL FLAG
A01A  85CA            STA     LOADFLG         ; RESET LOAD FLAG
A01C  C8              INY                     ; ALLOW 256 FOR OUTBUFF
A01D  8A              TXA                     ;VNTP
                  ;
A01E  A282            LDX     #VNTP           ; GET ZPG DISPC TO VNTP
A020  9500        :CS1    STA     0,X         ; SET TABLE ADR LOW
A022  E8              INX
A023  9400            STY     0,X             ; SET TABLE ADR HIGH
A025  E8              INX
A026  E092            CPX     #MEMTOP+2       ; AT LIMIT
A028  90F6 ^A020      BCC     :CS1            ; BR IF NOT
                  ;
A02A  A286            LDX     #VVTP           ; EXPAND VNT BY ONE

;---------147

A02C  A001            LDY     #01             ; FOR END OF VNT
A02E  207FA8          JSR     EXPLOW          ; ZERO BYTE
A031  A28C            LDX     #STARP          ; EXPAND STMT TBL
A033  A003            LDY     #3              ; BY 3 BYTES
A035  207FA8          JSR     EXPLOW          ; GO DO IT
                  ;
A038  A900            LDA     #0              ; SET 0
A03A  A8              TAY
A03B  9184            STA     [VNTD],Y        ; INTO VVTP
A03D  918A            STA     [STMCUR],Y      ; INTO STMCUR+0
A03F  C8              INY
A040  A980            LDA     #$80            ; $80 INTO
A042  918A            STA     [STMCUR],Y      ; STMCUR+1
A044  C8              INY
A045  A903            LDA     #$03            ; $03 INTO
A047  918A            STA     [STMCUR],Y      ; STMCUR+2
                  ;
A049  A90A            LDA     #10             ; SET PRINT TAB
A04B  85C9            STA     PTABW           ; WIDTH TO 10
                  ;

;Warm Start
                  ;      WARMSTART - BASIC RESTART
                  ;                  DOES NOT DESTROY CURRENT PGM
A04D              WARMSTART
A04D  20F8B8          JSR     RUNINIT         ; INIT FOR RUN
A050  2041BD      SNX1JSR     CLSALL          ; GO CLOSE DEVICE 1-7
A053  2072BD      SNX2JSR     SETDZ           ; SET E/L DEVICE 0
A056  A592            LDA     MEOLFLG         ; IF AN EOL INSERTED
A058  F003 ^A05D      BEQ     SNX3
A05A  2099BD          JRS     RSTSEOL         ; THEN UN-RESET IT
A05D  2057BD      SNX3    JSR     PREADY      ; PRINT READY MESSAGE

;Syntax

A060                  LOCAL

;Editor-Get Lines of Input

A060              SYNTAX
A060  A5CA            LDA     LOADFLG         ; IF LOAD IN PROGRES
A062  D09C ^A000      BNE     COLDSTART       ; GO DO COLDSTART
A064  A2FF            LDX     #$FF            ; RESTORE STACK
A066  9A              TXS
A067  2051DA          JSR     INTLBF          ; GO INT LBUFF
A06A  A95D            LDA     #EPCHAR
A06C  85C2            STA     PROMPT
A06E  2092BA          JSR     GLGO            ;
A071  20F4A9          JSR     TSTBRK          ; TEST BREAK
A074  D0EA ^A060      BNE     SYNTAX          ; BR IF BREAK
                  ;
A076  A900            LDA     #0              ; INIT CURRENT
A078  85F2            STA     CIX             ;INPUT INDEX TO ZERO
A07A  859F            STA     MAXCIX
A07C  8594            STA     COX             ;OUTPUT INDEX TO ZERO
A07E  85A6            STA     DIRFLG          ;SET DIRECT SMT
A080  85B3            STA     SVONTX          ; SET SAVE ONT CIX
A082  85B0            STA     SVONTC
A084  85B1            STA     SVVVTE          ; VALUE IN CASE
A086  A584            LDA     VNTD            ; OF SYNTAX ERROR
A088  85AD            STA     SVVNTP
A08A  A585            LDA     VNTD+1
A08C  85AE            STA     SVVNTP+1
                  ;
A08E  20A1DB          JSR     SKBLANK         ;SKIP BLANKS
A091  209FA1          JSR     :GETLNUM        ;CONVERT AND PUT IN BUFFER
A094  20C8A2          JSR     :SETCODE        ; SET DUMMY FOR LINE LENGTH
A097  A5D5            LDA     BININT+1
A099  1002            BPL     :SYN0
A09B  85A6            STA     DIRFLG

;---------148

A09D              :SYN0
A09D  20A1DB          JSR     SKBLANKS        ; SKIP BLANKS
A0A0  A4F2            LDY     CIX             ;GET INDEX
A0A2  84A8            STY     STMSTRT         ;SAVE INCASE OF SYNTAX ERROR
A0A4  B1F3            LDA     [INBUFF],Y      ;GET NEXT CHAR
A0A6  C99B            CMP     #CR             ;IS IT CR
A0A8  D007 ^A0B1      BNE     :SYN1           ;BR NOT CR
A0AA  24A6            BIT     DIRFLG          ; IF NO LINE NO.
A0AC  30B2 ^A060      BMI     SYNTAX          ; THEN NO. DELETE
A0AE  4C89A1          JMP     :SDEL           ;GO DELETE STMT
A0B1              :SYN1
A0B1              :XIF
A0B1  A594            LDA     COX             ;SAVE COX
A0B3  85A7            STA     STMLBD          ;AS PM TO STMT LENGTH BYTE
A0B5  20C8A2          JSR     :SETCODE        ; DUMMY FOR STMT LENGTH
                  ;
                  ;
A0B8  20A1DB          JSR     SKBLANK         ;GO SKIP BLANKS
A0BB  A9A4            LDA     #SNTAB/256      ; SET UP FOR STMT
A0BD  A0AF            LDY     #SNTAB&255      ;NAME SEARCH
A0BF  A202            LDX     #2
A0C1  2062A4          JSR     SEARCH          ;AND DO IT
A0C4  86F2            STX     CIX
A0C6  A5AF            LDA     STENUM          ;GET STMT NUMBER
A0C8  20C8A2          JSR     :SETCODE        ;GO SET CODE
A0CB  20A1DB          JSR     SKBLANK
A0CE  20C3A1          JSR     :SYNENT         ;AND GO SYNTAX HIM
A0D1  9035 ^A108      BCC     :SYNOK          ;BR IF OK SYNTAX
                  ;
A0D3  A49F            LDY     MAXCIX          ; GET MAXCIX
A0D5  B1F3            LDA     [INBUFF],Y      ; LOAD MAXCIX CHAR
A0D7  C99B            CMP     #CR             ; WAS IT CR
A0D9  D006 ^A0E1      BNE     :SYN3A          ; BR IF NOT CR
A0DB  C8              INY                     ; MOVE CR RIGHT ONE
A0DC  91F3            STA[INBUFF],Y
A0DE  88              DEY                     ; THEN PUT A
A0DF  A920            LDA     #$20            ; BLANK IN IT'S PLACE
A0E1  0980        :SYN3A  ORA     #$80        ; SET MAXCIX CHAR
A0E3  91F3            STA     [INBUFF],Y      ; TO FLASH
                  ;
A0E5  A940            LDA     #$40            ;INDICATE SYNTAX ERROR
A0E7  05A6            ORA     DIRFLAG
A0E9  85A6            STA     DIRFLAG         ; IN DIRFLAG
A0EB  A4A8            LDY     STMTSTRT        ;RESTORE STMT START
A0ED  84F2            STY     CIX
A0EF  A203            LDX     #3              ;SET FOR FIRST STMT
A0F1  86A7            STX     STMLBD
A0F3  E8              INX                     ;INC TO CODE
A0F4  8694            STX     COX             ;AND SET COX
A0F6  A937            LDA     #CERR           ; GARBADGE CODE
A0F8  20C8A2      :SYN3   JSR     :SETCODE    ;GO SET CODE
A0FB              :XDATA
A0FB  A4F2            LDY     CIX             ;GET INDEX
A0FD  B1F3            LDA     [INBUFF],Y      ;GET INDEX CHAR
A0FF  E6F2            INC     CIX             ;INC TO NXT
A101  C99B            CMP     #CR             ;IS IT CR
A103  D0F3 ^A0F8      BNE     :SYN3           ;BR IF NOT
A105  20C8A2          JSR     :SETCODE
                  ;
A108  A594        :SYNOK  LDA     COX         ; GET DISPL TO END OF STMT
A10A  A4A7            LDY     STMLBL
A10C  9180            STA     [OUTBUFF],Y     :SET LENGTH BYTE
                  ;
A10E  A4F2            LDY     CIX             ;GET INPUT DISPL
A110  88              DEY
A111  B1F3            LDA     [INBUFF],Y      ;GET LAST CHAR
A113  C99B            CMP     #CR             ;IS IT CR
A115  D09A ^D0B1      BNE     :SYN1           ;BR IF NOT
                  ;
A117  A002        :SYN4   LDY     #2          ; SET LINE LENGTH
A119  A594            LDA     COX             ; INTO STMT

;---------149

A11B  9180            STA     [OUTBUFF],Y
                  ;
                  ;
A11D  20A2A9      :SYN5   JSR     GETSTMT     ;GO GET STMT
A120  A900            LDA     #0
A122  B003 ^A127      BCS     :SYN6
                  ;
A124              :SYN5A
A124  20DDA9          JSR     GETLL           ;GO GET LINE LENGTH
A127  38          :SYN6   SEC
A128  E594            SBC     COX             ;ACU=LENGTH[OLD-NEW]
A12A  F020 ^A14C      BEQ     :SYNIN          ; BR NEW=OLD
A12C  B013 ^A141      BCS     :SYNCON         ;BR OLD>NEW
                  ;                           ;OLD<NEW
A12E  49FF            EOR     #$FF            ;COMPLEMENT RESULT
A130  A8              TAY
A131  C8              INY
A132  A28A            LDX     #STMCUR         ;POINT TO STMT CURRENT
A134  207FA8          JSR     EXPLOW          ;GO EXPAND
A137  A597            LDA     SVESA           ;RESET STMTCUR
A139  858A            STA     STMCUR
A13B  A598            LDA     SVESA+1
A13D  858B            STA     STMCUR+1
A13F  D00B  ^A14C     BNE     :SYNIN
                  ;
A141  48          :SYNCON PHA     ;CONTRACT LENGTH
A142  20D0A9          JSR     GNXTL
A145  68              PLA
A146  A8              TAY
A147  A28A            LDX     #STMCUR         ;POINT TO STMT CURRENT
A149  20FBA8          JSR     CONTLOW         ;GO CONTRACT
                  ;
A14C  A494        :SYNIN  LDY     COX         ; STMT LENGTH
A14E  88          :SYN7   DEY                 ; MINUS ONE
A14F  B180            LDA     [OUTBUFF],Y     ; GET BUFF CHAR
A151  918A            STA     [STMCUR],Y      ;PUT INTO STMT TBL
A153  98              TYA                     ; TEST END
A154  D0F8            BNE     :SYN7           ; BR IF NOT
A156  24A6            BIT     DIRFLG          ;TEST FOR SYNTAX ERROR
A158  502A ^A184      BVC     :SYN8           ;BR IF NOT
A15A  A5B1            LDA     SVVVTE          ; CONTRACT VVT
A15C                  ALSA
A15C +0A              ASL     A
A15D                  ASLA
A15D +0A              ASL     A
A15E                  ASLA
A15E +0A              ASL     A
A15F  A8              TAY
A160  A288            LDX     #ENDVVT
A162  20FBA8          JSR     CONTLOW
A165  38              SEC
A166  A584            LDA     VNTD            ; CONTRACT VNT
A168  E5AD            SBC     SVVNTP
A16A  A8              TAY
A16B  A585            LDA     VNTD+1
A16D  E5AE            SBC     SVVNTP+1
A16F  A284            LDX     #VNTD
A171  20FDA8          JSR     CONTRACT
A174  24A6            BIT     DIRFLG          ; IF STMT NOT DIRECT
A176  1006 ^A17E      BPL     :SYN9A          ; THE BRANCH
A178  2078B5          JSR     LDLINE          ; ELSE LIST DIRECT LINE
A17B  4C60A0          JMP     SYNTAX          ; THEN BACK TO SYNTAX
A17E  205CB5      :SYN9A  JSR     LLINE       ; LIST ENTIRE LINE
A181  4C60A0      :SYN9   JMP     SYNTAX
A184  10FB ^A181  :SYN8   BPL     :SYN9
A186  4C5FA9          JMP     EXECNL          ; GO TO PROGRAM EXECUTOR
                  ;
A189  20A2A9      :SDEL   JSR     GETSTMT     ; GO GET LINE
A18C  B0F3 ^A181      BCS     :SYN9           ; BR NOT FOUND
A191  48              PHA                     ; Y

;----------150

A192  20D0A9          JSR     GNXTL
A195  68              PLA
A196  A8              TAY
A197  A28A            LDX     #STMCUR         ;GET STMCUR DISPL
A199  20FBA8          JSR     CONTLOW         ; GO DELETE
A19C  4C60A0          JMP     SYNTAX          ;GO FOR NEXT LINE

;Get a Line Number

                  ;GETLNUM-GET A LINE NO FROM ASCLT IN INBUFF
                  ;       TO BINARY INTO OUTBUFF
A19F              ;GETLNUM
A19F  2000D8          JSR     CVAFP           ; GO CONVERT LINE #
A1A2  9008 ^A1AC      BCC     :GLNUM          ; BR IF GOOD LINE #
A1A4              :GLN1
                  ;
A1A4  A900            LDA     #0              ;SET LINE #
A1A6  85F2            STA     CIX
A1A8  A080            LDY     #$80            ; =$8000
A1AA  3009 ^A1B5      BMI     :SLNUM
                  ;
A1AC  2056AD      :GLNUM  JSR     CVFPI       ; CONVERT FP TO INT
A1AF  A4D5            LDY     BININT+1        ; LOAD RESULT
A1B1  30F1 ^A1A4      BMI     :GLN1           ; BR IF LNO>32767
A1B3  A5D4            LDA     BINIT
                  ;
A1B5              :SLNUM
A1B5  84A1            STY     TSLNUM+1        ; SET LINE # HIGH
A1B7  85A0            STA     TSLNUM          ; AND LOW
A1B9  20C8A2          JSR     :SETCODE        ; OUTPUT LOW
A1BC  A5A1            LDA     TSLNUM+1        ; OUTPUT HI
A1BE  85D5            STA     BININT+1
A1C0  4CC8A2          JMP     :SETCODE        ; AND RETURN

;SYNENT           ;        PERFORM LINE PRE-COMPILE
                  ;
A1C3              ;SYNENT
A1C3  A001            LDY     #1              ; GET PC HIGH
A1C5  B195            LDA     [SCRADR],Y
A1C7  859E            STA     CPC+1           ; SET PGM COUNTERS
A1C9  8D8304          STA     SPC+1
A1CC  88              DEY
A1CD  B195            LDA     [SCRADR],Y
A1CF  859D            STA     CPC
A1D1  8D8204          STA     SPC
A1D4  A900            LDA     #0              ; SET STKLUL
A1D6  85A9            STA     STKLVL          ; SET STKLUL
A1D8  A594            LDA     COX             ; MOVE
A1DA  8D8104          STA     SOX             ; COX TO SOX
A1DD  A5F2            LDA     CIX             ; MOVE
A1DF  8D8004          STA     SIX             ; CIX TO SIX

;NEXT
                  ;              GET NEXT SYNTAX CODE
                  ;              AS LONG AS NOT FAILING
                  ;
      = A1E2      :NEXT   EQU     *
A1E2  20A1A2          JSR     :NXSC           ; GET NEXT CODE
                  ;
A1E5  301A ^A201      BMI     :ERNTV          ; BR IF REL-NON-TERMINAL
                  ;
A1E7  C901            CMP     #1              ; TEST CODE=1
A1E9  902A ^A215      BCC     :GETADR         ; BR CODE=0 [ABS-NON-TERMINAL]
A1EB  D008 ^A1F5      BNE     :TSTSUC         ; BR CODE >1
                  ;
A1ED  2015A2          JSR     :GETADR         ; CODE=1 [EXTERNAL SUBROUTINE]
A1F0  90F0 ^A1E2      BCC     :NEXT           ; BR IF SUB REPORTS SUCCESS
A1F2  4C6CA2          JMP     :FAIL           ; ELSE GO TO FAIL CODE
                  ;
A1F5  C905        :TSTSUC CMP     #5          ; TEST CODE = 5

;---------151

A1F7  9059 ^A252      BCC     :POP            ; CODE= [2,3, OR 4] POP UP TO
                                              ; NEXT SYNTAX CODE
A1F9  20A9A2          JSR     :TERMTST        ; CODE>5 GO TEST TERMINAL
A1FC  90E4 ^A1E2      BCC     :NEXT           ; BR IF SUCCESS
A1FE  4C6CA2          JMP     :FAIL           ; ELSE GO TO FAIL CODE
                  ;
A201  38          :ERNTV  SEC                 ; RELATIVE NON TERMINAL
A202  A200            LDX     #0              ; TOKEN MINUS
A204  E9C1            SBC     #$1
A206  B002 ^A20A      BCS     :ERN1           ; BR IF RESULT PLUS
A208  A2FF            LDX     #$FF            ; ADD A MINUS
A20A  18          :ERN1   CLC
A20B  659D            ADC     CPC             ; RESULT PLUS CPC
A20D  48              PHA                     ; IS NEW CPC-1
A20E  8A              TXA
A20F  659E            ADC     CPC+1
A211  48              PHA                     ; SAVE NEW PC HIGH
A212  4C28A2          JMP     :PUSH           ; GO PUSH
      = A215      :GETADR EQU     *           ; GET DOUBLE BYTE ADR [-1]
A215  20A1A2          JSR     :NXSC           ; GET NEXT CODE
A218  48              PHA                     ; SAVE ON STACK
A219  20A1A2          JSR     :NXSC           ; GET NEXT CODE
A21C  48              PHA                     ; SAVE ON STACK
A21D  9009 ^A228      BCC     :PUSH           ; BR IF CODE =0
A21F  68              PLA                     ; EXCHANGE TOP
A220  A8              TAY                     ; 2 ENTRIES ON
A221  68              PLA                     ; CPU STACK
A222  AA              TAX
A223  98              TYA
A224  48              PHA
A225  8A              TXA
A226  48              PHA
A227  60              RTS                     ; ELSE GOTO EXTERNAL SRT VIA RTS

;PUSH             ;              PUSH TO NEXT STACK LEVEL
                  ;
      = A228      ;PUSH   EQU     *
A228  A6A9            LDX     STKLVL          ; GET STACK LEVEL
A22A  E8              INX                     ; PLUS 4
A22B  E8              INX
A22C  E8              INX
A22D  E8              INX
A22E  F01F ^A24F      BEQ     :SSTB           ;BR STACK TOO BIG
A230  68A9            STX     STKLVL          ; SAVE NEW STACK LEVEL
                  ;
A232  A5F2            LDA     CIX             ; CIX TO
A234  9D8004          STA     SIX,X           ; STACK IX
A237  A594            LDA     COX             ; COX TO
A239  9D8104          STA     SOX,X           ; STACK OX
A23C  A59D            LDA     CPC             ; CPC TO
A23E  9D8204          STA     SPC,X           ; STACK CPC
A241  A59E            LDA     CPC+1
A243  9D8304          STA     SPC+1,X
                  ;
A246  68              PLA                     ; MOVE STACKED
A247  859E            STA     CPC+1           ; PC TO CPC
A249  68              PLA
A24A  859D            STA     CPC
A24C  4CE2A1          JMP     :NEXT           ; GO FOR NEXT
                  ;
A24F  4C24B9      :SSTB   JMP     ERLTL

;POP
                  ;             LOAD CPC FROM STACK PC
                  ;             AND DECREMENT TO PREV STACK LEVEL
                  ;
      = A252      :POP    EQU     *
A252  A6A9            LDX     STKLVL          ; GET STACK LEVEL
A254  D001 ^A257      BNE     :POP1           ; BR NOT TOP OF STACK
                  ;

;---------152

A256  68              RTS                     ; TO SYNTAX CALLER
                  ;
A257  BD8204      :POP1   SPC,X               ; MOVE STACK PC
A25A  859D            STA     CPC             ; TO CURRENT PC
A25C  BD8304          LDA     SPC+1,X
A25F  859E            STA     CPC+1
                  ;
A261  CA              DEX                     ; X=X-4
A262  CA              DEX
A263  CA              DEX
A264  CA              DEX
A265  86A9            STX     STKLVL
                  ;
A267  B003 ^A26C      BCS     :FAIL           ; BR IF CALLER FAILING
A269  4CE2A1          JMP     :NEXT           ; ELSE GO TO NEXT

;FAIL
                  ;              TERMINAL FAILED
                  ;              LOOK FOR ALTERNATIVE [OR] OR
                  ;              A RETURN VALUE
                  ;
      = A26C      :FAIL    EQU    *
A26C  20A1A2          JSR     ;NXSC           ; GET NEXT CODE
                  ;
A26F  30FB ^A26C      BMI     :FAIL           ; BR IF RNTV
                  ;
A271  C902            CMP     #2              ; TEST CODE =2
A273  B002 ^A27D      BCS     :TSTOR          ; BR IF POSSIBLE OR
                  ;
A275  209AA2          JSR     :INCCPC         ; CODE = 0 OR 1
A278  209AA2          JSR     :INCCPC         ; INC PC BY TWO
A27B  D0EF ^A26C      BNE     :FAIL           ; AND CONTINUE FAIL PROCESS
                  ;
A27D  C903        :TSTOR  CMP     #3          ; TEST CODE=3
A27F  F0D1 ^A252      BEQ     :POP            ; BR CODE =3 [RETURN]
A281  B0E9 ^A26C      BCS     :FAIL           ; CODE>3 [RNTV] CONTINUE
                  ;
A283  A5F2            LDA      CIX            ; IF THIS CIX
A285  C59F            CMP      MAXCIX         ; IS A NEW MAX
A287  9002 ^A28B      BCC      :SCIX
A289  859F            STA      MAXCIX         ; THEN SET NEW MAX
A28B              :SCIX
A28B  A6A9            LDX      STKLVL         ; CODE=2 [OR]
A28D  BD8004          LDA      SIX,X          ; MOVE STACK INDEXES
A290  85F2            STA      CIX            ; TO CURRENT INDEXES
A292  BD8104          LDA      SOX,X
A295  8594            STA      COX
A297  4CE2A1          JMP      :NEXT          ; TRY FOR SUCCESS HERE

;INCREMENT CPC
                  ;       INCCPC - INC CPC BY ONE
                  ;
      = A29A      :INCCPC EQU     *
A29A  E69D            INC      CPC
A29C  D002 ^A2A0      BNE      :ICPCR
A29E  E69E            INC      CPC+1
A2A0  60          :ICPCR  RTS

;NXSC
                  ;               GET NEXT SYNTAX CODE
                  ;
A2A1              ;NXSC
A2A1  209AA2          JSR      :INCCPC        ; INC PC
A2A4  A200            LDX      #0
A2A6  A19D            LDA      [CPC,X]        ; GET NEXT CODE
A2A8  60              RTS                     ; RETURN

;---------153

;TERMTST
                  ;         TEST A TERMINAL CODE
                  ;
                  ;
A2A9              ;TERMTST
A2A9  C90F            CMP      #$0F           ; TEST CODE=F
A2AB  F00D ^A2BA      BEQ      :ECHNG         ; BR CODE < F
A2AD  B037 ^A2E6      BCS      :SRCONT        ; BR CODE > F
                  ;
A2AF  68              PLA                     ; POP RTN ADR
A2B0  68              PLA
A2B1  A90C            LDA      #:EXP-1&255    ; PUSH EXP ADR
A2B3  48              PHA                     ; FOR SPECIAL
A2B4  A9A6            LDA      #:EXP/256      ; EXP ANTV CALL
A2B6  48              PHA
A2B7  4C28A2          JMP      :PUSH          ; GO PUSH
                  ;
ECHNG
                  ;                EXTERNAL CODE TO CHANGE COX -1
                  ;
A2BA              ;ECHNG
A2BA  209AA2          JSR      :INCCPC        ; INC PC TO CODE
A2BD  A000            LDY      #0
A2BF  B19D            LDA      [CPC],Y        ; GET CODE
                  ;
A2C1  A494            LDY      COX            ; GET COX
A2C3  88              DEY                     ; MINUS 1
A2C4  9180            STA      [OUTBUFF],Y    ; SET NEW CODE
A2C6  18              CLC                     ; SET SUCCESS
A2C7  60              RTS                     ; RETURN

;SETCODE
                  ;         SET CODE IN ACV AT COX AND INC COX
                  ;
A2C8              ;SETCODE
A2C8  A494            LDY      COX            ; GET COX
A2CA  9180            STA      [OUTBUFF],Y    ; SET CHAR
A2CC  E694            INC      COX            ; INC COX
A2CE  F001 ^A2D1      BEQ      :SCOVF         ; BR IF NOT ZERO
A2D0  60              RTS                     ; DONE
A2D1  4C24B9      :SCOVF  JMP      ERLTL      ; GO TO LINE TOO LONG ERR

;Exits for IF and REM

A2D4  A2FF        :EIF    LDX      #$FF       ; RESET STACK
A2D6  9A              TXS
A2D7  A594            LDA      COX            ; SET STMT LENGTH
A2D9  A4A7            LDY      STMLBD
A2DB  9180            STA      [OUTBUFF],Y
A2DD  4CB1A0          JMP      :XIF           ; GO CONTINUE IF
                  ;
A2E0              :EREM
A2E0              :EDATA
A2E0  A2FF            LDX      #$FF           ; RESET STACK
A2E2  9A              TXS
A2E3  4CFBA0          JMP      :XDATA         ;GO CONTINUE DATA

;SRCONT
                  ;                 SEARCH OP NAME TABLE AND TEST RESULT
                  ;
A2E6              :SRCONT
A2E6  20A1DB          JSR      SKPBLANK       ; SKIP BLANKS
A2E9  A5F2            LDA      CIX            ; GET CURRENT INPUT INDEX
A2EB  C5B3            CMP      SVONTX         ; COMPARE WITH SAVED IX
A2ED  F016 ^A305      BEQ      :SONT1         ; BR IF SAVED IX SAME
A2EF  85B3            STA      SVONTX         ; SAVE NEW IX
                  ;
A2F1  A9A7            LDA      #OPNTAB/256    ; SET UP FOR ONT
A2F3  A0E3            LDY      #OPNTAB&255    ; SEARCH
A2F5  A200            LDX      #0
A2F7  2062A4          JSR      SEARCH         ; GO SEARCH

;---------154

A2FA  B028 ^A324      BCS      :SONF          ; BR NOT FOUND
A2FC  86B2            STX      SVONTL         ; SAVE NEW CIX
A2FE  18              CLC
A2FF  A5AF            LDA      STENUM         ; ADD $10 TO
A301  6910            ADC      #$10           ; ENTRY NUMBER TO
A303  85B0            STA      SVONTC         ; GET OPERATOR CODE
                  ;
A305  A000        :SONT1  LDY      #0
A307  B19D            LDA      [CPC],Y        ; GET SYNTAX REQ CODE
A309  C5B0            CMP      SVONTC         ; DOES IT MATCH THE FOUND
A30B  F00E ^A31B      BEQ      :SONT2         ; BR IF MATCH
A30D  C944            CMP      #CNFNP         ; WAS REQ NFNP
A30F  D006 ^A317      BNE      :SONTF         ; BR IF NOT
A311  A5B0            LDA      SVONTC         ; GET WHAT WE GOT
A313  C944            CMP      #CNFNP         ; IS IT NFNA
A315  B002 ^A319      BCS      :SONTS         ; BR IF IT IS
A317              :SONTF
A317  38              SEC                     ; REPORT FAIL
A318  60              RTS
A319  A5B0        :SONTS  LDA     SVONTC      ; GET REAL CODE
                  ;
A31B  20C8A2      :SONT2  JSR      :SETCODE   ; GO SET CODE
A31E  A6B2            LDX      SVONTL         ; INC CIX BY
A320  86F2            STX      CIX
A322  18              CLC                     ; REPORT SUCCESS
A323  60              RTS                     ; DONE
A324  A900        :SONF   LDA      #0         ; SET ZERO AS
A326  85B0            STA      SVONTC         ; SAVED CODE
A328  38              SEC
A329  60              RTS                     ; DONE

;TVAR
                  ;               EXTERNAL SUBROUTINE FOR TNVAR & TSVAR
                  ;
A32A  A900        :TNVAR  LDA      #0         ; SET NUMERIC TEST
A32C  F002 ^330      BEQ       :TVAR
                  ;
A32E  A980        :TSVAR  LDA      #$80       ; SET STR TEST
                  ;
A330  85D2        :TVAR   STA      TVTYPE     ; SAVE TEST TYPE
A332  20A1DB          JSR      SKPBLANK       ; SKIP LEADING BLANKS
A335  A5F2            LDA      CIX            ; GET INDEX
A337  85AC            STA      TVSCIX         ; FOR SAVING
                  ;
A339  20F3A3          JSR      :TSTALPH       ; GO TEST FIRST CHAR
A33C  B025 ^A363      BCS      :TVFAIL        ; BR NOT ALPHA
A33E  20E6A2          JSR      :SRCONT        ; IF THIS IS A
A341  A5B0            LDA      SVONTC         ; RESVD NAME
A343  F008 ^A34D      BEQ      :TV1           ; BR NOT RSVDNAME
A345  A4B2            LDY      SVONTL         ; IF NEXT CHAR AFTER
A347  B1F3            LDA      [INBUFF],Y     ; RESERVED NAME
A349  C930            CMP      #$30           ; NOT ALARM NUMERIC
A34B  9016 ^A363      BCC      :TVFAIL        ; THEN ERROR
                  ;
A34D  E6F2        :TV1    CIX                 ; INC TO NEXT CHAR
A34F  20F3A3          JSR      :TSTALPH       ; TEST ALPHA
A352  90F9 ^A34D      BCC      :TV1           ; BR IF ALPHA
A354  20AFDB          JSR      TSTNUM         ; TRY NUMBER
A357  90F4 ^A34D      BCC      :TV1           ; BR IF NUMBER
                  ;
A359  B1F3            LDA      [INBUFF],Y     ; GET OFFENDING CHAR
A358  C924            CMP      #'$'           ; IS IT $
A35D  F006 ^A365      BEQ      :TVSTR         ; BR IF $ [STRING]
A35F  24D2            BIT      TVTYPE         ; THIS A NVAR SEARCH
A361  1009 ^A36C      BPL      :TVOK          ; BR IF NVAR
                  ;
A363  38          :TVFAIL SEC                 ; SET FAIL CODE
A364  60              RTS                     ; DONE
                  ;
A365  24D2        :TVSTR  BIT      TVTYPE     ; TEST SVAR SEARCH
A367  10FA ^A363      BPL      :TVFAIL        ; BR IF SVAR

;---------155

A369  C8              INY                     ; INC OVER $
A36A  D00D ^A379      BNE      :TVOK2         ; BR ALWAYS
                  ;
A36C  B1F3        :TVOK   LDA      [INBUFF],Y     ; GET NEXT CHAR
A36E  C928            CMP      #'('           ; IS IT PAREN
A370  D007 ^A379      BNE      :TVOK2         ; BR NOT PAREN
A372  C8              INY                     ; INC OVER PAREN
A373  A940            LDA      #$40           ; OR IN ARRAY
A375  05D2            ORA      TVTYPE         ; CODE TO TVTYPE
A377  85D2            STA      TVTYPE
                  ;
A379  A5AC        :TVOK2  LDA      TVSCIX     ; GET SAVED CIX
A37B  85F2            STA      CIX            ; PUT BACK
A37D  84AC            STY      TVSCIX         ; SAVE NEW CIX
                  ;
A37F  A583            LDA      VNTP+1         ; SEARCH VNT
A381  A482            LDY      VNTP           ; FOR THIS GUY
A383  A200            LDX      #0
A385  2062A4          JSR      SEARCH
A388              :TVRS
A388  B00A ^A394      BCS      :TVS0          ; BR NOT FOUND
A38A  E4AC            CPX      TVSCIX         ; FOUND RIGHT ONE
A38C  F04D            BEQ      :TVSUC         ; BR IF YES
A38E  2090A4          JSR      SRCNXT         ; GO SEARCH MORE
A391  4C88A3          JMP      ;TVRS          ; TEST THIS RESULT
                  ;
A394              :TVS0
A394  38              SEC                     ; SIGH:
A395  A5AC            LDA      TVSCIX         ; VAR LENGTH IS
A397  E5F2            SBC      CIX            ; NEW CIX-OLD CIX
A399  85F2            STA      CIX
                  ;
A39B  A8              TAY                     ; GO EXPAND VNT
A39C  A284            LDX      #VNTD          ; BY VAR LENGTH
A39E  207FA8          JSR      EXPLOW
A3A1  A5AF            LDA      STENUM         ; SET VARIABLE NUMBER
A3A3  85D3            STA      TVNUM
                  ;
A3A5  A4F2            LDY      CIX            ; AND
A3A7  88              DEY
A3A8  A6AC            LDX      TVSCIX         ; GET DISPL TO EQU+1
A3AA  CA              DEX
A3AB  BD8005      :TVS1   LDA      LBUFF,X    ; MOVE VAR TO
A3AE  9197            STA      [SVESA],Y
A3B0  CA              DEX
A3B1  88              DEY
A3B2  10F7            BPL      :TVS1
                  ;
A3B4  A4F2            LDY      CIX            ; TURN ON MSB
A3B6  88              DEY                     ; OF LAST CHAR
A3B7  B197            LDA      [SVESA],Y      ; IN VTVT ENTRY
A3B9  0980            ORA      #$80
A3BB  9197            STA      [SVESA],Y
                  ;
A3BD  A008            LDY      #8             ; THEN EXPAND
A3BF  A288            LDX      #STMTAB        ; VVT BY 8
A3C1  207FA8          JSR      EXPLOW
A3C4  E6B1            INC      SVVVTE         ; INC VVT EXP SIZE
                  ;
A3C6  A002            LDY      #2             ; CLEAR VALUE
A3C8  A900            LDA      #0             ; PART OF
A3CA  99D200      :TVS1A  STA      TVTYPE,Y   ; ENTRY
A3CD  C8              INY
A3CE  C008            CPY      #8
A3D0  90F8 ^A3CA      BCC      :TVS1A
A3D2  88              DEY                     ; AND THEN
A3D3  B9D200      :TVS2   LDA      TVTYPE,Y   ; PUT IN VAR TABLE
A3D6  9197            STA      [SVESA],A      ; ENTRY
A3D8  88              DEY
A3D9  10F8 ^A3D3      BPL      :TVS2
                  ;

;---------156

A3DB  24DB  24D2  :TVSUC  BIT      TVTYPE     ; WAS THERE A PAREN
A3DD  5002 ^A3E1      BVC      :TVNP          ; BR IF NOT
A3DF  C6AC            DEC      TVSCIX         ; LET SYNTAX PAREN
                  ;
A3E1  A5AC        :TVNP   LDA      TVSCIX     ; GET NEW CIX
A3E3  85F2            STA      CIX            ; TO CIX
                  ;
A3E5  A5AF            LDA      STENUM         ; GET TABLE ENTRY NO
A3E7  3007 ^A3F0      BMI      :TVFULL        ; BR IF > $7F
A3E9  0980            ORA      #$80           ; MAKE IT > $7F
A3EB  20C8A2          JSR      :SETCODE       ; SET CODE TO OUTPUT BUFFER
A3EE  18              CLC                     ; SET SUCCESS CODE
A3EF  60              RTS                     ; RETURN
                  ;
A3F0  4C38B9      :TVFULL JMP      ERRVSF     ; GOTO ERROR RTN

;TSTALPH

                  ;                  TEST CIX FOR ALPHA
                  ;
A3F3              ;TSTALPH
A3F3  A4F2            LDY      CIX
A3F5  B1F3            LDA      [INBUFF],Y
A3F7              TSTALPH
A3F7  C941            CMP      #'A'
A3F9  9003 ^A3FE      BCC      :TAFAIL
A3FB  A95B            CMP      #$5B
A3FD  60              RTS

                  ;
A3FE  38          :TAFAIL SEC
A3FF  60              RTS

;TNCON
                  ;               EXTERNAL SUBROUTINE TO CHECK FOR NUMBER
                  ;
A400              :TNCON
A400  20A1DB          JSR      SKBLANK
A403  A5F2            LDA      CIX
A405  85AC            STA      TVSCIX
A407  2000D8          JSR      CVAFP          ; GO TEST AND CONVERT
A40A  9005 ^A411      BCC      :TNC1          ; BR IF NUMBER
A40C  A5AC            LDA      TVSCIX
A40E  85F2            STA      CIX
A410  60              RTS
                  ;
A411  A90E        :TNC1   LDA      #$0E       ; SET NUMERIC CONST
A413  20C8A2          JSR      :SETCODE
                  ;
A416  A494            LDY      COX
A418  A200            LDX      #0
A41A  B5D4        :TNC2   LDA      FR0,X      ; MOVE CONST TO STMT
A41C  9180            STA      [OUTBUFF],Y
A41E  C8              INY
A41F  E8              INX
A420  E006            CPX      #6
A422  90F6 ^A41A      BCC      :TNC2
A424  8494            STY      COX
A426  18              CLC
A427  60              RTS

;TSCON
                  ;                EXT SRT TO CHEXK FOR STR CONST
                  ;
A428              :TSCON
A428  20A1DB          JSR      SKBLANK
A42B  A4F2            LDY      CIX            ; GET INDEX
A42D  B1F3            LDA      [INBUFF],Y     ; GET CHAR
A42F  C922            CMP      #$22           ; IS IT DQUOTE
A431  F002 ^A435      BEQ      :TSC1          ; BR IF DQ
A433  38              SEC                     ; SET FAIL
A434  60              RTS                     ; RETURN

;-------157

A435  A90F        :TSC1   LDA      #$0F       ; SET SCON CODE
A437  20C8A2          JSR      :SETCODE
A43A  A594            LDA      COX            ; SET COX
A43C  85AB            STA      TSCOX          ; SAVE FOR LENGTH
A43E  20C8A2          JSR      :SETCODE       ; SET DUMMY FOR NOW
                  ;
A441  E6F2        :TSC2   INC      CIX        ; NEXT INPUT CHAR
A443  A4F2            LDY      CIX
A445  B1F3            LDA      [INBUFF],Y
A447  C99B            CMP      #CR            ; IS IT CR
A449  F00C ^A457      BEQ      :TSC4          ; BR IF CR
A44B  C922            CMP      #$22           ; IS IT DQ
A44D  F006 ^A455      BEQ      :TSC3          ; BR IF DQ
A44F  20C8A2          JSR      :SETCODE       ; OUTPUT IT
A452  4C41A4          JMP      :TSC2          ; NEXT
                  ;
A455  E6F2        :TSC3   INC      CIX        ; INC CIX OVER DQ
A457  18          :TSC4   CLC
A458  A594            LDA      COX            ; LENGTH IS COX MINUS
A45A  E5AB            SBC      TSCOX          ; LENGTH BYTE COX
A45C  A4AB            LDY      TSCOX
A45E  9180            STA      [OUTBUFF],Y    ; SET LENGTH
                  ;
A460  18              CLC                     ; SET SUCCESS
A461  60              RTS                     ; DONE

;                         Search a Table
                  ;              TABLE FORMAT:
                  ;                 GARBADGE TO SKIP  [N]
                  ;                 ASCII CHAR        [N]
                  ;                   WITH LEAST SIGNIFICANT BYTE HAVING
                  ;                   MOST SIGNIFICANT BIT ON
                  ;              LAST TABLE ENTRY MUST HAVE FIRST ASCII CHAR = 0
                  ;              ENTRY PARM:
                  ;                 X = SKIP LENGTH
                  ;                 A,Y = TABLE ADR [HIGH, LOW]
                  ;                 ARGUMENT = INBUFF + CIX
                  ;              EXIT PARAMS:
                  ;                 CARRY = CLEAR IF FOUND
                  ;                 X = FOUND ARGUMENT END CIX+1
                  ;                 SCRADR = TABLE ENTRY ADR
                  ;                 STENUM = TABLE ENTRY NUMBER
                  ;
A462              SEARCH
A462  86AA            STX      SRCSKP         ; SAVE SKIP FACTOR
                  ;
A464  A2FF            LDX      #$FF           ; SET ENTRY NUMBER
A466  86AF            STX      STENUM         ; TO ZERO
                  ;
A468  8596        :SRC1   STA      SRCADR+1   ; SET SEARCH ADR
A46A  8495            STY      SRCADR
A46C  E6AF            INC      STENUM         ; INC ENTRY NUMBER
A46E  A6F2            LDX      CIX            ; GET ARG DISPL
A470  A4AA            LDY      SRCSKP         ; GET SKIP LENGTH
A472  B195            LDA      [SRCADR],Y     ; GET FIRST CHAR
A474  F027 ^A49D      BEQ      :SRCNF         ; BR IF EOT
A476  A900            LDA      #0             ; SET STATUS = EQ
A478  08              PHP                     ; AND PUSH IT
                  ;
A479  BD8005      :SRC2   LDA      LBUFF,X    ; GET INPUT CHAR
A47C  297F            AND      #$7F           ; TURN OFF MSB
A47E  C92E            CMP      #'.'           ; IF WILD CARD
A480  F01D ^A49F      BEQ      :SRC5          ; THEN BR
A482              :SRC2A
A482  5195            EOR      [SRCADR],Y     ; EX-OR WITH TABLE CHAR
A482                  ASLA                    ; SHIFT MSB TO CARRY
A484 +0A              ASL      A
A485  F002 ^A489      BEQ      :SRC3          ; BR IF [ARG=TAB] CHAR

;---------158

A487  68              PLA                     ; POP STATUS
A488  08              PHP                     ; PUSH NE STATUS
                  ;
A489  C8          :SRC3   INY                 :INC TABLE INDEX
A48A  E8              INX                     ;INC ARG INDEX
A48B  90EC ^A479      BCC      :SRC2          ; IF TABLE MSB OFF, CONTINUE
                  ;                           ;ELSE END OF ENTRY
A48D  28              PLP                     ;GET STATUS
A48E  F00B ^A49B      BEQ      :SRCFOUND      ;BR IF NO MIS MATCH
                  ;
A490              SRCNXT
A490  18              CLC
A491  98              TYA                     ;ACV=ENTRY LENGTH
A492  6595            ADC      SRCADR         ;PLUS START ADR [L]
A494  A8              TAY                     ;TO Y
A495  A596            LDA      SRCADR+1       ;ETC
A497  6900            ADC      #0
A499  D0CD ^A468      BNE      :SRC1          ;BR ALLWAYS
                  ;
A49B  18          :SRCFND CLC                 ;INDICATE FOUND
A49C  60              RTS
                  ;
A49D  38          :SRCNF  SEC                 ;INDICATE NOT FOUND
A49E  60              RTS
                  ;
A49F  A902        :SRC5   LDA     #1          ; IF NOT
A4A1  C5AA            CMP     SRCSKP          ; STMT NAME TABLE
A4A3  D0DD ^A482      BNE     :SRC2A          ; THEN IGNORE
A4A5  B195        :SRC6   LDA     [SRCADR],Y      ;TEST MSB OF TABLE
A4A7  3003 �4AC       BMI     :SRC7           ; IF ON DONE
A4A9  C8              INY                     ; ELSE
A4AA  D0F9 ^A4A5      BNE     :SRC6           ; LOOK AT NEXT CHAR
A4AC  38          :SRC7   SEC                 ; INDICATE MSB ON
A4AD  B0DA ^A489      BCS     :SRC3           ; AND RE-ENTER CODE

;                        Statement Name Table
                  ;
                  ; SNTAB- STATEMENT NAME TABLE
                  ;       EACH ENTRY HAS SYNTAX TABLE ADR PTR
                  ;       FOLLOWED BY STMT NAME
                  ;
A4AF              SNTAB
                  ;
A4AF  C7A7            DW      :SREM-1
A4B1  5245CD          DC      'REM'
                  ;
A4B4  CAA7            DW      :SDATA-1
A4B6  444154C1        DC      'DATA'
                  ;
A4BA  F3A6            DW      :SINPUT-1
A4BC  494E5055D4      DC      �NPUT'
                  ;
A4C1  BCA6            DW      :SCOLOR-1
A4C3  434F4C4FD2      DC      'COLOR'
                  ;
A4C8  32A7            DW      :SLIST-1
A4CA  4C4953D4        DC      'LIST'
                  ;
A4CE  23A7            DW      :SENTER-1
A4D0  454E5445D2      DC      'ENTER'
A4D5  BFA6            DW      :SLET-1
A4D7  4C45D4          DC      'LET'
                  ;
A4DA  93A7            DW      :SIF-1
A4DC  49C6            DC      'IF'
                  ;
A4DE  D1A6            DW      :SFOR-1
A4E0  464FD2          DC      'FOR'
                  ;
A4E3  E9A6            DW      :SNEXT-1

;---------159

A4E5  4E4558D4        DC      'NEXT'
                  ;
A4E9  BCA6            DW      :SGOTO-1
A4EB  474F54CF        DC      'GOTO'
                  ;
A4EF  BCA6            DW      :SGOTO-1
A4F1  474F2054CF      DC      'GO TO'
                  ;
A4F6  BCA6            DW      :SGOSUB-1
A4F8  474F5355C2      DC      'GOSUB'
                  ;
A4FD  BCA6            DW      :STRAP-1
A4FF  545241D0        DC      'TRAP'
                  ;
                  ;
A503  BD              DW      :SBYE-1
A505  4259C5          DC      'BYE'
                  ;
A508  BDA6            DW      :SCONT-1
A50A  434F4ED4        DC      'CONT'
                  ;
A50E  5FA7            DW      :SCOM-1
A510  434FCD          DC      'COM'
                  ;
                  ;
A513  20A7            DW      :SCLOSE-1
A515  434C4F53C5      DC      'CLOSE'
                  ;
A51A  BDA6            DW      :SCLR-1
A51C  434CD2          DC      'CLR'
A51F  BDA6            DW      :SDEG-1
A521  4445C7          DC      'DEG'
                  ;
A524  5FA7            DW      :SDIM-1
A526  4449CD          DC      'DIM'
                  ;
A529  BDA6            DW      :SEND-1
A52B  454EC4          DC      'END'
                  ;
A52E  BDA6            DW      :SNEW-1
A530  4E45D7          DC      'NEW'
                  ;
A533  19A7            DW      :SOPEN-1
A535  4F5045CE        DC      'OPEN'
A539  23A7            DW      :SLOAD-1
A53B  4C4F41C4        DC      'LOAD'
A53F  23A7            DW      :SSAVE-1
A541  535156C5        DC      'SAVE'
A545  40A7            DW      :SSTATUS-1
A547  5354415455      DC      'STATUS'
      D3
A54D  49A7            DW      :SNOTE-1
A54F  4E4F54C5        DC      'NOTE'
A553  49A7            DW      :SPOINT-1
A555  504F494ED4      DC      'POINT'
A55A  17A7            DW      'SXIO-1
A55C  5849CF          DC      'XIO'
                  ;
A55F  62A7            DW      :SON-1
A561  4FCE            DC      'ON'
                  ;
A563  5CA7            DW      :SPOKE-1
A565  504F4BC5        DC      'POKE'
                  ;
A569  FBA6            DW      :SPRINT-1
A56B  5052494ED4      DC      'PRINT'
                  ;
A570  BDA6            DW      :SRAD-1
A572  5241C4          DC      'RAD'
                  ;
A575  F4A6            DW      :SREAD-1

;---------160

A577  524541C4        DC      'READ'
                  ;
A57B  EEA6            DW      :SREST-1
A57D  524553544F      DC      'RESTORE'
      52C5
                  ;
A584  BDA6            DW      :SRET-1
A586  5245545552      DC      'RETURN'
      CE
                  ;
A5BC  26A7            DW      :SRUN-1
A58E  5255CE          DC      'RUN'
                  ;
A591  8DA6            DW      :SSTOP-1
A593  53544FD0        DC      'STOP'
                  ;
A597  BDA6            DW      :SPOP-1
A599  504FD0          DC      'POP'
                  ;
A59C  FBA6            DW      :SPRINT-1
A59E  BF              DC      '?'
                  ;
A59F  E7A6            DW      :SGET-1
A5A1  4745D4          DC      'GET'
A5A4  B9A6            DW      :SPUT-1
A5A6  5055D4          DC      'PUT'
A5A9  BCA6            DW      :SGR-1
A5AB  4752415048      DC      'GRAPHICS'
      4943D3
                  ;
A5B3  5CA7            DW      :SPLOT-1
A5B5  504C4FD4        DC      'PLOT'
                  ;
A5B9  5CA7            DW      :SPOS-1
A5BB  504F534954      DC      'POSITION'
      494FCE
                  ;
A5C3  BDA6            DW      :SDOS-1
A5C5  444FD3          DC      'DOS'
                  ;
A5C8  5CA7            DW      :DRAWTO-1
A5CA  4452415754      DC      'DRAWTO'
      CF
                  ;
A5D0  5AA7            DW      :SSETCOLOR-1
A5D2  534554434F      DC      'SETCOLOR'
      4C4FD2
                  ;
A5DA  E1A6            DW      :LOCATE-1
A5DC  4C4F434154      DC      'LOCATE'
      C5
                  ;
A5E2  58A7            DW      :SSOUND-1
A5E4  534F554EC4      DC      'SOUND'
A5E9  FFA6            DW      :SLPRINT-1
A5EB  4C5052494E      DC      'LPRINT'
      D4
                  ;
A5F1  BDA6            DW      :SCSAVE-1
A5F3  43534156C5      DC      'CSAVE'
A5F8  BDA6            DW      :SCLOAD-1
A5FA  434C4F41C4      DC      'CLOAD'
A5FF  BFA6            DW      :SILET-1
A601  00              DB      0
A602  8000            DB      $80,00
A604  2A4552524F      DB      '*ERROR- '
      522D20
A60C  A0              DB      $A0

;---------161

;Syntax Tables

;Syntax Table OP Codes

   = 0000         :ANTV   EQU      $00        ; ABSOLUTE NON TERMINAL VECTOR
                  ;                                 FOLLOWED BY 2 BYTE ADR -1
   = 0001         :ESRT   EQU      $01        ; EXTERNAL SUBROUTINE CALL
                  ;                                 FOLLOWED BY 2 BYTE ADR -1
   = 0002         :OR     EQU      $02        ; ALTERNATIVE, BNF OR (])
   = 0003         :RTN    EQU      $03        ; RETURN (#)
   = 0004         :NULL   EQU      $04        ; ACCEPT TO THIS POINT (&)
   = 000E         :VEXP   EQU      $0E        ; SPECIAL NTV FOR EXP (<EXP>)
   = 000F         :CHNG   EQU      $0F        ; CHANGE OUTPUT TOKEN

;<EXP>=(EXP>)<NOP>|<UNARY><EXP>|<NV><NOP>#

A60D              :EXP    SYN      CLPRN
A60D +2B                DB    CLPRN
A60E                  SYN      JS,:EXP
A60E +BF              DB      $80+(((:EXP-*)&$7F) XOR $40 )
A60F                  SYN      CRPRN
A60F +2F                DB    CRPRN
A610                  SYN      JS,:NOP
A610 +DE              DB      $80+(((:NOP-*)&$7F) XOR $40 )
A611                  SYN      :OR
A611 +02                DB    :OR
A612                  SYN      JS,:UNARY
A612 +C6              DB      $80+(((:UNARY-*)&$7F) XOR $40 )
A613                  SYN      JS,:EXP
A613 +BA              DB      $80+(((:EXP-*)&$7F) XOR $40 )
A614                  SYN      :OR
A614 +02               DB     :OR
A615                  SYN      JS,:NV
A615 +CD              DB      $80+(((:NV-*)&$7F) XOR $40 )
A616                  SYN      JS,:NOP
A616 +D8              DB      $80+(((:NOP-*)&$7F) XOR $40 )
A617                  SYN      :RTN
A617 +03                DB    :RTN

;<UNARY>=+|.|NOT#
                  ;
A618              :UNARY  SYN      CPLUS
A618 +25                DB    CPLUS
A619                  SYN      :CHNG,CUPLUS
A619 +0F                DB    :CHNG
A61A +35                DB    CUPLUS
A61B                  SYN      :OR
A61B +02                DB    :OR
A61C                  SYN      CMINUS
A61C +26                DB    CMINUS
A61D                  SYN      :CHNG,CUMINUS
A61D +0F                DB    :CHNG
A61E +36                DB    CUMINUS
A61F                  SYN      :OR
A61F +02                DB    :OR
A620                  SYN      CNOT
A620 +28                DB    CNOT
A621                  SYN      :RTN
A621 +03                DB    :RTN

;<NV>=<NFUN>|<NVAR>|<NCON>|<STCOMP>#

A622              :NV     SYN      JS,:NFUN,:OR
A622 +FD              DB      $80+(((:NFUN-*)&$7F) XOR $40)
A623 +02                DB    :OR
A624                  SYN      JS,:NVAR,:OR
A624 +E8              DB      $80+(((:NVAR-*)&$7F) XOR $40 )          
A625                    DB    :OR
A626                  SYN      :ESRT,AD,:TNCON-1,:OR
A626 +01                DB    :ESRT

;--------162

A627 +FFA3              DW    (:TNCON-1)
A629 +02                DB    :OR
A62A                  SYN      :(ANTV,AD,:STCOMP-1)
A62A +00                DB    :ANTV
A62B +7DA6              DW    (:STCOMP-1)
A62D                  SYN      :RTN
A62D +03                DB    :RTN

;<NOP>=<OP><EXP>|&#

A62E              :NOP    SYN      JS,:OP
A62E +C4              DB      $80+(((:OP-*)&$7F) XOR $40 )
A62F                  SYN      JS,:EXP
A62F +9E              DB      $80+(((:EXP-*)&$7F) XOR $40 )
A630                  SYN      :OR
A630 +02                DB    :OR
A631                  SYN      :RTN
A631 +03                DB    :RTN

;<OP>=**|*|/|<=|S=|<>|<|>|=|AND|OR#

A632              :OP     SYN      CEXP,:OR
A632 +23                DB    CEXP
A633 +02                DB    :OR
A634                  SYN      CPLUS,:OR
A634 +25                DB    CPLUS
A635 +02                DB    :OR
A636                  SYN      CMINUS,:OR
A636 +26                DB    CMINUS
A637 +02                DB    :OR
A638                  SYN      CMUL,:OR
A638 +24                DB    CMUL
A639 +02                DB    :OR
A63A                  SYN      CDIV,:OR
A63A +27                DB    CDIV
A63B +02                DB    :OR
A63C                  SYN      CLE,:OR
A63C +1D                DB    CLE
A63D +02                DB    :OR
A63E                  SYN      CGE,:OR
A63E +1F                DB    CGE
A63F +02                DB    :OR
A640                  SYN      CNE,:OR
A640 +1E                DB    CNE
A641 +02                DB    :OR
A642                  SYN      CLT,:OR
A642 +20                DB    CLT
A643 +02                DB    :OR
A644                  SYN      CGT,:OR
A644 +21                DB    CGT
A645 +02                DB    :OR
A646                  SYN      CEQ,:OR
A646 +22                DB    CEQ
A647 +02                DB    :OR
A648                  SYN      CAND,:OR
A648 +2A                DB    CAND
A649 +02                DB    :OR
A64A                  SYN      COR
A64A +29                DB    COR
A64B                  SYN      :RTN
A64B +03                DB    :RTN

<NVAR>=<TNVAR><NMAT>#

A64C              :NVAR   SYN      :ESSRT,AD,TNVAR-1
A64C +01                DB    :ERST
A64D +29A3              DW    (:TNVAR-1)
A64F                  SYN      JS,lNMAT
A64F +C2              DB      $80+(((:NMAT-*)&$7F) XOR $40)
A650                  SYN      :RTN
A650 +03                DB    :RTN

;--------163

;<NMAT>=(<EXP><NMAT2>)|&#

A651              :NAMT   SYN      CLPRN,:CHNG,CALPRN
A651 +2B                DB    CLPRN
A652 +0F                DB    :CHNG
A653 +38                DB    CALPRN
A654                  SYN      :VEXP
A654 +0E                DB    :VEXP
A655                  SYN      JS,:NMAT2
A655 +C4              DB      $80+(((:NMAT2-*)&$7F) XOR $40 )
A656                  SYN      CRPRN
A656 +2C                DB    CRPRN
A657                  SYN      :OR
A657 +02                DB    :OR
A658                  SYN      :RTN
A658 +03                DB    :RTN

;<NMAT2>=,<EXP>|&#

A659              :NAMT2   SYN      CCOM,:CHNG,CACOM
A659 +12                DB     CCOM
A65A +0F                DB     :CHNG
A65B +3C                DB     CACOM
A65C                  SYN      :VEXP
A65C +0E                DB    :VEXP
A65D                  SYN      :OR
A65D +02                DB    :OR
A65E                  SYN      :RTN
A65E +03                DB    :RTN

;<NFUN>=<NFNP><NFP>|<NFSP>|<NFUSR>#

A65F              :NFUN    SYN      CNFNP
A65F +44                DB     CNFNP
A660                  SYN       JS,:NFP
A660 +D2              DB       $80+(((:NFP-*)#$7F) XOR $40)
A661                  SYN      :OR
A661 +02                DB    :OR
A662                  SYN      :ANTV,AD,:NFSP-1
A662 +00                DB    :ANTV
A663 +CDA7              DW    (:NFSP-1)
A665                  SYN      JS,:SFP
A665 +D3              DB       $80+(((:SFP-*)#$7F) XOR $40)
A666                  SYN      :OR
A666 +02                DB    :OR
A667                  SYN      JS,:NFUSR
A667 +C2              DB       $80+(((:NFUSR-*)#$7F) XOR $40)
A668                  SYN      :RTN
A668 +03                DB    :RTN

;<NFUSR>=USR(<PUSR>)#

A669              :NFURS  SYN      CUSR
A669 +3F                DB    CUSR
A66A                  SYN      CLPRN,:CHNG,CFLPRN
A66A +2B                DB    CLPRN
A66B +0F                DB    :CHNG
A66C +3A                DB    CFLPRN
A66D                  SYN      :ANTV,AD,:PUSR-1
A66D +00                DB    :ANTV
A66E +D9A7              DW    (:PUSR-1)
A670                  SYN      CRPRN
A670 +2C                DB    CRPRN
A671                  SYN      :RTN
A672 +03                DB    :RTN

;<NFP>=(<EXP>)#

A672              :NFP    SYN      CLPRN,:CHNG,CFLPRN
A672 +2B                DB    CLPRN
A673 +0F                DB    :CHNG
A674 +3A                DB    CFLPRN
A675                  SYN      :VEXP

;--------164

A675 +0E                DB    :VEXP
A676                  SYN      CRPRN
A676 +2C                DB    CRPRN
A677                  SYN      :RTN
A667 +03                DB    :RTN

;<SFP>=<STR>)#

A678              :SFP    SYN      CLPRN,:CHNG,CFLPRN
A678 +2B                DB    CLPRN
A679 +0F                DB    :CHNG
A67A +3A                DB    CFLPRN
A67B                  SYN      JS,:STR
A67B +C7              DB      $80+(((:STR-*)&$7F) XOR $40 )
A67C                  SYN      CRPRN
A67C +2C                DB    CRPRN
A67D                  SYN      :RTN
A66D +03                DB    :RTN

;<STCOMP>=<STR><SOP><STR>#

A67E              :STCOMP SYN      JS,:STR
A67E +C4              DB      $80+(((:STR-*)&$7F) XOR $40 )
A67F                  SYN      JS,:SOP
A67F +E3              DB      $80+(((:SOP-*)&$7F) XOR $40 )
A680                  SYN      JS,:STR
A680 +C2              DB      $80+(((:STR-*)&$7F) XOR $40 )
A681                  SYN      :RTN
A681 +03                DB    :RTN

;<STR>=<SFUN>|<SVAR>|<SCON>#

A682              :STR    SYN      JS,:SFUN
A682 +C8              DB      $80+(((:SFUN-*)&$7F) XOR $40 )
A683                  SYN      :OR
A683 +02                DB    :OR
A684                  SYN      JS,:SVAR
A684 +CB              DB      $80+(((:SVAR-*)&$7F) XOR $40 )
A685                  SYN      :OR
A685 +02                DB    :OR
A686                  SYN      :ESRT,AD,:TSCON-1
A686 +01                DB    :ESRT
A687 +27A4              DW    (:TSCON-1)
A689                  SYN      :RTN
A689 +03                DB    :RTN

;<SFUN>=SFNP<NFP>#

A68A              :SFUN   SYN      :ANTV,AD,:SFNP-1
A68A +00                DB    :ANTV
A68B +D5A7              DW    (:SFNP-1)
A68D                  SYN      JS,:NFP
A68D +A5              DB      $80+(((:NFP-*)&$7F) XOR $40 )
A68E                  SYN      :RTN
A68E +03                DB    :RTN

;<SVAR>=<TSVAR><SMAT>#

A68FA              :STR    SYN      :ESRT,AD,:TSVAR-1
A68F +01                 DB    :ESRT
A690 +2DA3               DW    (:TSVAR-1)
A692                   SYN      JS,:SMAT
A692 +C2               DB      $80+(((:SMAT-*)&$7F) XOR $40 )
A693                  SYN      :RTN
A693 +03                DB    :RTN

;<SMAT>=(<EXP><SMAT2>)|&#

A694               :SMAT   SYN      CLPRN,:CHNG,CSLPRN
A694 +2B                DB    CLPRN
A695 +0F                DB    :CHNG
A696 +37                DB    CSLPRN

;--------165

A697                  SYN      :VEXP
A697 +0E                DB    :VEXP
A698                  SYN      JS,:SMAT2
A698 +C4              DB      $80+(((:SMAT2-*)&$7F) XOR $40 )
A699                  SYN      CRPRN
A699 +2C                DB    CRPRN
A69A                  SYN      :OR
A69A +02                DB    :OR
A69B                  SYN      :RTN
A69B +03                DB    :RTN

;<SMAT2>=,<EXP>|&#

A69C               :SMAT2  SYN      CCOM,:CHNG,CACOM
A69C +12                DB    CCOM
A69D +0F                DB    :CHNG
A69E +3C                DB    CACOM
A69F                  SYN      :VEXP
A69F +0E                DB    :VEXP
A6A0                  SYN      :OR
A6A0 +02                DB    :OR
A6A1                  SYN      :RTN
A6A1 +03                DB    :RTN

;<SOP>=<><#

A6A2               :SOP
A6A2                   SYN      CLE,:CHNG,CSLE,:OR
A6A2 +1D                DB    CLE
A6A3 +0F                DB    :CHNG
A6A4 +2F                DB    CSLE
A6A5 +02                DB    :OR
A6A6                   SYN      CNE,:CHNG,CSNE,:OR
A6A6 +1E                DB    CNE
A6A7 +0F                DB    :CHNG
A6A8 +30                DB    CSNE
A6A9 +02                DB    :OR
A6AA                   SYN      CGE,:CHNG,CSGE,:OR
A6AA +1F                DB    CGE
A6AB +0F                DB    :CHNG
A6AC +31                DB    CSGE
A6AD +02                DB    :OR
A6AE                   SYN      CLT,:CHNG,CSLT,:OR
A6AE +20                DB    CLT
A6AF +0F                DB    :CHNG
A6B0 +32                DB    CSLT
A6B1 +02                DB    :OR
A6B2                   SYN      CGT,:CHNG,CSGT,:OR
A6B2 +21                DB    CGT
A6B3 +0F                DB    :CHNG
A6B4 +33                DB    CSGT
A6B5 +02                DB    :OR
A6B6                   SYN      CEQ,:CHNG,CSEQ
A6B6 +22                DB    CEQ
A6B7 +0F                DB    :CHNG
A6B8 +34                DB    CSEQ
A6B9                  SYN      :RTN
A6B9 +03                DB    :RTN

;<PUT>=<D1>,<EXP><EOS>#

A6BA               :SPUT
A6BA                   SYN      CPND,:VEXP
A6BA +1C                DB    CPND
A6BB +0E                DB    :VEXP
A6BC                   SYN      CCOM
A6BC +12                DB    CPND

;--------166

;< >=<EXP><EOS>#

A6BD               :STRAP
A6BD               :SGOTO
A6BD               :SGOSUB
A6BD               :SGR
A6BD               :SCOLOR
A6BD               :SEOS   SYN      :VEXP
A6BD +0E                 DB    :VEXP

;< >=EOS>#

A6BE               :SCSAVE
A6BE               :SCLOAD
A6BE               :SDOS
A6BE               :SCLR
A6BE               :SRET
A6BE               :SEND
A6BE               :SSTOP
A6BE               :SPOP
A6BE               :SNEW
A6BE               :SBYE
A6BE               :SCONT
A6BE               :SDEG
A6BE               :SRAD
A68E                   SYN      JS,:EOS
A6BE +FA               DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6BF                   SYN      :RTN
A6BF +03                 DB    :RTN

;<LET>=<NVAR>=<EXP><EOS>|<SVAR>=<STR><EOS>#

A6C0               :SLET
A6C0               :SILET
A6C0                   SYN      :ANTV,AD,:NVAR-1
A6C0 +00                 DB    :ANTV
A6C1 +4BA6               DW    (:NVAR-1)
A6C3                   SYN      CEQ,:CHNG,CAASN
A6C3 +22                DB     CEQ
A6C4 +0F                DB     :CHNG
A6C5 +2D                DB     CAASN
A6C6                  SYN       :VEXP
A6C6 +0E                DB     :VEXP
A6C7                  SYN      JS,:EOS
A6C7 +F1              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6C8                  SYN      :OR
A6C8 +02                DB    :OR
                   ;
A6C9                  SYN      JS,:SVAR
A6C9 +86F1              DB      $80+(((:SVAR-*)&$7F) XOR $40 )
A6CA +22                DB     CEQ
A6CB +0F                DB     :CHNG
A6CC +2E                DB     CSASN
A6CD                   SYN      ANTV,AD,:STR-1
A6CD +00                DB     :ANTV
A6CE +81A6              DB     (:STR-1)
A6D0                  SYN      JS,:EOS
A6D0 +E8                DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6D1                  SYN      :RTN
A6D1 +03                DB    :RTN

;<FOR>=<TNVAR>=<EXP>TO<EXP><FSTEP><EOS>#

A6D2              :SFOR   SYN      :ESRT,AD,:TNVAR-1
A6D2 +01                DB    :ESRT
A6D3 +29A3              DW    (:TNAR-1)
A6D5                  SYN      CEQ,:CHNG,CAASN
A6D5 +22                DB    CEQ
A6D6 +0F                DB    :CHNG
A6D7 +2D                DB    CAASN

;--------167

A6D8                  SYN      :VEXP
A6D8 +0E                DB    :VEXP
A6D9                  SYN      CTO
A6D9 +19                DB    CTO
A6DA                  SYN      :VEXP
A6DA +0E                DB    :VEXP
A6DB                  SYN      JS,:FSTEP
A6DB +C3              DB      $80+(((:FSTEP-*)&$7F) XOR $40 )
A6DC                  SYN      JS,:EOS
A6DC +DC              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6DD                  SYN      :RTN
A6DD +03                DB    :RTN

;<FSTEP>=STEP<EXP>|&

A6DE              :FSTEP
A6DE                  SYN      CSTEP
A6DE +1A                DB    CSTEP
A6DF                  SYN      :VEXP
A6DF +0E                DB    :VEXP
A6E0                  SYN      :OR
A6E0 +02                DB    :OR
A6E1                  SYN      :RTN
A6E1 +03                DB    :RTN

;<LOCATE>=<EXP>,<EXP>,<TNVAR><EOL>#

A6E2              :SLOCATE
A6E2                  SYN      :VEXP
A6E2 +0E                DB    :VEXP
A6E3                  SYN      CCOM
A6E3 +12                DB    CCOM
A6E4                  SYN      :VEXP
A6E4 +0E                DB    :VEXP
A6E5                  SYN      CCOM
A6E5 +12                DB    CCOM
A6E6                  SYN      JS,:SNEXT
A6E6 +C4              DB      $80+(((:SNEXT-*)&$7F) XOR $40 )
A6E7                  SYN      :RTN
A6E7 +03                DB    :RTN

;<GET>=<D1>,<TNVAR>#

A6E8              :SGET
A6E8                  SYN      JS,:D1
A6E8 +DD              DB      $80+(((:D1-*)&$7F) XOR $40 )
A6E9                  SYN      CCOM
A6E9 +12                DB    CCOM

;<NEXT>=<TNVAR><EOS>#

A6EA              :SNEXT  SYN      :ESRT,AD,:TNVAR-1
A6EA +01                DB    :ESRT
A6EA +29A3              DW    (:TNAR-1)
A6ED                  SYN      JS,:EOS
A6ED +CB              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6EE                  SYN      :RTN
A6EE +03                DB    :RTN

;<RESTORE>=<EXP><EOS>|<EOS>#

A6EF              :SREST  SYN     :VEXP
A6EF +0E                DB   :VEXP
A6F0                  SYN      JS,:EOS
A6F0 +CB              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6F1                  SYN      :OR
A6F1 +02                DB    :OR
A6F2                  SYN      JS,:EOS
A6F2 +C6              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6F3                  SYN      :RTN
A6F3 +03                DB    :RTN

;-------168

;<INPUT>=<OPD><READ>#

A6F4              :SLINPUT SYN      JS,:OPD
A6F4 +F8               DB      $80+(((:OPD-*)&$7F) XOR $40 )

;<READ>=<NSVARL><EOS>#

A6F5              :SREAD   SYN      JS,:NSVRL
A6F5 +DB               DB      $80+(((:NSVRL-*)&$7F) XOR $40 )
A6F6                  SYN      JS,:EOS
A6F6 +C2              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6F7                  SYN      :RTN
A6F7 +03                DB    :RTN

;EOS=:|CR#

A6F8              :EOS   SYN      CEOS
A6F8 +14               DB    CEOS
A6F9                  SYN      :OR
A6F9 +02                DB    :OR
A6FA                  SYN      CCR
A6FA +16                DB    CCR
A6FB                  SYN      :RTN
A6FB +03                DB    :RTN

;<PRINT>=<D1><EOS>|<D1><PR1><EOS>

A6FC              :SPRINT
A6FC                  SYN      JS,:D1
A6FC +C9              DB      $80+(((:D1-*)&$7F) XOR $40 )
A6FD                  SYN      JS,:EOS
A6FD +BB              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A6FE                  SYN      :OR
A6FE +02                DB    :OR
A6FF                  SYN      JS,:OPD
A6FF +ED              DB      $80+(((:OPD-*)&$7F) XOR $40 )
A700              :SLPRINT
A700                  SYN      :ANTV,AD,PR1-1
A700 +00                DB    :ANTV
A701 +9FA7              DW    (:PR1-1)
A703                  SYN      JS,:EOS
A703 +B5              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A704                  SYN      :RTN
A704 +03                DB    :RTN

;<D1>=<CPND><EXP>#

A705              :D1      SYN      CPND
A705 +1C                 DB    CNPD
A706                  SYN      :VEXP
A706 +0E                DB    :VEXP
A707                  SYN      :RTN
A707 +03                DB    :RTN

<NSVAR>=<NVAR>|<SVAR>#

A708              :NSVAR  SYN      :ESRT,AD,:TNVAR-1
A708 +01                DB    :ESRT
A709 +29A3              DW    (:TNAR-1)
A70B                  SYN      :OR
A70B +02                DB    :OR
A70C                  SYN      :ESRT,AD,:TNVAR-1
A70C +01                DB    :ESRT
A70D +29A3              DW    (:TNAR-1)
A70F                  SYN      :RTN
A70F +03                DB    :RTN

;<NSVRL>=<NSVAR><NSV2>|&#

A710              :NSVRL  SYN      JS,:NSVAR
A710 +B8              DB      $80+(((:NSVAR-*)&$7F) XOR $40 )
A711                  SYN      JS,:NSV2

;-------169

A711 +C3              DB      $80+(((:NSV2-*)&$7F) XOR $40 )
A712                  SYN      :OR,:RTN
A712 +02                DB    :OR
A713 +03                DB    :RTN

;<NSV2>=,<NSVRL>|&#

A714              :NSV2   SYN      CCOM
A714 +12                DB    CCOM
A715                      SYN      JS,:NSVRL
A715 +BB              DB      $80+(((:NSVRL-*)&$7F) XOR $40 )
A716                  SYN      :OR,:RTN
A716 +02                DB    :OR
A717 +03                DB    :RTN

;<XIO>=<AEXP>,<DS2><FS>,<AEXP><EOS>#

A718              :SXIO
A718                  SYN      :VEXP
A718 +0E                DB    :VEXP
A719                  SYN      CCOM
A719 +12                DB    CCOM

;<OPEN>=<D1>,<EXP>,<EXP>,<FS>,<EOS>#

A71A              :SOPEN
A71A                  SYN      JS,:D1
A71A +AB              DB      $80+(((:D1-*)&$7F) XOR $40 )
A71B                  SYN      CCOM
A71B +12                DB    CCOM
A71C                  SYN      JS,:TEXP
A71C +AB              DB      $80+(((:TEXP-*)&$7F) XOR $40 )
A71D                  SYN      CCOM
A71D +12                DB    CCOM
A71E                  SYN      JS,:FS
A71E +F3              DB      $80+(((:FS-*)&$7F) XOR $40 )
A71F                  SYN      JS,:EOS
A71F +99              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A720                  SYN      :RTN
A720 +03                DB    :RTN

;<CLOSE>=<D1><EOS>#

A721              :SCLOSE
A721                  SYN      JS,:D1
A721 +A4              DB      $80+(((:D1-*)&$7F) XOR $40 )
A722                  SYN      JS,:EOS
A722 +96              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A723                  SYN      :RTN
A723 +03                DB    :RTN

;< >=<FS><EOS>#

A724              :SENTER
A724              :SLOAD
A724              :SSAVE
A724                  SYN      JS,:FS
A724 +ED              DB      $80+(((:FS-*)&$7F) XOR $40 )
A725                  SYN      JS,:EOS
A725 +93              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A726                  SYN      :RTN
A726 +03                DB    :RTN

;<RUN>=<FS><EOS2>|<EOS2>#

A727              :SRUN
A727                  SYN      JS,:FS
A727 +EA              DB      $80+(((:FS-*)&$7F) XOR $40 )
A728                  SYN      JS,:EOS
A728 +90              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A729                  SYN      :OR
A729 +02                DB    :OR

;-------170

A72A                  SYN      JS,:EOS
A72A +BE              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A72B                  SYN      :RTN
A72B +03                DB    :RTN

;<OPD>=<D1>,|#

A72C              :OPD
A72C                  SYN      JS,:D1
A72C +99              DB      $80+(((:D1-*)&$7F) XOR $40 )
A72D              :OPDX   SYN      CCOM
A72D +12                DB    CCOM
A72E                  SYN      :OR
A72E +02                DB    :OR
A72F                  SYN      JS,:D1
A72F +96              DB      $80+(((:D1-*)&$7F) XOR $40 )
A730                  SYN      CSC
A730 +15                DB    CSC
A731                  SYN      :OR
A731 +02                DB    :OR
A732                  SYN      :RTN
A732 +03                DB    :RTN

;<LIST>=<FS>;<L2>|<L2>#

A733              :SLIST
A733                  SYN      JS,:FS
A733 +DE              DB      $80+(((:FS-*)&$7F) XOR $40 )
A734                  SYN      JS,:EOS
A734 +84              DB      $80+(((:EOS-*)&$7F) XOR $40 )
A735                  SYN      :OR
A735 +02                DB    :OR
A736                  SYN      JS,:FS
A736 +DB              DB      $80+(((:FS-*)&$7F) XOR $40 )
A737                  SYN      CCOM
A737 +12                DB    CCOM
A738                  SYN      JS,:LIS
A738 +C4              DB      $80+(((:LIS-*)&$7F) XOR $40 )
A739                  SYN      :OR
A739 +02                DB    :OR
A73A                  SYN      JS,:LIS
A73A +C2              DB      $80+(((:LIS-*)&$7F) XOR $40 )
A73B                  SYN      :RTN
A73B +03                DB    :RTN

;<LIS>=<L1><EOS>#

A73C              :LIS
A73C                  SYN      :ANTV,AD,:L1-1
A73C +00                DB    :ANTV
A73D +BFA7              DW    (:L1-1)
A73F                  SYN      JS,:EOS2
A73F +F4              DB      $80+(((:EOS2-*)&$7F) XOR $40 )    
A740                  SYN      :RTN
A740 +03                DB    :RTN

;<STATUS>=<STAT><EOS>#

A741              :SSTATUS
A741                  SYN      JS,:STAT
A741 +C3              DB      $80+(((:STAT-*)&$7F) XOR $40 )
A742                  SYN      JS,:EOS2
A742 +F1              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A743                  SYN      :RTN
A743 +03                DB    :RTN

;<STAT>=<D1>,<NVAR>#

A744              :SSTAT
A744                  SYN      JS,:D1
A744 +81              DB      $80+(((:D1-*)&$7F) XOR $40 )

;-------171

A745                  SYN      CCOM
A745 +12                DB    CCOM
A746                  SYN      :ANTV,AD,:NVAR-1
A746 +00                DB    :ANTV
A747 +4BA6              DW    (:NVAR-1)
A749                  SYN      :RTN
A749 +03                DB    :RTN

;< >=<STAT>,<NVAR><EOS2>#

A74A              :SNOTE
A74A              :SPOINT
A74A                  SYN      JS,:STAT
A74A +BA              DB      $80+(((:STAT-*)&$7F) XOR $40 )
A74B                  SYN      CCOM
A74B +12                DB    CCOM  
A74C                  SYN      :ANTV,AD,:NVAR-1
A74C +00                DB    :ANTV
A74D +4BA6              DW    (:NVAR-1)
A74E                  SYN      JS,:EOS2
A74E +E4              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A750                  SYN      :RTN
A750 +03                DB    :RTN

;<FS>=<STR>

A751              :SFS
A751                  SYN      :ANTV,AD,:STR-1
A751 +00                DB    :ANTV
A752 +81A6              DW    (:STR-1)
A754                  SYN      :RTN
A754 +03                DB    :RTN

;<TEXP>=<EXP>,<EXP>#

A755              :TEXP
A755                  SYN      :VEXP
A755 +03                DB    :VEXP
A756                  SYN      :CCOM
A756 +12                DB    :CCOM
A757                  SYN      :VEXP
A757 +0E                DB    :VEXP
A758                  SYN      :RTN
A758 +03                DB    :RTN

;<SOUND>=<EXP>,<EXP>,<EXP>,<EXP><EOS>#

A759              :SSOUND
A759                  SYN      :VEXP
A759 +0E                DB    :VEXP
A75A                  SYN      :CCOM
A75A +12                DB    :CCOM
A75B              :SSETCOLOR
A75B                  SYN      :VEXP
A75B +0E                DB    :VEXP
A75C                  SYN      :CCOM
A75C +12                DB    :CCOM

;< >=<EXP>,<EXP><EOS>#

A75D              :SPOKE
A75D              :SPLOT
A75D              :SPOS
A75D              :SDRAWTO
A75D                  SYN      JS,:TEXP
A75D +B8              DB      $80+(((:TEXP-*)&$7F) XOR $40 )
A75E                  SYN      JS,:EOS2
A75E +D5              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A75F                  SYN      :RTN
A75F +03                DB    :RTN

;<DIM>=<NSML><EOS>#

A760              :SDIM
A760              :SCOM
A760                  SYN      JS,:NSML
A760 +EC              DB      $80+(((:NSML-*)&$7F) XOR $40 )
A761                  SYN      JS,:EOS2
A761 +D2              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A762                  SYN      :RTN
A762 +03                DB    :RTN

;<ON>=<EXP><ON1><EXPL><EOS>#

A763              :SON    SYN      :VEXP
A763 +0E                DB    :VEXP
A764                  SYN      JS,:ON1
A764 +C4              DB      $80+(((:ON1-*)&$7F) XOR $40 )
A765                  SYN      JS,:EXPL
A765 +C7              DB      $80+(((:EXPL-*)&$7F) XOR $40 )
A766                  SYN      JS,:EOS2
A766 +CD              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A767                  SYN      :RTN
A767 +03                DB    :RTN

;<ON1>=<GOTO>|GOSUB#

A768              :ON1    SYN      CGTO
A768 +17                DB    :CGTO
A769                  SYN      :OR
A769 +02                DB    :OR
A76A                  SYN      CGS
A76A +02                DB    CGS
A76B                  SYN      :RTN
A76B +03                DB    :RTN

;<EXPL>=<EXP><EXPL1>#

A76C              :EXPL   SYN      :VEXP
A76C +0E                DB    :VEXP
A76D                  SYN      JS,:EXPL1
A76D +C2              DB      $80+(((:EXPL1-*)&$7F) XOR $40 )
A76E                  SYN      :RTN
A76E +03                DB    :RTN

;<EXPL1>=,<EXPL>|&#

A76F              :EXPL1  SYN      CCOMP
A76F +12                DB    CCOMP
A770                  SYN      JS,:EXPL
A770 +BC              DB      $80+(((:EXPL-*)&$7F) XOR $40 )
A771                  SYN      :OR
A771 +02                DB    :OR
A772                  SYN      :RTN
A772 +03                DB    :RTN

;<EOS2>=<CEOS>|CCR#

A773              :EOS2
A773                  SYN      CEOS
A773 +14                DB    CEOS
A774                  SYN      :OR
A774 +02                DB    :OR
A775                  SYN      CCR
A775 +16                DB    CCR
A776                  SYN      :RTN
A776 +03                DB    :RTN

;<NSMAT>=<TNVAR>(<EXP><NMAT2>)

A777              :NSMAT
A777                  SYN      :ESRT,AD,:TNVAR-1
A777 +14                DB    :ESRT

;-------173

A778 +29A3              DW    (:TNVAR-1)
A77A                   SYN      CLPRN,:CHNG,CDLPRN
A77A +2B                DB    CLPRN
A77B +0F                DB    :CHNG
A77C +39                DB    CDLPRN
A77D                  SYN      :VEXP
A77D +0E                DB    :VEXP
A77E                   SYN      :ANTV,AD,:NMAT2-1
A77E +00                 DB    :ANTV
A77F +58A6               DW    (:NMAT2-1)
A781                   SYN      CPRN
A781 +2B                DB    CPRN
A782                  SYN      :OR
A782 +02                DB    :OR
A783                  SYN      :ESRT,AD,:TSVAR-1
A783 +01                DB    :ESRT
A784 +2DA3              DW    (:TSVAR-1)
A786                   SYN      CLPRN,:CHNG,CDSLPR
A786 +2B                DB    CLPRN
A787 +0F                DB    :CHNG
A788 +3B                DB    CDSLPR
A789                  SYN      :VEXP
A789 +0E                DB    :VEXP
A78A                  SYN      CRPRN
A78A +2C                DB    CRPRN
A78B                  SYN      :RTN
A78B +03                DB    :RTN

;<NSML>=<NSMAT><NSML2>|&#

A78C              :NSML   SYN      JS,:NSMAT
A78C +AB              DB      $80+(((:NSMAT-*)&$7F) XOR $40 )
A78D                  SYN      JS,:NMSL2
A78D +C3              DB      $80+(((:NMSL2-*)&$7F) XOR $40 )
A78E                  SYN      :OR,:RTN
A78E +02                DB    :OR
A78F +03                DB    :RTN

;<NSML2>=,<NSML>|&#

A790              :NSML2  SYN      CCOM
A790 +12                DB    CCOM
A791                  SYN      JS,:NSML
A791 +BB              DB      $80+(((:NSML-*)&$7F) XOR $40 )
A792                  SYN      :OR,:RTN
A792 +02                DB    :OR
A793 +03                DB    :RTN

;<IF>=<EXP>THEN<IFA><EOS>#

A794              :SIF    SYN      :VEXP
A794 +0E                DB    :VEXP
A795                  SYN      CTHEN
A795 +1B                DB    CTHEN
A796                  SYN      JS,:IFA
A796 +C3              DB      $80+(((:IFA-*)&$7F) XOR $40 )
A797                  SYN      JS,:EOS2
A797 +9C              DB      $80+(((:EOS2-*)&$7F) XOR $40 )
A798                  SYN      :RTN
A798 +03                DB    :RTN

;<IFA>=<TNCON>|<EIF>

A799              :IFA    SYN      :ESRT,AD,:TNCON-1
A799 +01                DB    :ESRT
A79A +FFA3              DW    (:TNCON-1)
A79C                  SYN      :OR
A79C +02                DB    :OR
A79D                  SYN      :ESRT,AD,:EIF-1
A79D +01                DB    :ESRT
A79E +D3A2              DW    (:EIF-1)

;--------174

<PR1>=<PEL>|<PSL><PR2>|&#

A7A0              :PR1
A7A0                  SYN      JS,:PEL,:OR
A7A0 +C9              DB      $80+(((:PEL-*)&$7F) XOR $40 )
A7A1 +02                DB    :OR
A7A2                  SYN      JS,:PSL
A7A2 +D4              DB      $80+(((:PSL-*)&$7F) XOR $40 )
A7A3                  SYN      JS,:PR2
A7A3 +C3              DB      $80+(((:PR2-*)&$7F) XOR $40 )
A7A4                  SYN      :OR
A7A4 +02                DB    :OR
A7A5                  SYN      :RTN
A7A5 +03                DB    :RTN

;<PR2>=<PEL>|&#

A7A6              :PR2    SYN      JS,:PEL,:PEL
A7A6 +C3              DB      $80+(((:PEL-*)&$7F) XOR $40 )
A7A7                  SYN      :OR
A7A7 +02                DB    :OR
A7A8                  SYN      :RTN
A7A8 +03                DB    :RTN

;<PEL>=<PES><PELA>#

A7A9              :PEL    SYN      JS,:PES
A7A9 +C3              DB      $80+(((:PES-*)&$7F) XOR $40 )
A7AA                  SYN      JS,:PELA
A7AA +C8              DB      $80+(((:PELA-*)&$7F) XOR $40 )
A7AB                  SYN      :RTN
A7AB +03                DB    :RTN

;<PES>=<EXP>|<STR>

A7AC              :PES    SYN      :VEXP
A7AC +0E                DB    :VEXP
A7AD                  SYN      :OR
A7AD +02                DB    :OR
A7AE                   SYN      :ANTV,AD,:STR-1
A7AE +00                 DB    :ANTV
A7AF +81A6               DW    (:STR-1)
A7B1                  SYN      :RTN
A7B1 +03                DB    :RTN

;<PELA>=<PSL><PEL>|&#

A7B2              :PELA   SYN      JS,:PSL
A7B2 +C4              DB      $80+(((:PSL-*)&$7F) XOR $40 )
A7B3                  SYN      JS,:PR2
A7B3 +B3              DB      $80+(((:PR2-*)&$7F) XOR $40 )
A7B4                  SYN      :OR
A7B4 +02                DB    :OR
A7B5                  SYN      :RTN
A7B5 +03                DB    :RTN

;<PSL>=<PS><PSLA>#

A7B6              :PSL    SYN      JS,:PS
A7B6 +C6              DB      $80+(((:PS-*)&$7F) XOR $40 )
A7B7                  SYN      JS,:PSLA
A7B7 +C2              DB      $80+(((:PSLA-*)&$7F) XOR $40 )
A7B8                  SYN      :RTN
A7B8 +03                DB    :RTN

;<PSLA>=<PSL>|&#

A7B9              :PSLA   SYN      JS,:PSL
A7B9 +BD              DB      $80+(((:PSL-*)&$7F) XOR $40 )
A7BA                  SYN      :OR

;-------175

A7BA +02                DB    :OR
A7BB                  SYN      :RTN
A7BB +03                DB    :RTN

;<PS>=,|,#

A7BC              :PS     SYN      CCOM
A7BC +12                DB    CCOM
A7BD                  SYN      :OR
A7BD +02                DB    :OR
A7BE                  SYN      CSC
A7BE +15                DB    CSC
A7BB                  SYN      :RTN
A7BB +03                DB    :RTN

;<L1>=<EXP><L2>|&#

A7C0              :L1     SYN      :VEXP
A7C0 +0E                DB    :VEXP
A7C1                  SYN      JS,:L2
A7C1 +C3              DB      $80+(((:L2-*)&$7F) XOR $40 )
A7C2                  SYN      :OR
A7C2 +02                DB    :OR
A7C3                  SYN      :RTN
A7C3 +03                DB    :RTN

;<L2>=,<EXP>|&#

A7C4              :L2     SYN      CCOM
A7C4 +12                DB    CCOM
A7C5                  SYN      :VEXP
A7C5 +0E                DB    :VEXP
A7C6                  SYN      :OR
A7C6 +02                DB    :OR
A7C7                  SYN      :RTN
A7C7 +03                DB    :RTN

;<REM>=<EREM>

A7C8               :SREM  SYN      :ESRT,AD,:EREM-1
A7C8 +01                DB    :ESRT
A7C9 +DFA2              DW    (:EREM-1)

;<SDATA>=<EDATA>

A7CB               :SDATA SYN      :ESRT,AD,:EDATA-1
A7CB +01                DB    :ESRT
A7CC +DFA2              DW    (:EREM-1)

;<NFSP>=ASC | VAL | LEN#

A7CE              :NFSP   SYN      CASC,:OR
A7CE +40                DB    CASC
A7CF +02                DB    :OR
A7D0                  SYN      CVAL,:OR
A7D0 +41                DB    CVAL
A7D1 +02                DB     :OR
A7D2                  SYN      CADR,:OR
A7D2 +43                DB    CADR
A7D3 +02                DB    :OR
A7D4                  SYN      CLEN
A7D4 +42                DB    CLEN
A7D5                  SYN      :RTN
A7D5 +03                DB    :RTN

;--------176

;<SFNP>=STR | CHR#

A7D6              :SFNP   SYN      CSTR,:OR
A7D6 +3D                DB    CSTR
A7D7 +02                DB    :OR
A7D8                  SYN      CCHAR
A7D8 +3E                DB    CCHAR
A7D9                  SYN      :RTN
A7D9 +03                DB    :RTN

;<PUSR>=<EXP><PUSR1>#

A7DA              :PUSR   SYN      :VEXP
A7DA +0E                DB    :VEXP
A7DB                  SYN      JS,:PUSR1
A7DB +C2              DB      $80+(((:PUSR1-*)&$7F) XOR $40 )
A7DC                  SYN      :RTN
A7DC +03                DB    :RTN

;<PUSR1>=,<PUSR>|&#

A7DD              :PUSR1  SYN      CCOM,:CHNG,CACOM
A7DD +12                DB    CCOM
A7DE +0F                DB    :CHNG
A7DF +3C                DB    CACOM
A7E0                  SYN      JS,:PUSR
A7E0 +BA              DB      $80+(((:PUSR-*)&$7F) XOR $40 )
A7E1                  SYN      :OR
A7E1 +02                DB    :OR
A7E2                  SYN      :RTN
A7E2 +03                DB    :RTN

;                OPNTAB - Operator Name Table

A7E3              OPNTAB
      = 000F      C       SET     $0F          ;FIRST ENTRY VALUE=$10
                  ;
      = 0010      C       SET     C+1
      = 0010      CDQ     EQU     C
A7E3  82              $82                      ;DOUBLE QUOTE
                  ;
      = 0011      C       SET     C+1
      = 0011      CSOE    EQU     C
A7E4  82              DB      $80              ;DUMMY FOR SOE
                  ;
      = 0012      C       SET     C+1
      = 0012      CCOM    EQU     C
A7E5  AC              DC    ','
                  ;
      = 0013      C       SET     C+1
      = 0013      CDOL    EQU     C
A7E6  A4              DC    '$'
                  ;
      = 0014      C       SET     C+1
      = 0014      CEOS    EQU     C
A7E7  BA              DC    ':'
                  ;
      = 0015      C       SET     C+1
      = 0015      CSC     EQU     C
A7E8  BB              DC    ';'
                  ;
      = 0016      C       SET     C+1
      = 0016      CCR     EQU     C              ;CARRIAGE RETURN
A7E9  9B              DB      CR
                  ;
      = 0017      C       SET     C+1
      = 0017      CGTO    EQU     C
A7EA  474F54CF        DC    'GOTO'
                  ;

;---------177

      = 0018      C       SET     C+1
      = 0018      CGS     EQU     C
A7EE  474F5355C2      DC    'GOSUB'
                  ;
      = 0019      C       SET     C+1
      = 0019      CTO     EQU     C
A7F3  54CF            DC    'TO'
                  ;
      = 001A      C       SET     C+1
      = 001A      CSTEP   EQU     C
A7F5  535445D0        DC    'STEP'
                  ;
      = 001B      C       SET     C+1
      = 001B      CTHEN   EQU     C
A7F9  544845CE        DC    'THEN'
                  ;
      = 001C      C       SET     C+1
      = 001C      CPND    EQU     C
A7FD  A3              DC    '#'
                  ;
      = 001D      CSROP   EQU     C+1
                  ;
      = 001D      C       SET     C+1
      = 001D      CLE     EQU     C
A7FE  3CBD            DC    '<='
                  ;
      = 001E      C       SET     C+1
      = 001E      CNE     EQU     C
A800  3CBE            DC    '<>'
                  ;
      = 001F      C       SET     C+1
      = 001F      CGE     EQU     C
A802  3EBD            DC    '>='
                  ;
      = 0020      C       SET     C+1
      = 0020      CLT     EQU     C
A804  BC              DC    '<'
                  ;
      = 0021      C       SET     C+1
      = 0021      CGT     EQU     C
A805  BE              DC    '>'
                  ;
      = 0022      C       SET     C+1
      = 0022      CEQ     EQU     C
A806  BD              DC    '='
                  ;
      = 0023      C       SET     C+1
      = 0023      CEXP    EQU     C
A807  DE              DB      $5E+$80            ;UP ARROW FOR EXP
                  ;
      = 0024      C       SET     C+1
      = 0024      CMUL    EQU     C
A808  AA              DC                '*'
                  ;
      = 0025      C       SET     C+1
      = 0025      CPLUS   EQU     C
A809  AB              DC    '+'
                  ;
      = 0026      C       SET     C+1
      = 0026      CMINUS  EQU     C
A80A  AD              DC    '-'
                  ;
      = 0027      C       SET     C+1
      = 0027      CDIV    EQU     C
A80B  AF              DC    '/'
                  ;
      = 0028      C       SET     C+1
      = 0028      CNOT    EQU     C
A80C  4E4FD4          DC    'NOT'
                  ;

;----------178

      = 0029      C       SET     C+1
      = 0029      COR     EQU     C
A80F  4FD2            DC    'OR'
                  ;
      = 002A      C       SET     C+1
      = 002A      CAND    EQU     C
A811  414EC4          DC    'AND'
                  ;
      = 002B      C       SET     C+1
      = 002B      CLPRN   EQU     C
A814  A8              DC    '('
                  ;
      = 002C      C       SET     C+1
      = 002C      CRPRN   EQU     C
A815  A9              DC    ')'
                  ;
                  ; THE FOLLOWING ENTRIES ARE COMRISED OF CHARACTERS
                  ; SIMILAR TO SOME OF THOSE ABOVE BUT HAVE
                  ; DIFFERENT SYNTACTICAL OR SEMANTIC MEANING
                  ;
      = 002D      C       SET     C+1
      = 002D      CAASN   EQU     C              ; ARITHMETIC ASSIGMENT
A816  BD              DC    '='
                  ;
      = 002E      C       SET     C+1
      = 002E      CSASN   EQU     C              ; STRING OPS
A817  BD              DC    '='
                  ;
      = 002F      C       SET     C+1
      = 002F      CSLE    EQU     C
A818  3CBD            DC    '<='
                  ;
      = 0030      C       SET     C+1
      = 0030      CSNE    EQU     C
A81A  3CBE            DC    '<>'
                  ;
      = 0031      C       SET     C+1
      = 0031      CSGE    EQU     C
A81C  3EBD            DC    '>='
                  ;
      = 0031      C       SET     C+1
      = 0031      CSLT    EQU     C
A81E  BC              DC    '<'
                  ;
      = 0033      C       SET     C+1
      = 0033      CSGT    EQU     C
A81F  BE              DC    '>'
                  ;
      = 0034      C       SET     C+1
      = 0034      CSEQ    EQU     C
A820  BD              DC    '='
                  ;
      = 0035      C       SET     C+1
      = 0035      CUPLUS  EQU     C              ;UNARY PLUS
A821  AB              DC    '+'
                  ;
      = 0036      C       SET     C+1
      = 0036      CUMINUS EQU     C              ; UNARY MINUS
A822  AD              DC    '-'
                  ;
      = 0037      C       SET     C+1
      = 0037      CSLPRN  EQU     C              ;STRING LEFT PAREN
A823  A8              DC    '('
                  ;
      = 0038      C       SET     C+1
      = 0038      CALPRN  EQU     C              ; ARRAY LEFT PAREN
A824  80              DC    $80                  ; DOES NOT PRINT
                  ;
      = 0039      C       SET     C+1
      = 0039      CDLPRN  EQU     C              ; DIM LEFT PAREN

;----------179

A825  80              DC    $80                  ; DOES NOT PRINT
                  ;
      = 003A      C       SET     C+1
      = 003A      CFLPRN  EQU     C              ; FUNCTION LEFT PAREN
A826  A8              DC    '('
                  ;
      = 003B      C       SET     C+1
      = 003B      CDSLPR  EQU     C
A827  A8              DC    '('
                  ;
      = 003C      C       SET     C+1
      = 003C      CACOM   EQU     C              ; ARRAY COMMA
A828  AC              DC    ','

;Function Name Table

                  ;       PART OF ONTAB
                  ;
                  ;
A829              FNTAB
                  ;
      = 003D      C       SET     C+1
      = 003D      CFFUN   EQU     C              ; FIRST FUNCTION CODE
      = 003D      CSTR    EQU     C
A829  53542AA4        DC    'STR$'
      = 003E      C       SET     C+1
      = 003E      CCHR    EQU     C
A82D  BC              DC    'CHR$'
      = 003F      C       SET     C+1
      = 003F      CUSR    EQU     C              ; USR FUNCTION CODE
A831  5553D2          DC    'USR'
      = 0040      C       SET     C+1
      = 0040      CASC    EQU     C
A834  4153C3          DC    'ASC'
      = 0041      C       SET     C+1
      = 0041      CVAL    EQU     C
A837  5641CC          DC    'VAL'
      = 0042      C       SET     C+1
      = 0042      CLEN    EQU     C
A83A  BC              DC    'LEN'
      = 0043      C       SET     C+1
      = 0043      CADR    EQU     C
A83D  4144D2          DC    'ADR'
      = 0044      C       SET     C+1
      = 0044      CNFPN   EQU     C
A840  4154CE          DC    'ATN'
A843  434FD3          DC    'COS'
A846  504545CB        DC    'PEEK'
A84A  5349CE          DC    'SIN'
A84D  524EC4          DC    'RND'
A850  4652C5          DC    'FRE'
A853  4558D0          DC    'EXP'
A856  4C4FC7          DC    'LOG'
A859  434C4FC7        DC    'CLOG'
A85D  5351D2          DC    'SQR'
A860  5347CE          DC    'SGN'
A863  4142D3          DC    'ABS'
A866  494ED4          DC    'INT'
A869  504144444C      DC    'PADDLE'
      C5
A86F  53544943CB      DC    'STICK'
A874  50545249C7      DC    'PTRIG'
A879  53545249C7      DC    'STRIG'
                  ;
A87E  00              DB    $00
                  ;
                  ; END OF OPTAB & FNTAB
;----------180

;                           Memory manager

A87F                  LOCAL
                 ;
                 ;       MEMORY MANAGEMENT CONSISTS OF EXPANDING AND
                 ;       CONTRACTING TO INFORMATION AREA POINTED TO
                 ;       BY THE ZERO PAGE POINTER TABLES.  ROUTINES
                 ;       MODIFY THE ADDRESS IN THE TABLES AND
                 ;       MOVE DATA AS REQUIRED.  THE TWO FUNDAMENTAL
                 ;       ROUTINES ARE 'EXPAND' AND 'CONTRACT'

;EXPAND

                 ;               X = ZERO PAGE ADDRESS OF TABLE AT WHICH
                 ;               EXPANSION IS TO START
                 ;               Y = EXPANSION SIZE IN BYTES [LOW]
                 ;               A = EXPANSION SIZE IN BYTES [HIGH]
                 ;
                 ; EXPLOW - FOR EXPANSION < 256 BYTES
                 ;                SETS A = 0
                 ;
A87F  A900       EXPLOW  LDA      #0
                 ;
A881             EXPAND
A881  84A4           STY     ECSIZE         ; SAVE EXPAND SIZE
A883  85A5           STA     ECSIZE+1
                 ;
A885  38             SEC
A886  A590           LDA     MEMTOP         ; TEST MEMORY TO BE FULL
A888  65A4           ADC     ECSIZE
A88A  A8             TAY                    ; MEMTOP+ECSIZE+1
A88B  A591           LDA     MEMTOP+1
A88D  65A5           ADC     ECSIZE+1       ; MUST BE LE
A88F  CDE602         CMP     HIMEM+1
A892  900C ^A8A0     BCC     :EXP2          ; HIMEM
A894  D007 ^A89D     BNE     :EXP1
A896  CCE502         CPY     HIMEM
A899  9005 ^A8A0     BCC     :EXP2
A89B  F003 ^A8A0     BEQ     :EXP2
A89D  4C3CB9     :EXP1   JMP     MEMFULL
                 ;
A8A0             :EXP2
A8A0  38             SEC                    ; FORM MOVE LENGTH [MVLNG]
A8A1  A590           LDA     MEMTOP         ; MOVE FROM ADR [MVFA]
A8A3  F500           SBC     0,X            ; MVLNG = MEMTOP-EXPAND ADR
A8A5  85A2           STA     MVLNG
A8A7  A591           LDA     MEMTOP+1       ; MVFA[L] = EXP ADR [L]
A8A9  F501           SBC     1,X
A8AB  85A3           STA     MVLNG+1        ; MVFA[H] = EXP ADR [H] +
                                              MVLNG[H]
A8AD  18             CLC                    ; DURING MOVE MVLNG[L]
A8AE  7501           ADC     1,X            ; WILL BE ADDED SUCH
A8B0  859A           STA     MVFA+1         ; THAT MVFA = MEMTOP
                 ;
A8B2  B500           LDA     0,X            ; SAVE PREMOVE EXPAND AT VALUE
A8B4  8599           STA     MVFA           ; SET MVFA LOW
A8B6  8597           STA     SVESA          ; FORM MOVE TO ADR [MVTA]
A8B8  65A4           ADC     ECSIZE         ; MVTA[L] = EXP ADR[L] +
                                              ECSIZE[L]
A8BA  859B           STA     MVTA           ; MVTA[H] = [CARRY + EXP
                                              AD-[H]
A8BC  B501           LDA     1,X            ;  +ECSIZE[H]] + MVLNG[H]
A8BE  8598           STA     SVESA+1
A8C0  65A5           ADC     ECSIZE+1       ; DURING MOVE MVLNG[L]
A8C2  65A3           ADC     MVLNG+1        ; WILL BE ADDED SUCH THAT
A8C4  859C           STA     MVTA+1         ; MVTA = MEMTOP + ECSIZE
                 ;
A8C6             :EXP3

;----------181

A8C6  B500           LDA     0,X            ; ADD ECSIZE TO
A8C8  65A4           ADC     ECSIZE         ; ALL TABLE ENTRIES
A8CA  9500           STA     0,X            ; FROM EXPAND AT ADR
A8CC  B501           LDA     1,X            ; TO HIMEM
A8CE  65A5           ADC     ECSIZE+1A8D0  9501           STA     1,X
A8D2  E8             INX
A8D3  E8             INX
A8D4  E092           CPX     *MEMTOP+2
A8D6  90EE ^A8C6     BCC     :EXP3
A8D8  850F           STA     APHM+1         ; SET NEW APL
A8DA  A590           LDA     MEMTOP         ; HI MEM TO
A8DC  850E           STA     APHM           ; MEMTOP
                 ;
A8DE  A6A3           LDX     MVLNG+1        ; X = MVLNG[H]
A8E0  E8             INX                    ; PLUS ONE
A8El  A4A2           LDY     MVLNG          ; Y = MVLNG[L]
A8E3  D00B ^ABF0     BNE     :EXP6          ; TEST ZERO LENGTH
A8E5  F0l0 ^A8F7     BEQ     :EXP7          ; BR IF LOW = 0
                 ;
A8E7  88         :EXP4   DEY                ; DEC MVLNG[L]
A8E8  C69A           DEC     MVFA+1         ; DEC MVFA[H]
A8EA  C69C           DEC     MVTA+1         ; DEC MVTA[H]
                 ;
A8EC  B199       :EXP5   LDA     [MVFA],Y   ; MVFA BYTE
A8EE  919B           STA     [MVTA],Y       ; TO MVTA
A8F0  88         :EXP6   DEY                ; DEC COUNT LOW
A8F1  D0F9 ^A8EC     BNE     :EXP5          ; BR IF NOT ZERO
                 ;
A8F3  B199           LDA     [MVFA],Y       ; MOVE THE ZERO BYTE
A8F5  919B           STA     [MVTA],Y

A8F7             :EXP7
A8F7  CA             DEX                    ; IF MVLNG[H] IS NOT
A8F8  D0ED ^A8E7     BNE     :EXP4          ; ZERO THEN MOVE 256 MORE
                 ;                                ELSE
A8FA  60             RTS                    ; DONE


;CONTRACT
                 ;               X = ZERO PAGE ADR OF TABLE AT WHICH
                 ;                   CONTRACTION WILL START
                 ;               Y = CONTRACT SIZE IN BYTES [LOW]
                 ;               A = CONTRACT SIZE IN BYTES [HI]
                 ;       CONTLOW
                 ;               SETS A = 0
                 ;
A8FB  A900       CONTLOW LDA     #0
                 ;
A8FD             CONTRACT
A8FD  84A4          STY      ECSIZE         ; SAVE CONTRACT SIZE
A8FF  85A5          STA      ECSIZE+1
                 ;
A901  38            SEC                     ; FORM MOVE LENGTH [LOW]
A902  A590          LDA      MEMTOP
A904  F500          SBC      0,X            ; MVLNG[L] = $100-
A906  49FF          EOR      #$FF           ; [MEMTOP[L]] -  CON AT
                                              VALUE [L]
A908  A8            TAY                     ; THIS MAKES START Y AT
A909  C8            INY                     ; MOVE HAVE A 2'S COMPLEMENT
A90A  84A2          STY      MVLNG          ; REMAINDER IN IT
                 ;
A90C  A591          LDA      MEMTOP+1       ; FORM MOVE LENGTH[HIGH]
A90E  F501          SBC      1,X
A910  85A3          STA      MVLNG+1
                 ;
A912  B500          LDA      0,X            ; FORM MOVE FROM ADR [MVFA]
A9l4  E5A2          SBC      MVLNG          ; MVFA = CON AT VALUE
A916  8599          STA      MVFA           ; MINUS MVLNG[L]
A918  B501          LDA      1,X            ; DURING MOVE MVLNG[L]


;---------182

A9lA  E900          SBC      #0             ; WILL BE ADDED BACK INTO
A9lC  859A          STA      MVFA+1         ; MVFA IN [IND],Y INST
                 ;
A91E  869B          STX      MVTA           ; TEMP SAVE OF CON AT DISPL
A920  38         :CONT1 SEC      ;SUBTRACT ECSIZE FROM
A921  B500          LDA      0,X            ; ALL TABLE ENTRY FROM
A923  E5A4          SBC      ECSIZE         ; CON AT ADR TO HIMEM
A925  9500          STA      0,X
A927  B501          LDA      1,X
A929  E5A5          SBC      ECSIZE+1
A92B  9501          STA      1,X
A92D  E8            INX
A92E  E8            INX
A92F  E092          CPX      #MEMTOP+2
A931  90ED  ^A920   BCC      :CONT1
A933  850F          STA      APHM+1         ; SET NEW APL
A935  A590          LDA      MEMTOP         ; HI MEM TO
A937  850E          STA      APHM           ; MEMTOP
                 ;
A939  A69B          LDX      MVTA
                 ;
A93B  B500          LDA      0,X            ; FORM MOVE TO ADR [MVTA]
A93D  E5A2          SBC      MVLNG          ; MVTA = NEW CON AT VALUE
A93F  859B          STA      MVTA           ; MINUS MVLNG [L]
A941  B501          LDA      1,X            ; DURING MOVE MVLNG[L]
A943  E900          SBC      #0             ; WILL BE ADDED BACK INTO
A945  859C          STA      MVTA+1         ; MVTA IN [INO],Y INST
                 ;
A947             FMOVER
A947  A6A3          LDX      MVLNG+1        ; GET MOVE LENGTH HIGH
A949  E8            INX                     ; INC SO MOVE CAN BNE
A94A  A4A2          LDY      MVLNG          ; GET MOVE LENGTH LOW
A94C  D006  ^A954   BNE      :CONT2         ; IF NOT ZERO GO
A94E  F00B  ^A95B   BEQ      :CONT4         ; BR IF LOW = 0
                 ;
A950  E69A       :CONT3  INC     MVFA+1     ;INC MVFA[H]
A952  E69C          INC      MVTA+1         ; INC MVTA[H]
                 ;
A954  B199       :CONT2  LDA     [MVFA],Y   ; GET MOVE FROM BYTE
A956  919B          STA      [MVTA],Y       ; SET MOVE TO BYTE
A958  C8            INY                     ; INCREMENT COUNT LOW
A959  D0F9  ^A954   BNE      :CONT2         ; BR IF NOT ZERO
                 ;
A95B             :CONT4
A95B  CA            DEX                     ; DECREMENT COUNT HIGH
A95C  D0F2  ^A950   BNE      :CONT3         ; BR IF NOT ZERO
A95E  68            RTS                     ; ELSE DONE


                            Execute Control
A95F                LOCAL

;EXECNL - Execute Next Line
                 ;  START PROGRAM EXECUTOR
                 ;
A95F             EXECNL
A95F  201BB8        JSR      SETLN1         ; SET UP LIN & NXT STMT


;EXECNS - Execute Next Statement

A962      EXECNS
A962  20F4A9        JSR      TSTBRK         ; TEST BREAK
A965  D035  ^A99C   BNE      :EXBRK         ; BR IF BREAK
A967  A4A7          LDY      NXTSTD         ;GET PTR TO NEXT STMT L
A969  C49F          CPY      LLNGTH         ;AT END OF LINE
A96B  B01C  ^A989   BCS      :EXEOL         ; BR IF EOL
                 ;

;---------183

A96D  B18A          LDA      [STMCUR],Y     ;GET NEW STMT LENGTH
A96F  85A7          STA      NXTSTD         ;SAVE AS FURURE STMT LENGTH
A971  98            TYA                     ;Y=DISPL TO THIS STMT LENGTH
A972  C8            INY                     ;PLUS 1 IS DISPL TO CODE
A973  B18A          LDA      [STMCUR],Y     ;GET CODE
A975  C8            INY                     ;INC TO STMT MEAT
A976  84A8          STY      STINDEX        ;SET WORK INDEX
                ;
A978  207EA9        JSR      :STGO          ;GO EXECUTE
A97B  4C62A9        JMP      EXECNS         ;THEN DO NEXT STMT
                ;
A97E            :STGO   ASLA                ;TOKEN*2
A97E +0A            ASL      A
A97F  AA            TAX
A980  BD00AA        LDA      STETAB,X       ; GET ADR AND
A983  48            PHA                     ;PUSH TO STACK
A984  BD01AA        LDA      STETAB+1,X     ; AND GO TO
A987  48            PHA                     ;VIA
A988  60            RTS                     ;RTS
                ;
A989            :EXEOL
A989  A001          LDY      #1
A98B  B18A          LDA      [STMCUR],Y
A98D  3010 ^A99F    BMI      :EXFD          ; BR IF DIR
                ;
A98F  A59F          LDA      LLNGTH         ;GET LINE LENGTH
A991  20D0A9        JSR      GNXTL          ;INC STMCUR
A994  20E2A9        JSR      TENDST         ;TST END STMT TABLE
A997  10C6 ^A95F    BPL      EXECNL         ;BR NOT END
                ;
A999 4C8DB7     :EXDONE JMP      XEND       ; GO BACK TO SYNTAX
A99C  4C93B7    :EXBRK  JMP      XSTOP      ; BREAK, DO STOP
A99F  4C5DA0    :EXFD   JMP      SNX3       ; GO TO SYNTAX VIA READY MSG

;GETSTMT-Get Statement in statement Table

                ;       SEARCH FOR STATEMENT THAT HAS TSLNUM
                ;       SET STMCUR TO POINT TO IT IF FOUND
                ;       OR TO WHERE IT WOULD GO IF NOT FOUND
                ;       CARRY SET IF NOT FOUND
A9A2            GETSTMT
                ;
                ;       SAVE CURRENT LINE ADDR
                ;
A9A2  A58A          LDA      STMCUR
A9A4  85BE          STA      SAVCUR
A9A6  A58B          LDA      STMCUR+1
A9A8  85BF          STA      SAVCUR+1
A9AA  A589          LDA      STMTAB+1       ;START AT TOP OF TABLE
A9AC  A488          LDY      STMTAB
                ;
A9AE  858B          STA      STMCUR+1       ;SET STMCUR
A9B0  848A          STY      STMCUR
                ;
                ;
A9B2  A001      :GS2    LDY      #1
A9B4  B18A          LDA      [STMCUR],Y     ;GET STMT LNO [HI]
A9B6  C5A1          CMP      TSLNUM+1       ;TEST WITH TSLNUM
A9B8  900D ^A9C7    BCC      :GS3           ;BR IF S<TS
A9BA  D00A ^A9C6    BNE      :GSRT1         ;BR IF S>TS
A9BC  88            DEY      :GS3           ;S=TS, TST LOW BYTE ???
A9BD  B18A          LDA      [STMCUR],Y
A9BF  C5A0          CMP      TSLNUM
A9C1  9004 ^A9C7    BCC      :GS3           ;BR S<TS
A9C3  D001 ^A9C6    BNE      :GSRT1         ;BR S>TS
A9C5  18            CLC                     ;S=TS, CLEAR CARRY
A9C6            :GSRT1
A9C6  60            RTS                     ;AND RETURN [FOUND]
                ;
A9C7  20DDA9    :GS3    JSR      GETLL      ;GO GET THIS GUYS LENGTH

;---------184

A9CA  20D0A9        JSR      GETNXTL
A9CD  4CB2A9        JMP      :GS2
                ;
A9D0            GNXTL
A9D0  18            CLC
A9D1  658A          ADC      STMCUR         ;ADD LENGTH TO STMCUR
A9D3  858A          STA      STMCUR
A9D5  A8            TAY
A9D6  A58B          LDA      STMCUR+1
A9D8  6900          ADC      #0
A9DA  858B          STA      STMCUR+1
A9DC  60            RTS
A9DD  A002      GETLL   LDY      #2
A9DF  B18A          LDA     [STMCUR],Y
A9E1  60            RTS

;TENDST-Test End of Statement Table

A9E2            TENDST
A9E2  A001          LDY     #1              ; INDEX TO CNO ['I]
A9E4  B18A          LDA     [STMCUR],Y      ; GET CNO [HI]
A9E6  60            RTS
A9E7            XREM
A9E7            XDATA
A9E7  60        TESTRTS RTS

;XBYE-Execute BYE

A9E8            XBYE
A9E8  2041BD        JSR     CLSALL          ; CLOSE 1-7
A9EB  4C71E4        JMP     BYELOC          ; EXIT

;XDOS-Execute DOS

A9EE            XDOS
A9EE  2041BD        JSR     CLSALL          ; CLOSE 1-7
A9F1  6C0A00        JMP     [DOSLOC]        ; GO TO DOS

;TSTBRK-Test for Break

A9F4            TSTBRK
A9F4  A000          LDY     #0
                ;
A9F6  A511          LDA     BRKBYT          ; LOAD BREAK BYTE
A9F8  D004 ^A9FE    BNE     :TB2
A9FA  A0FF          LDY     #$FF
A9FC  8411          STY     BRKBYT
A9FE  98        :TB2    TYA                 ; SET COND CODE
A9FF  60            RTS                     ; DONE

;                    Statement Execution Table

                ;STETAB-STATEMENT EXECUTION TABLE
                ;       -CONTAINS STMT EXECUTION ADR
                ;       -MUST BE IN SAME ORDER AS SNTAB
                ;
AA00            STETAB
AA00                FDB     XREM-1
AA00 +A9E6          DW      REV (XREM-1)
AA02                FDB     XDATA-1
AA02 +A9E6          DW      REV (XDATA-1)
      = 0001    CDATA   EQU     (*-STETAB)/2-1
AA04                FDB     XINPUT-1
AA04 +B315          DW      REV (XINPUT-1)
AA06                FDB     XCOLOR-1
AA06 +BA28          DW      REV (XCOLOR-1)
AA08                FDB     XLIST-1
AA08 +B482          DW      REV (XLIST-1)
      = 0004    CLIST   EQU     (*-STETAB)/2-1

;----------185

AA0A                FDB     XENTER-1
AA0A +BACA          DW      REV (XENTER-1)
AA0C                FDB     XLET-1
AA0C +AADF          DW      REV (XLET-1)
AA0E                FDB     XIF-1
AA0E +B777          DW      REV (XIF-1)
AA10                FDB     XFOR-1
AA10 +B64A          DW      REV (XFOR-1)
      = 0008    CFOR   EQU      (*-STETAB)/2-1
AA12                FDB     XNEXT-1
AA12 +B6CE          DW      REV (XNEXT-1)
AA14                FDB     XGOTO-1
AA14 +B6A2          DW      REV (XGOTO-1)
AA16                FDB     XGOTO-1
AA16 +B6A2          DW      REV (XGOTO-1)
AA18                FDB     XGOSUB-1
AA18 +B69F          DW      REV (XGOSUB-1)
      = 000C    CGOSUB  EQU     (*-STETEAB)/2-1
AA1A                FDB     XTRAP-1
AA1A +B7E0          DW      REV (XTRAP-1)
AA1C                FDB     XBYE-1
AA1C +A9E7          DW      REV (XBYE-1)
AA1E                FDB     XCONT-1
AA1E +B7BD          DW      REV (XCONT-1)
AA20                FDB     XCOM-1
AA20 +B1D8          DW      REV (XCOM-1)
AA22                FDB     XCLOSE-1
AA22 +BC1A          DW      REV (XCLOSE-1)
AA24                FDB     XCLR-1
AA24 +B765          DW      REV (XCLR-1)
AA26                FDB     XDEG-1
AA26 +B260          DW      REV (XDEG-1)
AA28                FDB     XDIM-1
AA28 +B1D8          DW      REV (XDIM-1)
AA2A                FDB     XEND-1
AA2A +B78C          DW      REV (XEND-1)
AA2C                FDB     XNEW-1
AA2C +A00B          DW      REV (XNEW-1)
AA2E                FDB     XOPEN-1
AA2E +BBEA          DW      REV (XOPEN-1)
AA30                FDB     XLOAD-1
AA30 +BAFA          DW      REV (XLOAD-1)
AA32                FDB     XSAVE-1
AA32 +BB5C          DW      REV (XSAVE-1)
AA34                FDB     XSTATUS-1
AA34 +BC27          DW      REV (XSTATUS-1)
AA36                FDB     XNOTE-1
AA36 +BC35          DW      REV (XNOTE-1)
AA38                FDB     XPOINT-1
AA38 +BC4C          DW      REV (XPOINT-1)
AA3A                FDB     XXIO-1
AA3A +BBE4          DW      REV (XXIO-1)
AA3C                FDB     XON-1
AA3C +B7EC          DW      REV (XON-1)
      = 001E    CON     EQU     (*-STETAB)/2-1
AA3E                FDB     XPOKE-1
AA3E +B24B          DW      REV (XPOKE-1)
AA40                FDB     XPRINT-1
AA40 +B3B5          DW      REV (XPRINT-1)
AA42                FDB     XRAD-1
AA42 +B265          DW      REV (XRAD-1)
AA44                FDB     XREAD-1
AA44 +B282          DW      REV (XREAD-1)
      = 0022    CREAD   EQU     (*-STETAB)/2-1
AA46                FDB     XREST-1
AA46 +B26A          DW      REV (XREST-1)
AA48                FDB     XRTN-1
AA48 +B718          DW      REV (XRTN-1)
AA4A                FDB     XRUN-1
AA4A +B74C          DW      REV (XRUN-1)
AA4C                FDB     XSTOP-1

;----------186

AA4C +B792          DW      REV (XSTOP-1)
AA4E                FDB     XPOP-1
AA4E +B840          DW      REV (XPOP-1)
AA50                FDB     XPRINT-1
AA50 +B3B5          DW      REV (XPRINT-1)
AA52                FDB     XGET-1
AA52 +BC7E          DW      REV (XGET-1)
AA54                FDB     XPUT-1
AA54 +BC71          DW      REV (XPUT-1)
AA56                FDB     XGR-1
AA56 +BA4F          DW      REV (XGR-1)
AA58                FDB     XPLOT-1
AA58 +BA75          DW      REV (XPLOT-1)
AA5A                FDB     XPOS-1
AA5A +BA15          DW      REV (XPOS-1)
AA5C                FDB     XDOS-1
AA5C +A9ED          DW      REV (XDOS-1)
AA5E                FDB     XDRAWTO-1
AA5E +BA30          DW      REV (XDRAWTO-1)
AA60                FDB     XSETCOLOR-1
AA60 +B9B6          DW      REV (XSETCOLOR-1)
AA62                FDB     XLOCATE-1
AA62 +BC94          DW      REV (XLOCATE-1)
AA64                FDB     XSOUND-1
AA64 +B9DC          DW      REV (XSOUND-1)
AA66                FDB     XLPRINT-1
AA66 +B463          DW      REV (XLPRINT-1)
AA68                FDB     XCSAVE-1
AA68 +BBA3          DW      REV (XCSAVE-1)
AA6A                FDB     XCLOAD-1
AA6A +BBAB          DW      REV (XCLOAD-1)
AA6C                FDB     XLET-1
AA6C +AADF          DW      REV (XLET-1)
      = 0036    CILET   EQU     (*-STETAB)/2-1
AA6E                FDB     XERR-1
AA6E +B91D          DW      REV (XERR-1)
      = 0037    CERR    EQU     (*-STETAB)/2-1


;                     Operator Execution Table

                ;       OPETAB - OPERATOR EXECUTION TABLE
                ;       - CONTAINS OPERATOR EXECUTION ADR
                ;       - MUST BE IN SAME ORDER AS OPNTAB
AA70            OPETAB
AA70                FDB     XPLE-1
AA70 +ACB4          DW      REV (XPLE-1)
AA72                FDB     XPNE-1
AA72 +ACBD          DW      REV (XPNE-1)
AA74                FDB     XPGE-1
AA74 +ACD4          DW      REV (XPGE-1)
AA76                FDB     XPLT-1
AA76 +ACC4          DW      REV (XPLT-1)
AA78                FDB     XPGT-1
AA78 +ACCB          DW      REV (XPGT-1)
AA7A                FDB     XPEQ-1
AA7A +ACDB          DW      REV (XPEQ-1)
AA7C                FDB     XPPOWER-1
AA7C +B164          DW      REV (XPPOWER-1)
AA7E                FDB     XPMUL-1
AA7E +AC95          DW      REV (XPMUL-1)
AA80                FDB     XPPLUS-1
AA80 +AC83          DW      REV (XPPLUS-1)
AA82                FDB     XPMINUS-1
AA82 +AC8C          DW      REV (XPMINUS-1)
AA84                FDB     XPDIV-1
AA84 +AC9E          DW      REV (XPDIV-1)
AA86                FDB     XPNOT-1
AA86 +ACF8          DW      REV (XPNOT-1)
AA88                FDB     XPOR-1
AA88 +ACED          DW      REV (XPOR-1)

;----------187

AA8A                FDB     XPAND-1
AA8A +ACE2          DW      REV (XPAND-1)
AA8C                FDB     XPLPRN-1
AA8C +AB1E          DW      REV (XPLPRN-1)
AA8E                FDB     XPRPRN-1
AA8E +AD7A          DW      REV (XPRPRN-1)
AA90                FDB     XPAASN-1
AA90 +AD5E          DW      REV (XPAASN-1)
AA92                FDB     XSAASN-1
AA92 +AEA2          DW      REV (XSAASN-1)
AA94                FDB     XPSLE-1
AA94 +ACB4          DW      REV (XPLSE-1)
AA96                FDB     XPSNE-1
AA96 +ACBD          DW      REV (XPSNE-1)
AA98                FDB     XPSGE-1
AA98 +ACD4          DW      REV (XPSGE-1)
AA9A                FDB     XPSLT-1
AA9A +ACC4          DW      REV (XPSLT-1)
AA9C                FDB     XPSGT-1
AA9C +ACCB          DW      REV (XPSGT-1)
AA9E                FDB     XPEQ-1
AA9E +ACDB          DW      REV (XPEQ-1)
AAA0                FDB     XPUPLUS-1
AAA0 +ACB3          DW      REV (XPUPLUS-1)
AAA2                FDB     XPUMINUS-1
AAA2 +ACA7          DW      REV (XPUMINUS-1)
AAA4                FDB     XPSLPRN-1
AAA4 +AE25          DW      REV (XPSLPRN-1)
AAA6                FDB     XPALPRN-1
AAA6 +AD85          DW      REV (XPALPRN-1)
AAA8                FDB     XPDLPRN-1
AAA8 +AD81          DW      REV (XPDLPRN-1)
AAAA                FDB     XPFLPRN-1
AAAA +AD7A          DW      REV (XPFLPRN-1)
AAAC                FDB     XDPSLP-1
AAAC +AD81          DW      REV (XSPSLP-1)
AAAE                FDB     XPACOM-1
AAAE +AD78          DW      REV (XPACOM-1)
                ;
AAB0                FDB     XPSTR-1
AAB0 +B048          DW      REV (XPSTR-1)
AAB2                FDB     XPCHR-1
AAB2 +B066          DW      REV (XPCHR-1)
AAB4                FDB     XPUSR-1
AAB4 +B0B9          DW      REV (XPUSR-1)
AAB6                FDB     XPASC-1
AAB6 +B011          DW      REV (XPASC-1)
AAB8                FDB     XPVAL-1
AAB8 +AFFF          DW      REV (XPVAL-1)
AABA                FDB     XPLEN-1
AABA +AFC9          DW      REV (XPLEN-1)
AABC                FDB     XPADR-1
AABC +B01B          DW      REV (XPADR-1)
AABE                FDB     XPATN-1
AABE +B12E          DW      REV (XPATN-1)
AAC0                FDB     XPCOS-1
AAC0 +B124          DW      REV (XPCOS-1)
AAC2                FDB     XPPEEK-1
AAC2 +AFE0          DW      REV (XPPEEK-1)
AAC4                FDB     XPSIN-1
AAC4 +B11A          DW      REV (XPSIN-1)
AAC6                FDB     XPRND-1
AAC6 +B08A          DW      REV (XPRND-1)
AAC8                FDB     XPFRE-1
AAC8 +AFEA          DW      REV (XPFRE-1)
AACA                FDB     XPEXP-1
AACA +B14C          DW      REV (XPEXP-1)
AACC                FDB     XPLOG-1
AACC +B138          DW      REV (XPLOG-1)
AACE                FDB     XPL10-1
AACE +B142          DW      REV (XPL10-1)

;----------188

AAD0                FDB     XPSQR-1
AAD0 +B156          DW      REV (XPSQR-1)
AAD2                FDB     XPSGN-1
AAD2 +AD18          DW      REV (XPSGN-1)
AAD4                FDB     XPABS-1
AAD4 +B0AD          DW      REV (XPABS-1)
AAD6                FDB     XPINT-1
AAD6 +B0DC          DW      REV (XPINT-1)
AAD8                FDB     XPPDL-1
AAD8 +B021          DW      REV (XPPDL-1)
AADA                FDB     XPSTICK-1
AADA +B025          DW      REV (XPSTICK-1)
AADC                FDB     XPPTRIG-1
AADC +B029          DW      REV (XPPTRIG-1)
AADE                FDB     XPSTRIG-1
AADE +B02D          DW      REV (XPSTRIG-1)


;                       Execute Expression

AAE0                LOCAL

;EXEXPR-Execute Expression

AAE0            XLET
AAE0            EXEXPR
AAE0  202EAB        JSR     EXPINT          ; GO INIT
                ;
AAE3            :EXNXT
AAE3  203EAB        JSR     :EGTOKEN        ; GO GET TOKEN
AAE6  B006 ^AAEE    BCS     :EXOT           ; BR IF OPERATOR
                ;
AAE8  20BAAB        JSR     ARGPUSH         ; PUSH ARGUMENT
AAEB  4CE3AA        JMP     :EXNXT          ; GO FOR NEXT TOKEN
                ;
AAEE  85AB      :EXOT   STA     EXSVOP      ; SAVE OPERATOR
AAF0  AA            TAX
AAF1  BD2FAC        LDA     OPRTAB-16,X     ; GET OP PREC
AAF4                LSRA                    ; SHIFT FOR GOES ON TO PREC
AAF4 +4A            LSR     A
AAF5                LSRA
AAF5 +4A            LSR     A
AAF6                LSRA
AAF6 +4A            LSR     A
AAF7                LSRA
AAF7 +4A            LSR     A
AAF8  85AC          STA     EXSVPR          ; SAVE GOES ON PREC
                ;
AAFA  A4A9      :EXPTST LDY     OPSTKX      ; GET OP STACK INDEX
AAFC  B180          LDA     [ARGSTK],Y      ; GET TOP OP
AAFE  AA            TAX
AAFF  BD2FAC        LDA     OPRTAB-16,X     ; GET TOP OP PREC
AB02  290F          AND     #$0F
AB04  C5AC          CMP     EXSVPR          ; [TOP OP]: [NEW OP]
AB06  900D ^AB15    BCC     :EOPUSH         ; IF T<N, PUSH NEW
                ;
AB08  AA            TAX                     ; IF POP SOE
AB09  F014 ^AB1F    BEQ     :EXEND          ; THEN DONE
                ;
AB0B            :EXOPOP
AB0B  B180          LDA     [ARGSTK],Y      ; RE-GET TOS OP
AB0D  E6A9          INC     OPSTACK         ; DEC OP STACK INDEX
AB0F  2020AB        JSR     :EXOP           ; GET EXECUTE OP
AB12  4CFAAA        JMP     :EXPTST         ; GO TEST OP WITH NEW TOS
                ;
AB15  A5AB      :EOPUSH LDA     EXSVOP      ; GET OP TO PUSH
AB17  88            DEY                     ; DEC TO NEXT ENTRY
AB18  9180          STA     [ARGSTK],Y      ; SET OP IN STACK
AB1A  84A9          STY     OPSTKX          ; SAVE NEW OP STACK INDEX
AB1C  4CE3AA        JMP     :EXNXT          ; GO GET NEXT TOKEN
                ;
AB1F            XPLPRN

;----------189

AB1F  60        :EXEND  RTS                 ; DONE EXECUTE EXPR
AB20            :EXOP
AB20  38            SEC                     ; SUBSTRACT FOR REL 0
AB21  E91D          SBC     #CSROP          ; VALUE OF FIRST REAL OP
AB23                ASLA
AB23 +0A            ASL     A
AB24  AA            TAX
AB25  BD70AA        LDA     OPETAB,X        ; PUT OP EXECUTION
AB28  48            PHA                     ; ROUTINE ON STACK
AB29  BD71AA        LDA     OPETAB+1,X      ; AND GOTO
AB2C  48            PHA                     ; VIA
AB2D  60            RTS                     ; RTS

;Initialize Expression Parameters

AB2E            EXPINT
AB2E  A0FF          LDY     #$FF
AB30  A911          LDA     #CSOE           ; OPERATOR
AB32  9180          STA     [ARGSTK],Y      ; STACK
AB34  84A9          STY     OPSTKX
AB36  C8 AB
           INY                     ; AND INITIALIZE
AB37  84B0          STY     COMCNT
AB39  84AA          STY     ARSTKX          ; ARG STACK
AB3B  84B1          STY     ADFLAG          ; ASSIGN FLAG
AB3D  60            RTS

;GETTOK-Get Next Token and Classify

AB3E            GETTOK
AB3E            :EGTOKEN
AB3E  A4A8          LDY     STINDEX         ; GET STMT INDEX
AB40  E6A8          INC     STINDEX         ; INC TO NEXT
AB42  B18A          LDA     [STMCUR],Y      ; GET TOKEN
AB44  3043 ^AB89    BMI     :EGTVAR         ; BR IF VAR
                ;
AB46  C90F          CMP     #$0F            ; TOKEN: $0F
AB48  9003 ^AB4D    BCC     :EGNC           ; BR IF $OE, NUMERIC CONST
AB4A  F013 ^AB5F    BEQ     :EGSC           ; BR IF $0F, STR CONST
AB4C  60            RTS                     ; RTN IF OPERATOR
                ;
AB4D            NCTOFR0
AB4D  A200      :EGNC   LDX     $0
AB4F  C8        :EGT1                       ; INC LINE INDEX
AB50  B18A          LDA     [STMCUR],Y      ; GET VALUE FROM STMT TBL
AB52  95D4          STA     FR0,X           ; AND PUT INTO FR0
AB54  E8            INX
AB55  E006          CPX     #0
AB57  90F6 ^ABF6    BCC     :EGT1
AB59  C8            INY                     ; INY Y BEYOND CONST
AB5A  A900          LDA     #EVSCALER       ; ACU=SCALER
AB5C  AA            TAX                     ; X = VAL NO 0
AB5D  F022 ^AB81    BEQ     :EGST           ; GO SET REM
                ;
AB5F  C8        :EGSC   INY                 ; INC Y TO LENGTH BYTE
AB60  B18A          LDA     [STMCUR],Y      ; GET LENGTH
AB62  A28A          LDX     #STMCUR         ; POINT TO SMCUR
AB64            RISC
AB64  85D6          STA     VTYPE+EVSLEN    ; SET AS LENGTH
AB66  85D8          STA     VTYPE+EVSDIM    ; AND DIM
AB68  C8            INY
AB69  98            TYA                     ; ACU=DISPL TO STR
AB6A  18            CLC
AB6B  7500          ADC     0,X             ; DISPL PLUS ADR
AB6D  85D4          STA     VTYPE+EVSADR    ; IS STR ADR
AB6F  A900          LDA     #0              ; SET = 0
AB71  85D7          STA     VTYPE+EVSLEN+1  ; LENGTH HIGH
AB73  85D9          STA     VTYPE+EVSDIM+1  ; DIM HIGH
AB75  7501          ADC     1,X             ; FINISH ADR
AB77  85D5          STA     VTYPE+EVSADR+1
                ;

;----------190

AB79  98            TYA                     ; ACU=DISPL TO STR
AB7A  65D6          ADC     VTYPE+EVSLEN    ; PLUS STR LENGTH
AB7C  A8            TAY                     ; IS NEW INDEX
AB7D  A200          LDX     #00             ; VAR NO = 0
AB7F  A983          LDA     #EVSTR+EVSDTA+EVDIM  ; TYPE = STR
                ;
AB81  85D2      :EGST   STA     VTYPE       ; SET TYPE
AB83  86D3          STX     VNUM            ; SET NUM
AB85  84A8          STY     STINDEX         ; SET NEW INDEX
AB87  18            CLC                     ; INDICATE VALUE
AB88  60        :EGRTS  RTS                 ; RETURN
                ;
AB89            GETVAR
AB89            :EGTVAR
AB89  2028AC        JSR     GVVTADR         ; GET VVT ADR
AB8C  B19D      :EGT2   LDA     [WVVTPT],Y      ; MOVE VVT ENTRY
AB8E  99D200        STA     VTYPE,Y         ; TO FR0
AB91  C8            INY
AB92  C008          CPY     #8
AB94  90F6 ^AB8C    BCC     :EGT2
AB96  18            CLC                     ; INDICATE VALUE
AB97  60            RTS                     ; RETURN

;AAPSTR-Pop String Argument and Make Address Absolute

AB98  20F2AB    AAPSTR  JSR     ARGPOP      ; GO POP ARG

;GSTRAD-Get String[ABS]Address

AB9B            GSTRAD
AB9B  A902          LDA     #EVSDTA         ; LOAD TRANSFORMED BIT
AB9D  24D2          BIT     VTYPE           ; TEST STRING ADR TRANSFORM
AB9F  D015 ^ABB6    BNE     :GSARTS         ; BR IF ALREADY TRANSFORMED
ABA1  05D2          ORA     VTYPE           ; TURN ON TRANS BIT
ABA3  85D2          STA     VTYPE           ; AND SET
ABA5                RORA                    ; SHIFT DIM BIT TO CARRY
ABA5 +6A            ROR     A
ABA6  900F ^ABB7    BCC     :GSND
                ;
ABA8  18            CLC
ABA9  A5D4          LDA     VTYPE+EVSADR    ; STRING ADR = STRING DISPL
                                              + STRAP
ABAB  658C          ADC     STARP
ABAD  85D4          STA     VTYPE+EVSADR
ABAF  A8            TAY
ABB0  A5D5          LDA     VTYPE+EVSADR+1
ABB2  658D          ADC     STARP+1
ABB4  85D5          STA     VTYPE+EVSADR+1
ABB6  60        :GSARTS RTS
ABB7  202EB9    :GSND   JSR     ERRDIM

;ARGPUSH-Push FR0 to Argument Stack

ABBA            ARGPUSH
ABBA  E6AA          INC     ARSLVL          ; INC ARG STK LEVEL
ABBC  A5AA          LDA     ARSLVL          ; ACU = ARG STACK LEVEL
ABBE                ASLA                    ; TIMES 8
ABBE +0A            ASL     A
ABBF                ASLA
ABBF +0A            ASL     A
ABC0                ASLA
ABC0 +0A            ASL     A
ABC1  C5A9          CMP     OPSTKX          ; TEST EXCEED MAX
ABC3  B00D ^ABD2    BCS     :APERR          ; BR IF GT MAX
ABC5  A8            TAY                     ; Y = NEXT ENTRY ADR
ABC6  88            DEY                     ; MINUS ONE
ABC7  A207          LDX     #7              ; X = 7 FOR 8
                ;
ABC9  B5D2      :APH1   LDA     VTYPE,X     ; MOVE FR0
ABCB  9180          STA     [ARGOPS],Y      ; TO ARGOPS

;---------191

ABCD  88            DEY                     ; BACKWARDS
ABCE  CA            DEX
ABCF  10F8 ^ABC9    BPL     :APH1
ABD1  60            RTS                     ; DONE
                ;
ABD2  4C2CB9    :APERR  JMP     ERRAOS      ; STACK OVERFLOW

;GETPINT-Get Positive Integer from Expression

ABD5            GETPINT
ABD5  20E0AB        JSR     GETINT          ; GO GET INT
ABD8            GETPI0
ABD8  A5D5          LDA     FR0+1           ; GET HIGH BYTE
ABDA  3001 ^ABDD    BMI     :GPIERR         ; BR > 32767
ABDC  60            RTS                     ; DONE
ABDD  4C32B8    :GPIERR JMP     ERRLN


;GETINT-Get Integer Expression

ABE0  20E0AA    GETINT  JSR     EXEXPR      ; EVAL EXPR
ABE3            GTINTO
ABE3  20F2AB       JSR      ARGPOP          ; POP VELUE TO FR0
ABE6  4C56AD       JMP      CVFPI           ; GO CONVERT FR0 TO INT &
                                              RETURN

;GET1INT-Get One-Byte Integer from Expression

ABE9            GET1INT
ABE9  20D5AB        JSR     GETPINT         ; GET INT <32768
ABEC  D001 ^ABEF    BNE     :ERV1           ; IF NOT 1 BYTE, THEN ERROR
ABEE  60            RTS
ABEF            :ERV1
ABEF  203AB9        JSR     ERVAL

;ARGPOP-Pop Argument Stack Entry to FR0 or FR1

ABF2            ARGPOP
ABF2  A5AA          LDA     ARSLVL          ; GET ARG STACK LEVEL
ABF4  C6AA          DEC     ARSLVL          ; DEC AS LEVEL
ABF6                ASLA                    ; AS LEVEL * 8
ABF6 +0A            ASL     A
ABF7                ASLA
ABF7 +0A            ASL     A
ABF8                ASLA
ABF8 +0A            ASL     A
ABF9  A8            TAY                     ; Y = START OF NEXT ENTRY
ABFA  88            DEY                     ; MINUS ONE
ABFB  A207          LDX     #7              ; X = 7 FOR 8
                ;
ABFD  B180      :APOP0  LDA     [ARGOPS],Y      ; MOVE ARG ENTRY
ABFF  95D2          STA     VTYPE,X
AC01  88            DEY                     ; BACKWARDS
AC02  CA            DEX
AC03  10F8 ^ABFD    BPL     :APOP0
AC05  60            RTS                     ; DONE

;ARGP2-Pop TOS to FR1,TOS-1 to FR0

AC06  20F2AB    ARGP2   JSR     ARGPOP      ; POP TOS TO FR0
AC09  20B6DD        JSR     MV0TO1          ; MOVE FR0 TO FR1
AC0C  4CF2AB        JMP     ARGPOP          ; POP TOS TO FR0 AND RETURN

;POP1-Get Value in FR0
                ;           - EVALUATE EXPRESSION IN STMT LINE &
                ;             POP IT INTO FR0
                ;
AC0F            POP1
AC0F  20E0AA        JSR     EXEXPR          ; EVALUATE EXPRESSION
AC12  20F2AB        JSR     ARGPOP          ; PUSH INTO FR0
AC15  60            RTS

;----------192

AC16            RTNVAR
AC16  A5D3          LDA     VNUM            ; GET VAR NUMBER
AC18  2028AC        JSR     GVVTADR
AC1B  A200          LDX     #0
                ;
AC1D  B5D2      :RV1     LDA     VTYPE,X     ; MOVE FR0 TO
AC1F  919D          STA     [WVVTPT],Y      ; VAR VALUE TABLE
AC21  C8            INY
AC22  E8            INX
AC23  E008          CPX     #8
AC25  90F6 ^AC1D    BCC     :RV1
AC27  60            RTS                     ; DONE

;GVVTADR-Get Value's Value Table Entry Address

AC28            GVVTADR
AC28  A000         LDY      #0              ; CLEAR ADR HI
AC2A  849E         STY      WVVTPT+1
AC2C               ASLA                     ; MULT VAR NO
AC2C +0A           ASL      A
AC2D               ASLA                     ; BY 8
AC2D +0A           ASL      A
AC2E  269E         ROL      WVVTPT+1
AC30               ASLA
AC30 +0A           ASL      A
AC31  269E         ROL      WVVTPT+1
AC33  18           CLC                      ; THEN
AC34  6586         ADC      VVTP            ; ADD VVTP VALUE
AC36  859D         STA      WVVTPT          ; TO FORM ENTRY
AC38  A587         LDA      VVTP+1          ; ADR
AC3A  659E         ADC      WVVTPT+1
AC3C  859E         STA      WVVTPT+1
AC3E  60           RTS

;                   Operator Precedence Table

                ;              - ENTRIES MUST BE IN SAME ORDER AS OPNTAB
                ;              - LEFT NIBBLE IS TO GO ON STACK PREC
                ;              - RIGHT NIBBLE IS COME OFF STACK PREC
                ;
AC3F            OPRTAB
AC3F  00           DB        $00             ; CDQ
AC40  00           DB        $00             ; CSOE
AC41  00           DB        $00             ; CCOM
AC42  00           DB        $00             ; CDOL
AC43  00           DB        $00             ; CEOS
AC44  00           DB        $00             ; CSC
AC45  00           DB        $00             ; CCR
AC46  00           DB        $00             ; CGTO
AC47  00           DB        $00             ; CGS
AC48  00           DB        $00             ; CTO
AC49  00           DB        $00             ; CSTEP
AC4A  00           DB        $00             ; CTHEN
AC4B  00           DB        $00             ; CPND
AC4C  00           DB        $00             ; CLE
AC4D  00           DB        $00             ; CNE
AC4E  00           DB        $00             ; CGE
AC4F  88           DB        $88             ; CGT
AC50  88           DB        $88             ; CLT
AC51  88           DB        $88             ; CEQ
AC52  CC           DB        $CC             ; CEXP
AC53  AA           DB        $AA             ; CMUL
AC54  99           DB        $99             ; CPLUS
AC55  99           DB        $99             ; CMINUS
AC56  AA           DB        $AA             ; CDIV
AC57  77           DB        $77             ; CNOT
AC58  55           DB        $55             ; COR
AC59  66           DB        $66             ; CAND
AC5A  F2           DB        $F2             ; CLPRN

;----------193

AC5B  4E           DB        $4E             ; CRPRN
AC5C  F1           DB        $F1             ; CAASN
AC5D  F1           DB        $F1             ; CSASN
AC5E  EE           DB        $EE             ; CSLE
AC5F  EE           DB        $EE             ; CSNE
AC60  EE           DB        $EE             ; CSGE
AC61  EE           DB        $EE             ; CSLT
AC62  EE           DB        $EE             ; CSGT
AC63  EE           DB        $EE             ; CSEQ
AC64  DD           DB        $DD             ; CUPLUS
AC65  DD           DB        $DD             ; CUMINUS
AC66  F2           DB        $F2             ; CSLPRN
AC67  F2           DB        $F2             ; CALPRN
AC68  F2           DB        $F2             ; CDLPRN
AC69  F2           DB        $F2             ; CFLPRN
AC6A  F2           DB        $F2             ; CDSLPR
AC6B  43           DB        $43             ; CACOM
                ;
AC6C  F2           DB        $F2             ; FUNCTIONS
AC6D  F2           DB        $F2
AC6E  F2           DB        $F2
AC6F  F2           DB        $F2
AC70  F2           DB        $F2
AC71  F2           DB        $F2
AC72  F2           DB        $F2
AC73  F2           DB        $F2
AC74  F2           DB        $F2
AC75  F2           DB        $F2
AC76  F2           DB        $F2
AC77  F2           DB        $F2
AC78  F2           DB        $F2
AC79  F2           DB        $F2
AC7A  F2           DB        $F2
AC7B  F2           DB        $F2
AC7C  F2           DB        $F2
AC7D  F2           DB        $F2
AC7E  F2           DB        $F2
AC7F  F2           DB        $F2
AC80  F2           DB        $F2
AC81  F2           DB        $F2
AC82  F2           DB        $F2
AC83  F2           DB        $F2

;                     Miscellaneous Operators

;Miscellaneous Operators' Executors

AC84            XPLUS
AC84  2006AC        JSR       ARGP2
AC87  203BAD        JSR       FRADD
AC8A  4CBAAB        JMP       ARGPUSH
AC8D            XPMINUS
AC8D  2006AC        JSR       ARGP2
AC90  2041AD        JSR       FRSUB
AC93  4CBAAB        JMP       ARGPUSH
AC96            XPMUL
AC96  2006AC        JSR       ARGP2
AC99  2047AD        JSR       FRMUL
AC9C  4CBAAB        JMP       ARGPUSH
AC9F            XPDIV
AC9F  2006AC        JSR       ARGP2
ACA2  204DAD        JSR       FRDIV
ACA5  4CBAAB        JMP       ARGPUSH
ACA8            XPUMINUS
ACA8  20F2AB        JSR       ARGPOP          ;GET ARGUMENT INTO FR0
ACAB  A5D4          LDA       FR0             ;GET BYTE WITH SIGN
ACAD  4980          EOR       #$80            ;FLIP SIGN BIT
ACAF  85D4          STA       FR0             ;RETURN BYTE WITH SIGN CHANGED
ACB1  4CBAAB        JMP       ARGPUSH         ;PUSH ON STACKS
ACB4            XPUPLUS

;----------194

ACB4  60            RTS
ACB5            XPLE
ACB5            XPSLE
ACB5  2026AD        JSR     XCMP
ACB9  304B ^AD05    BMI     XTRUE
ACBA  F049 ^AD05    BEQ     XTRUE
ACBC  1042 ^AD00    BPL     XFALSE
ACBE            XPNE
ACBE            XPSNE
ACBE  2026AD        JSR     XCMP
ACC1  F03D ^AD00    BEQ     XFALSE
ACC3  D040 ^AD05    BNE     XTRUE
ACC5            XPLT
ACC5            XPSLT
ACC5  2026AD        JSR     XCMP
ACC8  303B ^AD05    BMI     XTRUE
ACCA  1034 ^AD00    BPL     XFALSE
ACCC            XPGT
ACCC            XPSGT
ACCC  2026AD        JSR     XCOMP
ACCF  302F ^AD00    BMI     XFALSE
ACD1  F02D ^AD00    BEQ     XFALSE
ACD3  1030 ^AD05    BPL     XTRUE
ACD5            XPGE
ACD5            XPSGE
ACD5  2026AD        JSR     XCOMP
ACD8  3026 ^AD00    BMI     XFALSE
ACDA  1029 ^AD05    BPL     XTRUE
ACDC            XPEQ
ACDC            XPSEQ
ACDC  2026AD        JSR     XCOMP
ACDF  F024 ^AD05    BEQ     XTRUE
ACE1  D01D ^AD00    BNE     XFALSE
                ;
ACE3            XPAND
ACE3  2006AC        JSR     ARGP2
ACE6  A5D4          LDA     FR0
ACE8  25E0          AND     FR1
ACEA  F014 ^AD00    BEQ     XFALSE
ACEC  D017 ^AD05    BNE     XTRUE
ACEE            XPOR
ACEE  2006AC        JSR     ARGP2
ACF1  A5D4          LDA     FR0
ACF3  05E0          ORA     FR1
ACF5  F009 ^AD00    BEQ     XFALSE
ACF7  D00C ^AD05    BNE     XTRUE
ACF9            XPNOT
ACF9  20F2AB        JSR     ARGPOP
ACFC  A5D4          LDA     FR0
ACFE  F005 ^AD05    BEQ     XTRUE
                ;       FALL THROUGH TO FALSE
                ;
                ;
AD00            XFALSE
AD00  A900          LDA     #0
AD02  A8            TAY
AD03  F004 ^AD09    BEQ     XTF
                ;
AD05            XTRUE
AD05  A940          LDA     #$40
AD07            XTI
AD07  A001          LDY     #1
                ;
AD09            XTF
AD09  85D4          STA     FR0
AD0B  84D5          STY     FR0+1
AD0D  A2D6          LDX     #FR0+2          ; POINT TO PART TO CLEAR
AD0F  A004          LDY     #FPRES-2        ; GET # OF BYTES TO CLEAR
AD11  2048DA        JSR     ZXLY            ; CLEAR REST OF FR0
AD14  85D2          STA     VTYPE
AD16            XPUSH
AD16  4CBAAB        JMP     ARGPUSH

;----------195

;XPSGN-Sign Function

AD19            XPSIGN
AD19  20F2AB        JSR     ARGPOP
AD1C  A5D4          LDA     FR0
AD1E  F0F6 ^AD16    BEQ     XPUSH
AD20  10E3 ^AD05    BPL     XTRUE
AD22  A9C0          LDA     #$C0            ; GET MINUS EXPONENT
AD24  30E1 ^AD07    BMI     XTI

;XCMP-Compare Executor

AD26            XCMP
AD26  20F2AB        LDY     OPSTKX          ; GET OPERATOR THAT
AD28  88            DEY                     ; GOT US HERE
AD29  B100          LDA     [ARGSTK],Y
AD2B  C92F          CMP     #CSLE           ; IF OP WAS ARETHMETIC
AD2D  9003 ^AD32    BCC     FROMPP          ; THEN DO FP REG COMP
AD2F  4C81AF        JMP     STRCMP          ; ELSE DO STRING COMPARE
                ;
AD32  2006AC    FRCMPP  JSR     ARGP2

;FRCMP-Compare Two Floating Point Numbers

                ;       ON ENTRY   FR0 & FR1 CONTAIN FLAOTING POINT #'S
                ;
                ;       ON EXIT    CC = + FR0 > FR1
                ;                  CC = - FR0 < FR1
                ;                  CC = 0 FRE0 = FR1
                ;
                ;
AD35            FRCMP
AD35  2041AD        JSR     FRSUB           ; SUBSTRACT FR1 FROM FR0
                ;
AD38  A5D4          LDA     FR0             ; GET FR0 EXPONENT
AD3A  60            RTS                     ; RETURN WITH CC SET

;FRADD-Floating Point Add

                ;      DOES NOT RETURN IF ERROR
                ;
AD3B            FRADD
AD3B  2066DA        JSR     FADD            ; ADD TWO #
AD3E  B013 ^AD53    BCS     :ERROV          ; BR IF ERROR
AD40  60            RTS

;FRSUB-Floating Point Substract

                ;      DOES NOT RETURN IF ERROR
                ;
AD41            FRSUB
AD41  2060DA        JSR     FSUB            ; SUB TWO #
AD44  B00D ^AD53    BCS     :ERROV          ; BR IF ERROR
AD46  60            RTS

;FRMUL-Floating Point Multiply

                ;      DOES NOT RETURN IF ERROR
                ;
AD47            FRMUL
AD47  20DBDA        JSR     FMUL            ; MULT TWO #
AD4A  B007 ^AD53    BCS     :ERROV          ; BR IF ERROR
AD4C  60            RTS

;FRDIV-Floating Point Divide

                ;      DOES NOT RETURN IF ERROR
                ;
AD4D            FRDIV
AD4D  20DBDA        JSR     FDIV            ; DIVIDE TWO #

;----------196

AD50  B001 ^AD53    BCS     :ERROV          ; BR IF ERROR
AD52  60            RTS
                ;
                ;
                ;
;CVFPI-Convert Floating Point to Integer

                ;      DOES NOT RETURN IF ERROR
                ;
AD56            CVFPI
AD56  20D2D9        JSR     FPI             ; GO CONVERT TO INTEGER
AD59  B00D ^AD5C    BCS     :ERRVAL         ; IF ERROR, BR
AD5B  60            RTS                     ; ELSE RETURN
                ;
                ;
                ;
AD5C            :ERRVAL
AD5C  203AB9        JSR     ERVAL           ; VALUE ERROR

;XPAASN-Arithmetic Assignement Operator

AD5F            XPAASN
AD5F  A5A9          LDA     OPSTKX          ; GET OP STACK INDEX
AD61  C9FF          CMP     #$FF            ; AT STACK START
AD63  D00F ^AD74    BNE     :AAMAT          ; BR IF NOT, [MAT ASSIGN]
                ;                                 DO SCALAR ASSIGN
AD65  2006AC        JSR     ARGP2           ; GO POP TOP 2 ARGS
AD68  A205          LDX     #5              ; MOVE FR1 VALUE
AD6A  B5E0      :AASN1  LDA     FR1,X       ; TO FR0
AD6C  95D4          STA     FR0,X
AD6E  CA            DEX
AD6F  10F9 ^AD6A    BPL     :AASN1
AD71  4C16AC        JMP     RTNVAR          ; FR0 TO VVT & RETURN
                ;
AD74            :AAMAT
AD74  A980          LDA     #$80            ; SET ASSIGN FLAG BIT ON
AD76  85B1          STA     ADFLAG          ; IN ASSIGN/DIM FLAG
AD78  60            RTS                     ; GO POP REM OFF OPS

;XPACOM-Array Comma Operator

AD79            XPACOM
AD79  E6B0          INC     COMCNT          ; INCREMENT COMMA COUNT

;XPRPRN-Right Parenthesis Operator

                ;       XPFLPRN - FUNCTION RIGHT PAREN OPERATOR
                ;
AD7B            XPRPRN
AD7B            XPFLPRN
AD7B  A4A9          LDY     OPSTKX          ; GET OPERATOR STACK TOP
AD7D  68            PLA
AD7E  68            PLA
AD7F  4C0BAB        JMP     EXOPOP          ; GO POP AND EXECUTE NEXT
                                              OPERATOR
                ;

;XPDLPRN-DIM Left Parenthesis Operator

AD82            XDPSLP
AD82            XPDLPRN
AD82  A940          LDA     #$40            ; SET DIM FLAG BIT
AD84  85B1          STA     ADFLAG          ; IN ADFLAG
                                                  FALL THRU TO XPALPRN

;----------197

;XPALPRN-Array Left Parenthesis Operator

AD86            XPALPRN
AD86  24B1          BIT     ADFLAG          ; IF NOT ASSIGN
AD88  1006 ^AD90    BPL     :ALP1           ; THE BRANCH
                ;                                 ELSE
AD8A  A5AA          LDA     ARSLVL          ; SAVE STACK LEVEL
AD8C  85AF          STA     ATEMP           ;OP THE VALUE ASSIGNEMENT
AD8E  C6AA          DEC     ARSLVL          ; AND PSEUDO POP IT
                ;
AD90  A900      :ALP1   LDA     #0          ; INIT FOR I2 = 0
AD92  A8            TAY
AD93  C5B0          CMP     COMCNT          ; IF COMMA COUNT =0 THEN
AD95  F00B ^ADA2    BEQ     :ALP2           ; BR WITH I2 = 0
                ;                                 ELSE
AD97  C6B0          DEC     COMCNT
AD99  20E3AB        JSR     GTINTO          ; ELSE POP I2 AND MAKE INT
AD9C  A5D5          LDA     FR0+1
AD9E  3023 ^ADC3    BMI     :ALPER          ; ERROR IF 32,767
ADA0  A4D4          LDY     FR0
                ;
ADA2  8598      :ALP2   STA     INDEX2+1    ; SET 12 VALUE
ADA4  8497          STY     INDEX2
                ;
ADA6  20E3AB        JSR     GTINTO          ; POP I2 AND MAKE INT
ADA9  A5D4          LDA     FR0             ; MOVE  IT
ADAB  85F5          STA     ZTEMP1          ; TO ZTEMP1
ADAD  A5D5          LDA     FR0+1
ADAF  3012 ^ADC3    BMI     :ALPER          ; ERROR IF > 32,767
ADB1  85F6          STA     ZTEMP1+1
                ;
ADB3  20F2AB        JSR     ARGPOP          ; POP THE ARRAY ENTRY
                ;
ADB6  24B1          BIT     ADFLAG          ; IF NOT EXECUTING DIM
ADB8  5005 ^ADBF    BVC     :ALP3           ; THEN CONTINUE
ADBA  A900          LDA     #0              ; TURN OFF DIM BIT
ADBC  85B1          STA     ADFLAG          ; IN ADFLAG
ADBE  60            RTS                     ; AND RETURN
                ;
ADBF            :ALP3
ADBF  66D2          ROR     VTYPE           ; IF ARRAY HAS BEEN
ADC1  B003 ^ADC6    BCS     :ALP4           ; DIMMED THEN CONTINUE
ADC3  202EB9    :ALPER   JRS    ERRDIM      ; ELSE DIM ERROR
                ;
ADC6            :ALP4
ADC6  A5F6          LDA     ZTEMP1+1        ; THEN INDEX 1
ADC8  C5D7          CMP     VTYPE+EVAD1+1   ; IN RANGE WITH
ADCA  9008 ^ADD4    BCC     :ALP5           ; DIM1
ADCC  D0F5 ^ADC3    BNE     :ALPER
ADCE  A5F5          LDA     ZTEMP1
ADD0  C5D6          CMP     VTYPE+EVAD1
ADD2  B0EF ^ADC3    BCS     :ALPER
                ;
ADD4  A598      :ALP5   LDA     INDEX2+1    ; TEST INDEX 2
ADD6  C5D9          CMP     VTYPE+EVAD2+1   ; IN RANGE WITH
ADD8  9008 ^ADE2    BCC     :ALP6           ; DIM 2
ADDA  D0E7 ^ADC3    BNE     :ALPER
ADDC  A597          LDA     INDEX2
ADDE  C5D8          CMP     VTYPE+EVAD2
ADE0  B0E1 ^ADC3    BCS     :ALPER
                ;
ADE2  205DAF    :ALP6   JSR     AMUL1       ; INDEX1 = INDEX1
ADE5  A597          LDA     INDEX2          ; INDEX1 = INDEX1 + INDEX2
ADE7  A498          LDY     INDEX2+1
ADE9  2052AF        JSR     AADD
ADEC  2046AF        JSR     AMUL2           ; ZTEMP1 = ZTEMP1*6
ADEF  A5D4          LDA     VTYPE+EVAADR    ; ZTEMP1 = ZTEMP1 + DISPL
ADF1  A4D5          LDY     VTYPE+EVAADR+1
ADF3  2052AF        JSR     AADD
ADF6  A58C          LDA     STARP           ; ZTEMP1 = ZTEMP1 + ADR

;----------198

ADF0  A48D          LDY     STARP+1
ADFA  2052AF        JSR     AADD
                ;                                ZTEMP1 NOW POINTS
                ;                                TO ELEMENT REQD
ADFD  24B1          BIT     ADFLAG          ; IF NOT ASSIGN
ADFF  1015 ^AE16    BPL     :ALP8           ; THEN CONTINUE
                ;                                 ELSE ASSIGN
AE01  A5AF          LDA     ATEMP           ;RESTORE ARG LEVEL
AE03  85AA          STA     ARSLVL          ; TO VALUE AND
AE05  20F2AB        JSR     ARGPOP          ; POP VALUE
                ;
AE08  A005          LDY     #5
AE0A  B9D400    :ALP7   LDA     FR0,Y       ; MOVE VALUE
AE0D  91F5          STA     [ZTEMP1],Y      ; TO ELEMENT SPACE
AE0F  88            DEY
AE10  10F8 ^AE0A    BPL     :ALP7
AE12  C8            INY                     ; TURN OFF
AE13  84B1          STY     ADFLAG          ; ADFLAG
AE15  60            RTS                     ; DONE
                ;
AE16  A005      :ALP8   LDY     #5
AE18  B1F5      :ALP9   LDA     [ZTEMP1],Y      ; MOVE ELEMENT TO
AE1A  99D400        STA     FR0,Y           ; FR0
AE1D  88            DEY
AE1E  10F8 ^AE18    BPL     :ALP9
                ;
AE20  C8            INY
AE21  84D2          STY     VTYPE
AE23  4CBAAB        JMP     ARGPUSH         ; PUSH FR0 BACK TO STACK
                ;                                 AND RETURN

;XPLPRN-String Left Parenthesis

AE26            XPSLPRN
AE26  A5B0          LDA     COMCNT          ; IF NO INDEX 2
AE28  F007 ^AE31    BEQ     :XSLP2          ; THEN BR
                ;
AE2A  2096AE        JSR     :XSPV           ; ELSE POP I2 AND
AE2D  8498          STY     INDEX2+1        ;SAVE IN INDEX 2
                ;
AE31  2096AE    :XSLP2  JSR     :XSPV       ; POP INDEX 1
AE34  38            SEC                     ; ADD DECREMENT BY ONE
AE35  E901          SBC     #1              ; AND PUT INTO ZTEMP1
AE37  85F5          STA     ZTEMP1
AE39  98            TYA
AE3A  E900          SBC     #0
AE3C  85F6          STA     ZTEMP1+1
                ;
AE3E  20F2AB        JSR     ARGPOP          ; POP ARG STRING
                ;
AE41  A5B1          LDA     ADFLAG          ; IF NOT A DEST STRING
AE43  100B ^AE50    BPL     :XSLP3          ; THEN BRANCH
AE45  05B0          ORA     COMCNT
AE47  85B1          STA     ADFLAG
AE49  A4D9          LDY     VTYPE+EVSDIM+1  ; INDEX 2 LIMIT
AE4B  A5D8          LDA     VTYPE+EVSDIM    ; IS DIM
AE4D  4C54AE        JMP     :XSLP4
                ;
AE50  A5D6      :XSLP3  LDA     VTYPE+EVSLEN    ; INDEX 2 LIMIT
AE52  A4D7          LDY     VTYPE+EVSLEN+1  ; IS STRING LENGTH
                ;
AE54  A6B0      :XSLP4  LDX     COMCNT      ; IF NO INDEX 2
AE56  F010 ^AE68    BEQ     :XSLP6          ; THEN BRANCH
AE58  C6B0          DEC     COMCNT          ; ELSE
AE5A  C498          CPY     INDEX2+1
AE5C  9035 ^AE93    BCC     :XSLER
AE5E  D004 ^AE64    BNE     :XSLP5          ; INDEX 2 LIMIT
AE60  C597          CMP     INDEX2
AE62  902F ^AE93    BCC     :XSLER
                ;

;----------199

AE64  A498      :XSLP5  LDY     INDEX2+1    ;USE INDEX2
AE66  A597          LDA     INDEX2          ;AS LIMIT
                ;
AE68  38        :XSLP6  SEC                 ; LENGTH IS
AE69  E5F5          SBC     ZTEMP1
AE6B  85D6          STA     VTYPE+EVSLEN    ; LIMIT - INDEX 1
AE6D  AA            TAX
AE6E  98            TYA
AE6F  E5F6          SBC     ZTEMP1+1
AE71  85D7          STA     VTYPE+EVSLEN+1
AE73  901E ^AE93    BCC     :XSLER          ; LENGTH MUST BE
AE75  A8            TAY                     ; GE ZERO
AE76  D003 ^AE7B    BNE     :XSLP7
AE78  8A            TXA
AE79  F018 ^AE93    BEQ     :XSLER
                ;
AE7B  209BAB    :XSLP7  JSR     GSTRAD      ; GET ABS ADR
                ;
AE7E  18            CLC
AE7F  A5D4          LDA     VTYPE+EVSADR
AE81  65F5          ADC     ZTEMP1          ; STRING ADR
AE83  85D4          STA     VTYPE+EVSADR    ; STRING ADR + INDEX 1
AE85  A5D5          LDA     VTYPE+EVSADR+1
AE87  65F6          ADC     ZTYPE1+1
AE89  85D5          STA     VTYPE+EVSADR+1
                ;
AE8B  24B1          BIT     ADFLAG          ; IF NOT ASSIGN
AE8D  1001 ^AE90    BPL     :XSLP8          ; THEN BR
AE8F  60            RTS                     ; ELSE RETURN TO ASSIGN
                ;
AE90  4CBAAB    :XSLP8  JMP     ARGPUSH     ; PUSH ARG AND RETURN
                ;
AE93  2036B9    :XSLER  JSR     ERRSSL

;XSPV-Pop Index Value as Integer and Insure Not Zero

AE96            :XSPV
AE96  20E3AB        JSR     GTINTO          ; GO GET THE INTEGER
AE99  A5D4          LDA     FR0             ; GET VALUE LOW
AE9B  A4D5          LDY     FR0+1           ; GET VALUE HI
AE9D  D003 ^AEA2 :XSPV1 BNE     :XSPVR      ; RTN IF VH NOT ZERO
AE9F  AA            TAX                     ; TEST VL
AEA0  F0F1 ^AE93    BEQ     :XSLER          ; BR VL, VH = 0
AEA2  60        :XSPVR  RTS                 ; DONE

;XSAASN-String Assign Operator

AEA3            XSAASN
AEA3  2098AB        JSR     AAPSTR          ; POP STR WITH ABS ADR
AEA6            RISASN
AEA6  A5D4          LDA     VTYPE+EVSADR    ; MVFA = ADR
AEA8  8599          STA     MVFA
AEAA  A5D5          LDA     VTYPE+EVSADR+1
AEAC  859A          STA     MVFA+1
AEAE  A5D6          LDA     VTYPE+EVSLEN
AEB0  85A2          STA     MVLNG           ; MVLNG = LENGTH
AEB2  A4D7          LDA     VTYPE+EVSLEN+1
AEB4  84A3          STY     MVLNG+1
               ;
AEB6  A4A9          LDY     OPSTKX          ; IF AT TOP OF
AEB8  C0FF          CPY     #$FF            ; OP STACK
AEBA  F00F ^AECB    BEQ     :XSA1           ; THEN BR
               ;                                  ELSE
AEBC  A980          LDA     #$80            ; SET ASSIGN BIT
AEBE  85B1          STA     ADFLAG          ; IN ASSIGN/DIM FLAG
AEC0  200BAB        JSR     EXOPOP          ; AND PROCESS SUBSTRING
AEC3  A5D7          LDA     VTYPE+EVSLEN+1  ; A,Y =
AEC5  A4D6          LDY     VTYPE+EVSLEN    ; DEST LEN
AEC7  26B1          ROL     ADFLAG          ; TURN OFF ASSIGN
AEC9  B007 ^AED2    BCS     :XSA2A          ; AND BR

;----------200

                ;
AECB  2098AB    :XSA1   JSR     AAPSTR      ; POP STR WITH ABS ADR
                ;
AECE  A5D9      :XSA2   LDA     VTYPE+EVSDIM+1  ; A,Y = DEST LENGTH
AED0  A4D8          LDY     VTYPE+EVSDIM
                ;
AED2            :XSA2A
AED2  C5A3          CMP     MVLNG+1         ; IF DEST LENGTH
AED4  9006 ^AEDC    BCC     :XSA3           ; LESS THAT MOVE LENGTH
AED6  D008 ^AEE0    :XSA4
AED8  C4A2          CPY     MVLNG           ; THEN
AEDA  B004 ^AEE0    BCS     :XSA4
AEDC  85A3      :XSA3   STA     MVLNG+1     ; SET MOVE LENGTH
AEDE  84A2          STY     MVLNG           ; = DIST LENGT
                ;
AEE0  18        :XSA4   CLC
AEE1  A5D4          LDA     VTYPE+EVSDAR    ; MOVE LENGTH PLUS
AEE3  65A2          ADC     MVLNG           ; START ADR IS
AEE5  A8            TAY                     ; END ADR
AEE6  A5D5          LDA     VTYPE+EVSADR+1
AEE8  65A3          ADC     MVLNG+1
AEEA  AA            TAX
                ;
AEEB  38            SEC                     ; END ADR MINUS
AEEC  98            TYA                     ; START OF STRING
AEED  E58C          SBC     STARP           ; SPACE IS DISPL
AEEF  85F9          STA     ZTEMP3          ; TO END OF STRING
AEF1  8A            TXA                     ; WHICH WE SAVE
AEF2  E58D          SBC     STARP+1         ; IN ZTEMP3
AEF4  85FA          STA     ZTEMP3+1
                ;
                ;
AEF6  38            SEC                     ; SET MOVE LENGTH LOW
AEF7  A900          LDA     #0              ; = $100 - MVL [L]
AEF9  E5A2          SBC     MVLNG           ; BECAUSE OF THE WAY
AEFB  85A2          STA     MVLNG           ; FMOVE WORKS
                ;
AEFD  38            SEC
AEFE  A599          LDA     MVFA            ; ADJUST MVFA TO
AF00  E5A2          SBC     MVLNG           ; CONFORM WITH MVL
AF02  8599          STA     MVFA            ; CHANGE
AF04  A59A          LDA     MVFA+1
AF06  E900          SBC     #0
AF08  859A          STA     MVFA+1
                ;
AF0A  38            SEC
AF0B  A5D4          LDA     VTYPE+EVSADR    ; MOVE THE DEST
AF0D  E5A2          SBC     MVLNG           ; STRING ADR TO
AF0F  859B          STA     MVTA            ; MVTA AND
AF11  A5D5          LDA     VTYPE+EVSADR+1  ; MAAKE IT CONFORM
AF13  E900          SBC     #0              ; WITH MVL
AF15  859C          STA     MVTA+1
                ;
AF17  2047A9        JSR     FMOVER          ;GO DO THE VERY FAST MOVE
                ;
                ;
AF1A  A5D3          LDA     VNUM            ; GO GET THE ORIGINAL DEST
AF1C  2089AB        JSR     GETVAR          ; STRING
AF1F  38            SEC                     ; DISPL TO END OF
AF20  A5F9          LDA     ZTEMP3          ; MOVE MINUS DISPL
AF22  E5D4          SBC     VTYPE+EVSADR    ; TO START OF STRING
AF24  A8            TAY                     ; IS OUR RESULT LENGTH
AF25  A5FA          LDA     ZTEMP3+1
AF27  E5D5          SBC     VTYPE+EVSADR+1
AF29  AA            TAX
                ;
AF2A  A902          LDA     #2              ; IF THE DESTINATION
AF2C  25B1          AND     ADFLAG          ; LENGTH WAS IMPLICIT
AF2E  F00F ^AF3F    BEQ     :XSA5           ; SET NEW LENGTH
AF30  A900          LDA     #0              ; CLEAR

;----------201

AF32  85B1          STA     ADFLAG          ; FLAG
                ;                                 ELSE FOR EXPLICT LENGTH
AF34  E4D7          CPX     VTYPE+EVSLEN+1  ; IF NEW LENGTH
AF36  9006 ^AF3E    BCC     :XSA6           ; GREATER THAN
AF38  D005 ^AF3F    BNE     :XSA5           ; OLD LENGTH THEN
AF3A  C4D6          CPY     VTYPE+EVSLEN    ; SET NEW LENGTH
AF3C  B001 ^AF3F    BCS     :XSA5           ; ELSE DO NOTHING
AF3E  60        :XSA6   RTS
                ;
AF3F  84D6      :XSA5   STY     VTYPE+EVSLEN
AF41  86D7          STX     VTYPE+EVSLEN+1
AF43  4C16AC        JMP     RTNVAR

;AMUL2-Integer Multiplication of ZTEMP1 by 6

AF46            AMUL2
AF46  06F5          ASL     ZTEMP1          ; ZTEMP1 = ZTEMP1*2
AF48  26F6          ROL     ZTEMP1+1
AF4A  A4F6          LDY     ZTEMP1+1        ; SAVE ZTEMP1*2 IN [A,Y]
AF4C  A5F5          LDA     ZTEMP1
AF4E  06F5          ASL     ZTEMP1          ; ZTEMP1 = ZTEMP1*4
AF50  26F6          ROL     ZTEMP1+1

;AADD-Integer Addition of [A,Y] to ZTEMP1

AF52            AADD
AF52  18            CLC
AF53  65F5      ADC     ADC     ZTEMP1      ; ADD LOW ORDER
AF55  85F5          STA     ZTEMP1
AF57  98            TYA
AF58  65F6          ADC     ZTEMP1+1        ; ADD HIGH ORDER
AF5A  85F6          STA     ZTEMP1+1
AF5C  60            RTS                     ; DONE

;AMUL-Integer Multiplication of ZTEMP1 by DIM2

AF5D            AMUL1
AF5D  A900          LDA     #0              ; CLEAR PARTIAL PRODUCT
AF5F  85F7          STA     ZTEMP4
AF61  85F8          STA     ZTEMP4+1
AF63  A010          LDY     #$10            ; SET FOR 16 BITS
                ;
AF65 A5F5       :AM1    LDA     ZTEMP1      ; GET MULTIPLICAN
AF67                LSRA                    ; TEST MSB = ON
AF67 +4A            LSR     A
AF68  900C ^AF76    BCC     :AM3            ; BR IF OFF
AF6A  18            CLC
AF6B  A2FE          LDX     #$FE            ; ADD MULTIPLIER
AF6D  B5F9      :AM2    LDA     ZTEMP4+2,X      ; TO PARTIAL PRODUCT
AF6F  75DA          ADC     VTYPE+EVAD2+2,X
AF71  95F9          STA     ZTEMP4+2,X
AF73  E8            INX
AF74  D0F7 ^AF6D    BNE     :AM2
                ;
AF76  A203      :AM3    LDX     #3          ; MULT PRODUCT BY 2
AF87  76F5      :AM4    ROR     ZTEMP1,X
AF7A  CA            DEX
AF7B  10FB ^AF78    BPL     :AM4
                ;
AF7D  88            DEY                     ; TEST MORE BITS
AF7E  D0E5 ^AF65    BNE     :AM1            ; BR IF MORE
                ;
AF80  60            RTS                     ; DONE

;STRCMP-String Compare

AF81            STRCMP
AF81  2098AB        JSR     AAPSTR          ; POP STRING WITH ABS ADR
AF84  20B6DD        JSR     MV0TO1          ; MOVE B TO FR1
AF87  2098AB        JSR     AAPSTR          ; POP STRING WITH ABS ADR

;----------202

                ;
AF8A  A2D6      SC1    LDX      #FR0-2+EVSLEN   ;GO DEC STR A LEN
AF8C  20BCAF        JSR     ZPADEC
AF8F  08            PHP                     ; SAVE RTN CODE
AF90  A2E2          LDX     #FR1-2+EVSLEN   ; GO DEC STR B LEN
AF92  20BCAF        JSR     ZPADEC
AF95  F013 ^AFAA    BEQ     :SC2            ; BR STR B LEN = 0
AF97  28            PLP                     ; GET STR A COND CODE
AF98  F00D ^AFA7    BEQ     :SCLT           ; BR STR A LEN = 0
                ;
AF9A  A000          LDY     #0              ; COMPARE A BYTE
AF9C  B1D4          LDA     [FR0-2+EVSADR],Y ; OF STRING A
AF9E  D1E0          CMP     [FR1-2+EVSADR],Y ; TO STRING B
AFA0  F00C ^AFAE    BEQ     :SC3            ; BR IF SAME
AFA2  9003 ^AFA7    BCC     :SCLT           ; BR IF A<B
                ;
AFA4  A901      :SCGT  LDA      #1          ; A>B
AFA6  60           RTS
                ;
AFA7            :SCLT  LDA      #$80        ; A<B
AFA9  60            RTS
                ;
AFAA  28        :SC2    PLP                 ; IF STR A LEN NOT
AFAB  D0F7 ^AFA4    BNE     :SCGT           ; ZERO THEN A>B
AFAD  60        :SCEQ   RTS                 ; ELSE A=B
AFAE  E6D4      :SC3    INC     FR0-2+EVSADR    ; INC STR A ADR
AFB0  D002 ^AFB4    BNE     :SC4
AFB2  E6D5          INC     FR0-1+EVSADR
AFB4  E6E0      :SC4    INC     FR1-2+EVSADR    ; INC STR B ADR
AFB6  D0D2 ^AF8A    BNE     :SC1
AFB8  E6E1          INC     FR1-1+EVSADR
AFBA  D0CE ^AF8A    BNE     :SC1

;ZPADEC-Decrement a Zero-Page Double Word

AFBC            ZPADEC
AFBC  B500          LDA     0,X             ; GET LOW BYTE
AFBE  D006 ^AFC6    BNE     :ZPAD1          ; BR NOT ZERO
AFC0  B501          LDA     1,X             ; GET HI BYTE
AFC2  F005 ^AFC9    BEQ     :ZPADR          ; BR IF ZERO
AFC4  D601          DEC     1,X             ; DEC HIGH BYTE
AFC6  D600      :ZPAD1  DEC     0,X         ; DEC LOW BYTE
AFC8  A8            TAY                     ; SET NE COND CODE
AFC9  60        :ZPADR  RTS                 ; RETURN

;                            Functions

;XPLEN-Length Function

AFCA            XPLEN
AFCA  2098AB        JSR     AAPSTR          ; POP STRING WITH ABS ADR
AFCD  A5D6          LDA     VTYPE+EVSLEN    ; MOVE LENGTH
AFCF  A4D7          LDY     VTYPE+EVSLEN+1
AFD1            XPIFP
AFD1  85D4          STA     FR0             ; TO TOP OF FR0
AFD3  84D5          STY     FR0+1
AFD5  20AAD9    XPIFP1  JSR     CVIFP       ; AND CONVERT TO FP
AFD8            XPIFP2
                ;
AFD8  A900          LDA     #0              ; CLEAR
AFDA  85D2          STA     VTYPE           ; TYPE AND
AFDC  85D3          STA     VNUM            ; NUMBER
AFDE  4CBAAB        JMP     ARGPUSH         ; PUSH TO STACK AND RETURN

;XPPEEK-Peek Function

AFE1            XPPEEK
AFE1  20E3AB        JSR     GTINTO          ; GET INT ARG
AFE4  A000          LDY     #0
AFE6  B1D4          LDA     [FR0],Y         ; GET MEM BYTE
AFE8  4CD1AF        JMP     XPIFP           ; GO PUSH AS FP

;----------203

;XPFRE-FRE Function

AFEB            XPFRE
AFEB  20F2AB        JSR     ARGPOP          ; POP DUMMY ARG
AFEE  38            SEC
AFEF  ADE502        LDA     HIMEM           ; NO FREE BYTES
AFF2  E590          SBC     MEMTOP          ; = HIMEM-MEMTOP
AFF4  85D4          STA     FR0
AFF6  ADE602        LDA     HIMEM+1
AFF9  E591          SBC     MEMTOP+1
AFFB  85D5          STA     FR0+1
AFFD  4CD5AF        JMP     XPIFP1          ; GO PUSH AS FP

;XPVAL-VAL Function

B000            XPVAL
B000  2079BD        JSR     SETSEOL         ; PUT EOL AT STR END
                ;
B003  A900          LDA     #0              ; GET NUMERIC TERMINATOR
B005  85F2          STA     CIX             ; SET INDEX INTO BUFFER = 0
B007  2000D8        JSR     CVAFP           ; CONVERT TO F.P.

;Restore Character

B00A  2099BD        JSR     RSTEOL          ; RESET END OF STR
                ;
B00D  90C9 ^AFD8    BCC     XPIFP2
                ;
                ;
B00F            :VERR
B00F 201CB9         JSR     ERSVAL

;XPASC-ASC Function

B012            XPASC
B012  2098AB        JSR     AAPSTR          ; GET STRING ELEMENT

;Get1 > T Byte of String

B015  A000          LDY     #0              ; GET INDEX TO 1ST BYTE
B017  B1D4          LDA     [FR0-2+EVSADR],Y ; GET BYTE
                ;
B019  4CD1AF        JMP     XPIFP
                ;
                ;
B01C            XPADR
B01C  2098AB        JSR     AAPSTR          ; GET STRING
B01F  4CD5AF        JMP     XPIFP           ; FINISH

;XPPDL-Function Paddle

B022            XPPDL
B022  A900          LDA     #0              ; GET DISPL FROM BASE ADDR
B024  F00A ^B030    BEQ     :GRF

;XPSTICK-Function Joystick

B026            XPSTICK
B026  A908          LDA     #8              ; GET DISP FROM BASE ADDR
B028  D006 ^B030    BNE     :GRF

;XPPTRIG-Function Paddle Trigger

B02A            XPPTRIG
B02A  A90C          LDA     #$0C            ; GET DISPL FROM BASE ADDR
B02C  D002 ^B030    BNE     :GRF

;XPSTRIG-Function Joystick Trigger

B02E            XPSTRIG
B02E  A914          LDA     #$14            ; GET DISPL FROM BASE ADDR
                ;

;----------204

B030            :GRF
B030  48            PHA
B031  20E3AB        JSR     GTINTO          ; GET INTEGER FROM STACK
B034  A5D5          LDA     FR0+1           ; HIGH ORDER BYTE
B036  D00E ^B046    BNE     :ERGRF          ; SHOULD BE =0
B038  A5D4          LDA     FR0             ; GET #
                ;
B03A  68            PLA                     ; GET DISPL FROM BASE
B03B  18            CLC
B03C  65D4          ADC     FR0             ; ADD MORE DISPL
B03E  AA            TAX
                ;
B03F  BD7002        LDA     GRFBAS,X        ; GET VALUE
B042  A000          LDY     #0
B044  F08B ^AFD1    BEQ     XPIFP           ; GO CONVERT & PUSH ON STACK
                ;
                ;;
                ;
B046            :ERGRF
B046  203AB9        JSR     ERVAL

;XPSTR-STR Function

B049            XPSTR
B049  20F2AB        JSR     ARGPOP          ; GET VALUE IN FR0
                ;
B04C  20E6D8        JSR     CVFASC          ; CONVERT TO ASCII

;Build String Element

B04F  A5F3          LDA     INBUFF          ; SET ADDR
B051  85D4          STA     FR0-2+EVSADR ;
B053  A5F4          LDA     INBUFF+1
B055  85D5          STA     FR0-1+EVSADR

;Get Length

B057  A0FF          LDY     #$FF            ; INIT FOR LENGTH COUNTER
B059            :XSTR1
B059  C8            INY                     ; BUMP COUNT
B05A  B1F3          LDA     [INBUFF],Y      ; GET CHAR
B05C  10FB ^B059    BPL     :XSTR1          ; IS MSB NOT ON, REPEAT
B05E  297F          AND     #$7F            ; TURN OFF MSB
B060  91F3          STA     [INBUFF],Y      ; RETURN CHAR TO BUFFER
B062  C8            INY                     ; INC TO GET LENGTH
                ;
B063  84D6          STY     FR0-2+EVSLEN    ; SET LENGTH LOW
                ;
B065  D017 ^B07E    BNE     :CHR            ; JOIN CHR FUNCTION

;XPCHR-CHR Function

B067            XPCHR
B067  20F2AB        JSR     ARGPOP          ; GET VALUE IN FR0
                ;
B06A  2056AD        JSR     CVFPI           ; CONVERT TO INTEGER
B06D  A5D4          LDA     FR0             ; GET INTEGER LOW
B06F  8DC005        STA     LBUFF+$40       ; SAVE

;Build String Element

B072  A905          LDA     #(LBUFF+$40)/256  ; SET ADDR
B074  85D5  85D5    STA     FR0-1+EVSADR    ; X
B067  A9C0          LDA     #(LBUFF+$40)&255  ; X
B078  85D4          STA     FR0-2+EVSADR    ; X
                ;
B07A  A901          LDA     #1              ; SET LENGTH LOW
B07C  85D6          STA     FR0-2+EVSLEN    ; X
B07E            :CHR
B07E  A900          LDA     #0              ; SET LENGTH HIGH
B080  85D7          STA     FR0-1+EVSLEN    ; X
                ;

;----------205

B082  85D3          STA     VNUM            ; CLEAR VARIABLE #
B084  A983          LDA     #EVSTR+EVSDATA+EVDIM  ; GET TYPE FLAG
B086  85D2          STA     VTYPE           ; SET VARIABLE TYPE
                ;
B088  4CBAAB        JMP     ARGPUSH         ; PUSH ON STACK

;XPRND-RND Function

B08B            XPRND
B08B  A2A8          LDX     #RNDDIV&255     ; POINT TO 65535
B08D  A0B0          LDY     #RNDDIV/256     ; X
B08F  2098DD        JSR     FLD1R           ;MOVE IT TO FR1
                ;
B092  20F2AB        JSR     ARGPOP          ; CLEAR DUMMY FLAG
                ;
B095  AC0AD2        LDY     RNDLOC          ; GET 2 BYTE RANDOM #
B098  84D4          STY     FR0             ; X
B09A  AC0AD2        LDY     RNDLOC          ; X
B09D  84D5          STY     FR0+1           ; X
B09F  20AAD9        JSR     CV1FP           ; CONVERT TO INTEGER
B0A2  204DAD        JSR     PRDIV           ;DO DIVIDE
                ;
B0A5  4CBAAB        JMP     ARGPUSH         ; PUT IT ON STACK
                ;
                ;
                ;
B0A8  4206553600 RNDDIV  DB     $42,$06,$55,$36,0,0
      00

;XPABS-Absolute Value Function

B0AE            XPABS
B0AE  20F2AB        JSR     ARGPOP          ;GET ARGUMENT
B0B1  A5D4          LDA     FR0             ;GET BYTE WITH SIGN
B0B3  297F          AND     #$7F            ;AND OUT SIGN
B0B5  85D4          STA     FR0             ;SAVE
B0B7  4CBAAB        JMP     ARGPUSH         ;PUSH ON STACK


;XPUSR-USR Function

B0BA            XPUSR
B0BA  20C3B0        JSR     :USR            ;PUT RETURN ADDR IN CPU STACK
B0BD  20AAD9        JSR     CVIFP           ; CONVERT FR0 TO FP
B0C0  4CBAAB        JMP     ARGPUSH         ; PUSH ON STACK
                ;
                ;
                ;
B0C3            :USR
B0C3  A5B0          LDA     COMCNT          ;GET COMMA COUNT
B0C5  85C6          STA     ZTEMP2          ;SET AS # OF ARG FOR LOOP
                                             CONTROL
B0C7            :USR1
B0C7  20E3AB        JSR     GTINTO          ; GET AN INTEGER FROM OP STACK
B0CA  C6C6          DEC     ZTEMP2          ;DECR # OF ARGUMENTS
B0CC  3009 ^B0D7    BMI     :USR2           ;IF DONE THEM ALL, BRANCH
                ;
B0CE  A5D4          LDA     FR0             ;GET ARGUMENT LOW
B0D0  48            PHA                     ;PUSH ON STACK
B0D1  A5D5          LDA     FR0+1           ;GET ARGUMENT HIGH
B0D3  48            PHA                     ;PUSH ON STACK
B0D4  4CC7B0        JMP     :USR1           ;GET NEXT ARGUMENT
B0D7            :USR2
B0D7  A5B0          LDA     COMCNT          ;GET # OF ARGUMENTS
B0D9  48            PHA                     ;PUSH ON CPU STACK
B0DA  6CD400        JMP     [FR0]           ;GO TO USER ROUTINE

;XPINT

B0DD            XPINT
B0DD  20F2AB        JSR     ARGPOP          ; GET NUMBER
B0E0  20E6B0        JSR     XINT            ; GET INTEGER
B0E3  4CBAAB        JMP     ARGPUSH         ; PUSH ON ARGUMENT STACK

;----------206

;XINT-Take Integer Part of FR0

B0E6            XINT
B0E6  A5D4          LDA     FR0             ; GET EXPONENT
B0E8  297F          AND     #$7F            ; AND OUT SIGN BIT
B0EA  38            SEC
B0EB  E93F          SBC     #$3F            ; GET LOCATION OF 1ST FRACTION
                                              BYTE
B0ED  1002 ^B0F1    BPL     :XINT1          ; IF > OR = 0, THEN BRANCH
B0EF  A900          LDA     #0              ; ELSE SET =0
                ;
B0F1            :XINT1
B0F1  AA            TAX                     ; PUT IN X AS INDEX INTO FR0
B0F2  A900          LDA     #0              ; SET ACCUM TO ZERO FOR ORING
B0F4  A8            TAY                     ; ZERO Y
B0F5            :INT2
B0F5  E005          CPX     #FMPREC         ; IS D.P. LOC > OF = 5?
B0F7  B007 ^B100    BCS     :XINT3          ; IF YES, LOOP DONE
B0F9  15D5          ORA     FR0M,X          ; OR IN THE BYTE
B0FB  94D5          STY     FR0M,X          ; ZERO BYTE
B0FD  E8            INX                     ; POINT TO NEXT BYTE
B0FE  D0F5 ^B0F5    BNE     :INT2           ; UNCONDITIONAL BRANCH
                ;
B100            :XINT3
B100  A6D4          LDX     FR0             ; GET EXPONENT
B102  1014 ^B118    BPL     :XINT4          ; BR IF # IS PLUS
B104  AA            TAX                     ; GET TOTAL OF ORED BYTES &
                                              SET CC
B105  F011 ^B118    BEQ     :XINT4          ; IF ALL BYTES WERE ZERO
                                              BRANCH
                ;
                ;        #IS NEGATIVE AND NOT A WHOLE # [ADD -1]
B107  A2E0          LDX     #FR1
B109  2046DA        JSR     ZF1             ; ZERO FR1
B10C  A9C0          LDA     #$C0            ; PUT -1 IN FR1
B10E  85E0          STA     FR1             ; X
B110  A901          LDA     #1              ; X
B112  85E1          STA     FR1+1           ; X
B114  203BAD        JSR     FRADD           ; ADD IT
B117  60            RTS
B118            :XINT4
B118  4C00DC        JMP     NORM            ; GO NORMALIZE

;                     Transcendental Functions

;XPSIN-Sine Function

B11B            XPSIN
B11B  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B11E  20A7BD        JSR     SIN
B121  B03F ^B162    BCS     :TBAD
B123  903A ^B15F    BCC     :TGOOD

;XPCOS-Cosine Function

B125            XPCOS
B125  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B128  20B1BD        JSR     COS
B12B  B035 ^B162    BCS     :TBAD
B12D  9030 ^B15F    BCC     :TGOOD

;XPATN-Arc Tangent Function

B12F            XPATN
B12F  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B132  2077BE        JSR     ATAN
B135  B02B ^B162    BCS     :TBAD
B137  9026 ^B15F    BCC     :TGOOD

;----------207

;XPLOG-LOG Function

B139            XPLOG
B139  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B13C  20CDDE        JSR     LOG
B13F  B021 ^B162    BCS     :TBAD
B141  901C ^B15F    BCC     :TGOOD

;XPL10-LOG Base Function

B143            XPL10
B143  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B146  20D1DE        JSR     LOG10
B149  B017 ^B162    BCS     :TBAD
B14B  9012 ^B15F    BCC     :TGOOD

;XPEXP-EXP Function

B14D            XPEXP
B14D  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B150  20C0DD        JSR     EXP
B153  B00D ^B162    BCS     :TBAD
B155  9008 ^B15F    BCC     :TGOOD

;XPSQR-Square Root Function

B157            XPSQR
B157  20F2AB        JSR     ARGPOP          ; GET ARGUMENT
B15A  20E5BE        JSR     SQR
B15D  B003 ^B162    BCS     :TBAD
                ;
                ;       FALL THREE TO :TGOOD
B15F            :TGOOD
B15F 4CBAAB         JMP     ARGPUSH         ; PUSH ARGUMENT ON STACK
                ;
                ;
B162            :TBAD
B162  203AB9        JSR     ERVAL

;ZPPOWER-Exponential Operator[A**B]

B165            XPPOWER
B165  2006AC        JSR     ARGP2           ;GET ARGUMENT IN FR0,FR1
B168  A5D4          LDA     FR0             ;IS BASE = 0
B16A  D00B ^B177    BNE     :N0             ;IF BASE NOT 0, BRANCH
B16C  A5E0          LDA     FR1             ;TEST EXPONENT
B16E  F004 ^B174    BEQ     :P0             ;IF = 0 ; BRANCH
B170  10ED ^B15F    BPL     :TGOOD          ;IF >0, ANSWER = 0
B172  30EE ^B162    BMI     :TBAD           ;IF <0, VALUE ERROR
B174            :P0
B174  4C05AD        JMP     XTRUE           ;IF =0, ANSWER = 1
B177            :N0
                ;
B177  1030 ^B1A9    BPL     :SPEVEN         ; IF BASE + THEN NO SPECIAL
                                              PROCESS
B179  297F          AND     #$7F            ; AND OUT SIGN BIT
B17B  85D4          STA     FR0             ; SET AS BASE EXPONENT
                ;
B17D  A5E0          LDA     FR1             ; GET EXPONENT OF POWER
B17F  297F          AND     #$7F            ; AND OUT SIGN BIT
B181  38            SEC
B182  E940          SBC     #$40            ; IS POWER <1?
B184  30DC ^B162    BMI     :TBAD           ; IF YES, ERROR
                ;
B186  A206          LDX     #6              ; GET INDEX TO LAST DIGIT
                ;
B188  C905          CMP     #5              ; IF # CAN HAVE DECIMAL
B18A  9004 ^B190    BCC     :SP4            ; PORTION, THEN BR
B18C  A001          LDY     #1
B18E  D008 ^B198    BNE     :SP3
B190            :SP4
                ;
B190  85F5          STA     ZTEMP1          ; SAVE EXP -40

;----------208

B192  38            SEC
B193  A905          LDA     #5              ;GET # OF BYTES POSSIBLE
B195  E5F5          SBC     ZTEMP1          ; GET # BYTES THAT COULD BE
                                              DECIMAL
B197  A8            TAY                     ; SET COUNTER
                ;
B198            :SP3
B198  CA            DEX
B199  88            DEY                     ; DEC COUNTER
B19A  F006 ^B1A2    BEQ     :SP2            ; IF DONE GO TEST EVEN/ODD
B19C  B5E0          LDA     FR1,X           ;GET BYTE OF EXPONENT
B19E  D0C2 ^B162    BNE     :TBAD           ; IF NOT =0, THEN VALUE ERROR
B1A0  F0F6 ^B198    BEQ     :SP3            ; REPEAT
                ;
B1A2            :SP2
B1A2  A080          LDY     #$80            ; GET ODD FLAG
B1A4  B5E0          LDA     FR1,X           ;GET BYTE OF EXPONENT
B1A6                LSRA                    ; IS IT ODD[LAST BIT OFF]?
B1A6 +4A            LSR     A
B1A7  B002 ^B1AB    BCS     :POWR           ; IF YES, BR
                ;
B1A9            :SPEVEN
B1A9 A000           LDY     #0
B1AB            :POWR
B1AB  98            TYA
B1AC  48            PHA

;Save Exponent [from FR1]

B1AD  A205          LDX     #FMPREC         ;GET POINTER INTO FR1
B1AF            :POWR1
B1AF  B5E0          LDA     FR1,X           ; GET A BYTE
B1B1  48            PHA                     ;PUSH ON CPU STACK
B1B2  CA            DEX                     :POINT TO NEXT BYTE
B1B3  10FA ^B1AF    BPL     :POWR1          ;BR IF MORE TO DO
                ;
B1B5  20D1DE        JSR     LOG10           ;TAKE LOG OF BASE
B1B8  B0A8 ^B162    BCS     :TBAD

;Pull Exponent into FR1 [from CPU Stack]

B1BA  A200          LDX     #0              ;GET POINTER INTO FR1
B1BC  A005          LDY     #FMPREC         ;SET COUNTER
B1BE            :POWR2
B1BE  68            PLA
B1BF  95E0          STA     FR1,X           ;PUT IN FR1
B1C1  E8            INX                     ;INCR POINTER
B1C2  88            DEY                     ;DEC COUNTER
B1C3  10F9 ^B1BE    BPL     :POWR2          ;BR IF MORE TO DO
                ;
B1C5  2047AD        JSR     FRMUL           ;GET LOG OF NUMBER
B1C8  20CCDD        JSR     EXP10           ;GET NUMBER
B1CB  B009 ^B1D6    BCS     :EROV
                ;
B1CD  68            PLA                     ; GET EVEN/ODD FLAG
B1CE  108F ^B15F    BPL     :TGOOD          ; IF EVEN, GO PUT ON STACK
                ;
B1D0  05D4          ORA     FR0             ; IF ODD MAKE ANSWER-
B1D2  85D4          STA     FR0             ; X
B1D4  D089 ^B15F    BNE     :TGOOD          ; PUSH ON STACK
                ;
B1D6            :EROV
B1D6  202AB9        JSR     EROVFL

;----------209

;                        Statements

;XDIM & XCOM - Execute DIM and COMMON Statements

B1D9            XDIM
B1D9            XCOM
                ;
B1D9  A4A8      :DC1    LDY     STINDEX     ; IF NOT AT
B1DB  C4A7          CPY     NXTSTD          ; STATEMENT END
B1DD  9001 ^B1E0    BCC     :DC2            ; THEN CONTINUE
B1DF  60            RTS                     ; RETURN
B1E0  20E0AA    :DC2    JSR     EXEXPR      ; GO SET UP VIA EXECUTE EXPR
B1E3  A5D2          LDA     VTYPE           ; GET VAR TYPE
B1E5                RORA                    ; SHIFT DIM BIT TO CARRY
B1E5 +6A            ROR     A
B1E6  9003 ^B1EB    BCC     :DC3            ; CONTINUE IF NOT YET DIMMED
B1E8  202EB9    :DCERR  JSR     ERRDIM      ; ELSE ERROR
                ;
B1EB  38        :DC3    SEC                 ; TURN ON
B1EC                ROLA                    ; DIM FLAG
B1EC +2A            ROL     A
B1ED 85D2           STA     VTYPE           ; AND RESET
B1EF  302F ^B220    BMI     :DCSTR          ; AND BR IF STRING
                ;
B1F1  A4F5          LDY     ZTEMP1          ; INCI1 BY 1
B1F3  A6F6          LDX     ZTEMP1+1        ; AND SET AS DIM1
B1F5  C8            INY
B1F6  D003 ^B1FB    BNE     :DC4
B1F8  E8            INX
B1F9  30ED ^B1E8    BMI     :DCERR          ; BR IF OUT OF BOUNDS
B1FB  84D6      :DC4    STY     VTYPE+EVAD1
B1FD  86D7          STX     VTYPE+EVAD1+1
B1FF  84F5          STY     ZTEMP1          ; ALSO PUT BACK ONTO
B201  86F6          STX     ZTEMP1+1        ; INDEX 1 FOR MULT
                ;
B203  A497          LDY     INDEX2          ; INC INDEX 2 BY 1
B205  A698          LDX     INDEX2+1        ; AND SET AS DIM 2
B207  C8            INY
B208  D003 ^B20D    BNE     :DC5
B20A  E8            INX
B20B  30DB ^B1E8    BMI     :DCERR          ; BR IF OUT OF BOUNDS
B20D  84D8      :DC5    STY     VTYPE+EVAD2
B20F  86D9          STX     VTYPE+EVAD2+1
                ;
B211  205DAF        JSR     AMUL1           ; ZTEMP1 = ZTEMP1*D2
B214  2046AF        JSR     AMUL2           ; ZTEMP1 = ZTEMP1*6
                                                  RESULT IS AN ARRAY
                                                  SPACE REQD
B217  A4F5          LDY     ZTEMP1          ; A,Y = LENGTH
B219  A5F6          LDA     ZTEMP1+1
B21B  30CB ^B1E8    BMI     :DCERR
B21D  4C34B2        JMP     :DCEXP          ; GO EXPAND
                ;
B220            :DCSTR
B220  A900          LDA     #0              ; SET CURRENT LENGTH =0
B222  85D6          STA     EVSLEN+VTYPE
B224  85D7          STA     EVSLEN+1+VTYPE
                ;
B226  A4F5          LDY     ZTEMP1          ; MOVE INDEX
B228  84D8          STY     VTYPE+EVSDIM    ; TO STR DIM
B22A  A5F6          LDA     ZTEMP1+1        ; [ALSO LOAD A,Y]
B22C  85D9          STA     VTYPE+EVSDIM+1  ; FOR EXPAND
B22E  D004 ^B234    BNE     :DCEXP          ; INSURE DIM
B230  C000          CPY     #0              ; NOT ZERO
B232  F0B4 ^B1E8    BEQ     :DCERR          ; FOR STRING
                ;
B234            :DCEXP
B234  A38E          LDX     #ENDSTAR        ; POINT TO END ST & ARRAY
                                              SPACE
B236  2081A8        JSR     EXPAND          ; GO EXPAND
                ;

;----------210

B239  38            SEC
B23A  A597          LDA     SVESA           ; CALCULATE DISPL INTO
B23C  E58C          SBC     STARP           ; ST/ARRAY SPACE
B23E  85D4          STA     VTYPE+EVSADR    ; AND PUT INTO VALUE BOX
B240  A598          LDA     SVESA+1
B242  E58D          SBC     STARP+1
B244  85D5          STA     VTYPE+EVSADR+1
                ;
B246  2016AC        JSR     RTNVAR          ; RETURN TO VAR VALUE TABLE
B249  4CD9B1        JMP     :DC1            ; AND GO FOR NEXT ONE

;XPOKE - Execute POKE

B24C            XPOKE
B24C  20E0AB        JSR     GETINT          ; GET INTEGER ADDR
B24F  A5D4          LDA     FR0             ; SAVE POKE ADDR
B251  8595          STA     POKADR          ;
B253  A5D5          LDA     FR0+1           ;
B255  8596          STA     POKADR+1        ;
                ;
B257  20E9AB        JSR     GET1INT         ; GET 1 BYTE INTEGER TO POKE
                ;
B25A  A5D4          LDA     FR0             ; GET INTEGER TO POKE
B25C  A000          LDY     #0              ; GET INDEX
B25E  9195          STA     [POKADR],Y      ;GET INDEX
B260  60            RTS

;XDEG - Execute DEG

B261            XDEG
B261  A906          LDA     #DEGON          ; GET DEGREES FLAG
B263  85FB          STA     RADFLG          ; SET FOR TRANSCENDENTALS
B265  60            RTS

;XDEG - Execute DEG

B266            XDEG
B266  A900          LDA     #DEGON          ; GET RADIAN FLAG
B268  85FB          STA     RADFLG          ; SET FOR TRANSCENDENTALS
B26A  60            RTS

;XREST - Execute RESTORE Statement

B26B            XREST
B26B  A900          LDA     #0              ; ZERO DATA DISPL
B26D  85B6          STA     DATAD
                ;
B26F  2010B9        JSR     TSTEND          ; TEST END OF STMT
B272  9003 ^B227    BCC     :XR1            ; BR IF NOT END
B274  A8            TAY                     ; RESTORE TO LN=0
B275  F007 ^B27E    BEQ     :XR2
                ;
B277  20D5AB    :XR1    JSR     GETINT      ; GET LINE NO.
                ;
B27A  A5D5          LDA     FR0+1           ; LOAD LINE NO.
B27C  A4D4          LDY     FR0
                ;
B27E  84B8      :XR2    STA     DATALN+1    : SET LINE
B280  84B7          STY     DATALN
B282  60            RTS                     ; DONE

;XREAD - Execute READ Statement

B283            XREAD
B283  A5A8          LDA     STINDEX         ; SAVE STINDEX
B285  48            PHA
B286  20C7B6        JSR     XGS             ; SAVE READ STMT VIA GOSUB
                ;
B289  A5B7          LDA     DATALN          ; MOVE DATALN TO TSLNUM
B28B  85A0          STA     TSLNUM
B28D  A5B8          LDA     DATALN+1
B28F  85A1          STA     TSLNUM=1

;----------211

B291  20A2A9        JSR     GETSTMT         ; GO FIND TSLNUM
                ;
B294  A58A          LDA     STMCUR          ; MOVE STMCUR TO INBUFF
B296  85F3          STA     INBUFF
B298  A58B          LDA     STMCUR+1
B29A  85F4          STA     INBUFF+1
                ;
B29C  2019B7        JSR     XRTN            ; RETURN READ STMT VIA RETURN
B29F  68            PLA                     ; GET SAVED STINDEX
B2A0  84A8          STA     STINDEX         ; SET IT
                ;
B2A2            :XRD1
B2A2  A000          LDY     #0              ; SET CIX=0
B2A4  84F2          STY     CIX             ; SET CIX
B2A6  2007B3        JSR     :XRTN1          ; GET LINE NO. LOW
B2A9  85B7          STA     DATALN          ; SET LINE NO. LOW
B2AB  2005B3        JSR     :XRNT
B2AE  85B8          STA     DATALN+1        ; SET LINE NO. HIGH
B2B0  2005B3        JSR     :XRNT
B2B3  85F5          STA     ZTEMP1          ; SET LINE LENGTH
B2B5            :XRD2
B2B5  2005B3        JSR     :XRNT
B2B8  85F6          STA     ZTEMP+1         ; SET STMT LENGTH
                ;
B2BA  2005B3        JSR     :XRNT           ; GET STMT LINE TOKEN
B2BD  C901          CMP     #CDATA          ; IS IT DATA
B2BF  F026 ^B2E7    BEQ     :XRD4           ; BR IF DATA
                ;
B2C1  A4F6          LDY     ZTEMP1+1        ; GET DISPL TO NEXT STMT
B2C3  C4F5          CPY     ZTEMP1          ; IS IT EOL
B2C5  B005 ^B2CC    BCS     :XRD2A          ; BR IF EOL
B2C7  88            DEY
B2C8  84F2          STY     CIX             ; SET NEW DISPL
B2CA  90E9 ^B2B5    BCC     :XRD2           ; AND CONTINUE THIS STMT
                ;
B2CC  84F2      :XRD2A  STY     CIX
B2CE  C6F2          DEC     CIX
                ;
B2D0  A001      :XRD3   LDY     #1          ; WAS THIS STMT THE
B2D2  B1F3          LDA     [INBUFF],Y      ; DIRECT ONE
B2D4  303D ^B313    BMI     :XROOD          ; BR IF IT WAS [OUT OF DATA]
B2D6  38            SEC
B2D7  A5F2          LDA     CIX             ; INBUFF + CIX + 1
B2D9  65F3          ADC     INBUFF          ; = ADR NEXT PGM LINE
B2DB  85F3          STA     INBUFF
B2DD  A900          LDA     #0
B2DF  85B6          STA     DATAD
B2E1  65F4          ADC     INBUFF+1
B2E3  85F4          STA     INBUFF+1
B2E5  90BB ^B2A2    BCC     :XRD1           ; GO SCANTHIS NEXT LINE
                ;
B2E7            :XRD4
B2E7  A900          LDA     #0              ; CLEAR ELEMENT COUNT
B2E9  85F5          STA     ZTEMP1
                ;
B2EB            :XRD5
B2EB  A5F5          LDA     ZTEMP1          ; GET ELEMENT COUNT
B2ED  C5B6          CMP     DATAD           ; AT PROPER ELEMENT
B2EF  B00B ^B2FC    BCS     :XRD7           ; BR IF AT
                ;                                 ELSE SCAN FOR NEXT
B2F1  2005B3    :XRD6   JSR     :XRNT       ; GET CHAR
B2F4  D0FB ^B2F1    BNE     :XRD6           ; BR IF NOT CR OR COMMA
B2F6  B0D8 ^B2D0    BCS     :XRD3           ; BR IF CR
B2F8  E6F5          INC     ZTEMP1          ; INC ELEMENT COUNT
B2FA  D0EF ^B2EB    BNE     :XRD5           ; AND GO NEXT
                ;
B2FC  A940      :XRD7   LDA     #$40        ; SET READ BIT
B2FE  85A6          STA     DIRFLAG
B300  E6F2          INC     CIX             ; INC OVER DATA TOKEN

;----------212

B302  4C35B3        JMP     :XINA           ; GO DO IT
                ;
                ;
B305            :XRNT
B305  E6F2          INC     CIX             ; INC INDEX
B307  A4F2      :XRNT1  LDY     CIX         ; GET INDEX
B309  B1F3          LDA     [INBUFF],Y      ; GET CHAR COUNT
B30B  C92C          CMP     #$2C            ; IS IT A COMMA
B30D  18            CLC                     ; CARRY CLEAR FOR COMMA
B30E  F002 ^B312    BEQ     :XRNT2          ; BR IF COMMA
B310  C99B          CMP     #CR             ; IS IT CR
B312  60        :XRNT2  RTS
                ;
B313  2034B9    :XROOD  JSR     ERROOD

;XINPUT - Execute INPUT

B316  A93F          LDA     #'?'            ; SET PROMPT CHAR
B318  85C2          STA     PROMPT
B31A  203EAB        JSR     GETTOK          ; GET FIRST TOKEN
B31D  C6A8          DEC     STINDEX         ; BACK UP OVER IT
B31F  9005 ^B326    BCC     :XIN0           ; BR IF NOT OPERATOR
B321  2002BD        JSR     GIOPRM          ; GO GET DEVICE NUM
B324  85B4          STA     ENTDTD          ; SET DEVICE NO.
                ;
B326            :XIN0
B326  2051DA        JSR     INTLBF
B329  2089BA        JSR     GLINE           ; GO GET INPUT LINE
B32C  204EB3        JSR     :XITB           ; TEST BREAK
B32F  A000          LDY     #0
B331  84A6          STY     DIRFLG          ; SET INPUT MODE
B333  84F2          STY     CIX             ; SET CIX=0
B335            :XINA
B335  203EAB        JSR     GETTOK          ; GO GET TOKEN
B338  E6A8          INC     STINDEX         ; INC OVER TOKEN
                ;
B33A  A5D2          LDA     VTYPE           ; IS A STR
                ;
B33E  2000D8        JSR     CVAFP           ; CONVERT TO FP
B341  B014 ^B357    BCS     :XIERR
B343  2007B3        JSR     :XRNT1          ; GET END TOKEN
B346  D00F ^B357    BNE     :XIERR          ; ERROR IF NO CR OR COMMA
B348  2016AC        JSR     RTNVAR          ; RETURN VAR
B34B  4C89B3        JMP     :XINX           ; GO FIGURE OUT WHAT TO DO
                                              NEXT
B34E  20F4A9    :XITB   JSR    TSTBRK       ; GO TEST BREAK
B351  D001 ^B354    BNE     XITBT           ; BR IF BRK
B353  60            RTS                     ; DONE
B354  4C93B7    XITBT   JMP    XSTOP        ; STOP
B357  A900      :XIERR  LDA    #0           ; RESET
B359  85B4          STA     ENTDTD          ; ENTER DVC
B35B  2030B9        JSR     ERRINP          ; GO ERROR
                ;
B35E            :XISTR
B35E  202EAB        JSR     EXPINT          ; INIT EXECUTE EXPR
B361  20BAAB        JSR     ARGPUSH         ; PUSH THE STRING
B364  C6F2          DEC     CIX             ; DEC CIX TO CHAR
B366  A5F2          LDA     CIX             ; BEFORE SOS
B368  85F5          STA     ZTEMP1          ; SAVE THAT CIX
B36A  A2FF          LDX     #$FF            ; SET CHAR COUNT = -1
                ;
B36C  E8        :XIS1   INX                 ; INC CHAR COUNT
B36D  2005B3        JSR     :XRNT           ; GET NEXT CHAR
B370  D0FA ^B36C    BNE     :XIS1           ; BR NOT CR OR COMMA
B372  B004 ^B378    BCS     :XIS2           ; BR IF CR
B374  24A6          BIT     DIRFLAG         ; IS IT COMMA, IF NOT READ
B376  50F4 ^B36C    BVC     :XIS1           ; THEN CONTINUE

;----------213

                ;
B378  A4F5      :XIS2   LDY     ZTEMP1      ; GET SAVED INDEX
B37A  A5A8          LDA     STINDEX         ; SAVE INDEX
B37C  48            PHA
B37D  8A            TXA                     ; ACU = CHAR COUNT
B37E  A2F3          LDX     #INBUFF         ; POINT TO INBUFF
B380  2064AB        JSR     RISC            ; GO MAKE STR VAR
B383  68            PLA
B384  85A8          STA     STINDEX         ; RESTORE INDEX
B386  20A6AE        JSR     RISASN          ; THEN DO STA ASSIGN
                ;
B389  24A6      :XINDEX   BIT   DIRFLG      ; IS THIS READ
B38B  50F ^B39C     BVC     :XIN            ; BR IF NOT
                ;
B38D  E6B6          INC     DATAD           ; INC DATA DISPL
B38F  2010B9        JSR     TSTEND          ; TEST END READ STMT
B392  B00D ^B3A1    BCS     :XIRTS          ; BR IF READ END
                ;
B394  2007B3    :XIR1   JSR     :XRNT1      ; GET END DATA CHAR
B397  9018 ^B3B1    BCC     :XINC           ; BR IF COMMA
B399  4CD0B2        JMP     :XRD3           ; GO GET NEXT DATA LINE
                ;
B39C            :XIN
B39C  2010B9        JSR     TSTEND
B39F  9008 ^B3A9    BCC     :XIN1
                ;
B3A1  2051DA    :XIRTS  JSR     INTLBF      ; RESTORE LBUFF
B3A4  A900          LDA     #0              ; RESTORE ENTER
B3A6  85B4          STA     ENTDTD          ; DEVICE TO ZERO
B3A8  60            RTS                     ; DONE
                ;
B3A9  2007B3    :XIN1   JSR     :XRNT1      ; IF NOT END OF DATA
B3AC  9003 ^B3B1    BCC     :XINC           ; THEN BRANCH
B3AE  4C26B3        JMP     :XIN0           ; AND CONTINUE
                ;
B3B1  E6F2      :XINC   INC     CIX         ; INC INDEX
B3B3  4C35B3        JMP     :XINA           ; AND CONTINUE

;XPRINT - Execute PRINT Statement

B3B6            XPRINT
B3B6  A5C9          LDA     PTABW           ; GET TAB VALUE
B3B8  85AF          STA     SCANT           ; SCANT
B3BA  A900          LDA     #0              ; SET OUT INDEX = 0
B3BC  8594          STA     COX
                ;
B3BE  A4A8      :XPR0   LDY    STINDEX      ; GET STMT DISPL
B3C0  B18A          LDA     [STMCUR],Y      ; GET TOKEN
                ;
B3C2  C912          CMP     #CCOM
B3C4  F053 ^B419    BEQ     :XPTAB          ; BR IF TAB
B3C6  C916          CMP     #CCR
B3C8  F07C ^B446    BEQ     :XPEOL          ; BR IF EOL
B3CA  C914          CMP     #CEOS
B3CC  F078 ^B446    BEQ     :XPEOL          ; BR IF EOL
B3CE  C915          CMP     #CSC
B3D0  F06F ^B441    BEQ     :XPNULL         ; BR IF NULL
B3D2  C91C          CMP     #CPND
B3D4  F061 ^B437    BEQ     :XPRIOD
                ;
B3D6  20E0AA        JSR     EXEXPR          ; GO EVALUATE EXPRESSION
B3D9  20F2AB        JSR     ARGPOP          ; POP FINAL VALUE
B3DC  C6A8          DEC     STINDEX         ; DEC STINDEX
B3DE  24D2          BIT     VTYPE           ; IS THIS A STRING
B3E0  3016 ^B3F8    BMI     :XPSTR          ; BR IF STRING
                ;
B3E2  20E6D8        JSR     CVFASC          ; CONVERT TO ASCII
B3E5  A900          LDA     #0
B3E7  85F2          STA     CIX
                ;
B3E9  A4F2      :XPR1   LDX     CIX         ; OUTPUT ASCII CHARACTERS

;----------214

B3EB  B1F3          LDA     [INBUFF],Y      ; FROM INBUFF
B3ED  48            PHA                     ; UNTIL THE CHAR
B3EE  E6F2          INC     CIX             ; WITH THE MSB ON
B3F0  205DB4        JSR     :XPRC           ; IS FOUND
B3F3  68            PLA
B3F4  10F3 ^B3E9    BPL     :XPR1
B3F6  30C6 ^B3BE    BMI     :XPR0           ; THEN GO FOR NEXT TOKEN
B3F8            ;XPSTR
B3F8  209BAB        JSR     GSTRAD          ; GO GET ABS STRING ARRAY
B3FB  A900          LDA     #0
B3FD  85F2          STA     CIX
B3FF  A5D6      :XPR2C  LDA     VTYPE+EVSLEN    ; IF LEN LOW
B401  D004 ^B407    BNE     :XPR2B          ; NOT ZERO BR
B403  C6D7          DEC     VTYPE+EVSLEN+1  ; DEC LEN HI
B405  30B7 ^B3BE    BMI     :XPR0           ; BR IF DONE
B407  C6D6      :XPR2B  DEC     VTYPE+EVSLEN    ; DEC LEN LOW
                ;
B409  A4F2      :XPR2   LDY     CIX         ; OUTPUT STRING CHARS
B40B  B1D4          LDA     [VTYPE+EVSADR],Y ; FOR THE LENGTH
B40D  E6F2          INC     CIX             ; OF THE STRING
B40F  D002 ^B413    BNE     :XPR2A
B411  E6D5          INC     VTYPE+EVSADR+1
B413            :XPR2A
B413  205FB4        JSR     :XPRC1
B416  4CFFB3        JMP     :XPR2C
                ;
B419            :XPTAB
B419  A494      :XPR3   LDY     COX         ; DO UNTIL COX+1 <SCANT
B41B  C8            INY
B41C  C4AF          CPY     SCANT
B41E  9009 ^B429    BCC     :XPR4
B420  18        :XPIC3  CLC
B421  A5C9          LDA     PTABW           ; SCANT = SCANT+TAB
B423  65AF          ADC     SCANT
B425  85AF          STA     SCANT
B427  90F0 ^B419    BCC     :XPR3
                ;
B429  A494      :XPR4   LDY     COX         ; DO UNTIL COX = SCANT
B42B  C4AF          CPY     SCANT
B42D  B012 ^B441    BCS     :XPR4A
B42F  A920          LDA     #$20            ; PRINT BLANKS
B431  205DB4        JSR     :XPRC
B434  4C29B4        JMP     :XPR4
                ;
B437  2002BD    :XPRIOD JSR     GIOPRM      ; GET DEVICE NO.
B43A  85B5          STA     LISTDTD         ; SET AS LIT DEVICE
B43C  C6A8          DEC     STINDEX         ;DEC INDEX
B43E  4CBEB3        JMP     :XPR0           ; GET NEXT TOKEN
                ;
B441            :XPR4A
B441  E6A8      :XPNULL INC     STINDEX     ; INC STINDEX
B443  4CBEB3        JMP     :XPR0
                ;
B446            :XPEOL
B446  A4A8      :XPEOS  LDY     STINDEX     ; AT END OF PRINT
B448  88            DEY
B449  B18A          LDA     [STMCUR],Y      ; IF PREV CHAR WAS
B44B  C915          CMP     #CSC            ; SEMI COLON THEN DONE
B44D  F009 ^B458    BEQ     :XPRTN          ; ELSE PRINT A CR
B44F  C912          CMP     #CCOM           ; OR A COMMA
B451  F005 ^B458    BEQ     :XPRTN          ; THEN DONE
B453  A99B          LDA     #CR
B445  205FB4        JSR     :XPRC1          ; THEN DONE
B458            :XPRTN
B458  A900          LDA     #0              ; SET PRIMARY
B45A  85B5          STA     LISTDTD         ; LIST DVC = 0
B45C  60            RTS                     ; AND RETURN
                ;
                ;
B45D  297F      :XPRC   AND     #$7F        ; MSB OFF
B45F  E694      :XPRC1  INC     COX         ; INC OUT INDEX

;----------215

B461  4C9FBA        JMP     PRCHAR          ; OUTPUT CHAR

;XLPRINT - Print to Printer

B464            XLPRINT
B464  A900          LDA     #PSTR&255       ; POINT TO FILE SPEC
B466  85F3          STA     INBUFF          ; X
B468  A984          LDA     #PSTR/256       ; X
B46A  85F4          STA     INBUFF+1        ; X
                ;
B46C  A207          LDX     #7              ; GET DEVICE
B46E  86B5          STX     LISTDTD         ; SET LIST DEVICE
B470  A900          LDA     #0              ; GET AUX 2
B472  A008          LDA     #8              ; GET OPEN TYPE
                ;
B474  20D1BB        JSR     SOPEN           ; DO OPEN
B477  20B3BC        JSR     IOTEST          ; TEST FOR ERROR
                ;
B47A  20B6B3        JSR     XPRINT          ; DO THE PRINT
B47D  4CF1BC        JMP     CLSYS1          ; CLOSE DEVICE
                ;
                ;
                ;
B480  50        PSTR    DB      'P'
B481  3A9B          DB      ':',CR

;XLIST - Execute LIST Command

B483            XLIST
B483  A000          LDY     #0              ;SET TABLE SEARCH LINE NO
B485  84A0          STY     TSLNUM          ;TO ZERO
B487  84A1          STY     TSLNUM+1
B489  88            DEY
B48A  84AD          STY     LELNUM          ; SET LIST END LINE NO
B48C  A97F          LDA     #$7F            ;TO $7FFF
B48E  85AE          STA     LELNUM+1
B490  8DFE02        STA     $2FE            ; SET NON-DISPLAY MODE
B493  A99B          LDA     #CR             ; POINT CR
B495  209FBA        JSR     PRCHAR
                ;
B498  20C7B6        JSR     XGS             ; SAVE CURLINE VIA GOSUB
B49B            :XL0
B49B  A4A8          LDY     STINDEX         ;GET STMT INDEX
B49D  C8            INY                     ;INC TO NEXT CHAR
B49E  C4A7          CPY     NXTSTD          ;RT NEXT STMT
B4A0  B02D ^B4CF    BCS     :LSTART         ; BR IF AT, NO PARMS
                ;
B4A2  A5A8          LDA     STINDEX         ; SAVE STINDEX
B4A4  48            PHA                     ; ON STACK
B4A5  200FAC        JSR     POP1            ; POP FIRST ARGUMENT
B4A8  68            PLA                     ; RESTORE STINDEX TO
B4A9  85A8          STA     STINDEX         ; RE-DO FIRST ARG
B4AB  A5D2          LDA     VTYPE           ; GET VAR TYPE
B4AD  1006 ^B4B5    BPL     :XL1            ; BR IF NOT FILE SPEC STRING
B4AF  20D5BA        JSR     FLIST           ; GO OPEN FILE
B4B2  4C9BB4        JMP     :XL0            ; GO BACK TO AS IF FIRST PARM
                ;
B4B5            :XL1
B4B5  20D5AB        JSR     GETPINT         ; GO GET START LNO
                ;
B4B8  85A1          STA     TSLNUM+1
B4BA  A5D4          LDA     FR0             ; MOVE START LNO
B4BC  85A0          STA     TSLNUM          ;TO TSLNUM
                ;
B4BE  A4A8          LDY     STINDEX         ;GET STMT INDEX
B4C0  C4A7          CPY     NXTSTD          ;AT NEXT STMT
B4C2  F003 ^B4C7    BEQ     :LSE            ; BR IF AT, NO PARMS
                ;

;----------216

B4C4  20D5AB        JSR     GETPINT         ; GO GET LINE NO
                ;
B4C7  A5D4      :LSE    LDA     FR0         ; MOVE END LINE NO
B4C9  85AD          STA     LELNUM          ; TO LIST END LINE NO
B4CB  A5D5          LDA     FR0+1           ;
B4CD  85AE          STA     LELNUM+1
                ;
                ;
B4CF            :LSTART
B4CF  20A2A9        JSR     GETSTMT         ;GO FIND FIRST LINE
                ;
B4D2  20E2A9    :LNXT   JSR     TENDST      ;AT END OF STMT
B4D5  3024 ^B4FB    BMI     :LRTN           ; BR AT END
                ;
B4D7  A001      :LTERNG LDY     #1          ;COMPARE CURRENT STMT
B4D9  B18A          LDA     [STMCUR],Y      ;LINE NO WITH END
B4DB  C5AE          CMP     LELNUM+1        ;LINE NO
B4DD  900B ^B4EA    BCC     :LGO
B4DF  D01A ^B4FB    BNE     :LRTN
B4E1  88            DEY
B4E2  B18A          LDA     [STMCUR],Y
B4E4  C5AD          CMP     LELNUM
B4E6  9002 ^B4EA    BCC     :LGO
B4E8  D011 ^B4FB    BNE     :LRTN
                ;
B4EA  205CB5    :LGO    JSR     :LLINE      ;GO LIST THE LINE
B4ED  20F4A9        JSR     TSTBRK          ; TEST FOR BREAK
B4F0  D009 ^B4FB    BNE     :LRTN           ; BR IF BREAK
B4F2  20DDA9        JSR     GETLL
B4F5  20D0A9        JSR     GNXTL           ;GO INC TO NEXT LINE
B4F8  4CD2B4        JMP     :LNXT           ;GO DO THIS LINE
                ;
B4FB            :LRTN
B4FB  A5FB          LDA     LISTDTD         ; IF LIST DEVICE
B4FD  F007 ^B506    BEQ     :LRTN1          ; IF ZERO BR
B4FF  20F1BC        JSR     CLSYSD          ; ELSE CLOSE DEVICE
B502  A900          LDA     #0              ; AND RESET
B504  85B5          STA     LISTDTD         ; DEVICE TO ZERO
                ;
B506  8DFE02        STA     $2FE            ; SET DISPLAY MODE
B509  4C19B7        JMP     XRTN            ; THEN RESTORE LIST LINE
                                              AND RETURN

;LSCAN - Scan a Table for LIST Token

                ;               ENTRY PARMS
                ;                  X = SKIP LENGTH
                ;                A,Y = TABLE ADR
                ;              SCANT = TOKEN
                ;
B50C            :LSCAN
B50C  86AA          STX     SRCSKP          ; SAVE SKIP LENGTH
B50E  2030B5        JSR     :LSST           ; SAVE SRC ADR
                ;
B511  A4AA      :LSC0   LDY     SRCSKP      ; GET SKIP FACTOR
                ;
B513  C6AF          DEC     SCANT           ; DECREMENT SRC COUNT
B515  300E ^B525    BMI     :LSINC          ; BR IF DONE
                ;
B517  B195      :LSC1   LDA     [SRCADR],Y      ; GET CHARACTER
B519  3003 ^B51E    BMI     :LSC2           ; BR IF LAST CHARACTER
B51B  C8            INY                     ; INC TO NEXT
B51C  D0F9 ^B517    BNE     :LSC1           ; BR ALWAYS
B51E  C8        :LSC2   INY                 ; INC TO AFTER LAST CHAR
B51F  2025B5        JSR     :LSINC          ; INC SRC ADR BY Y
B522  4C11B5        JMP     :LSC0           ; GO TRY NEXT
                ;
B525  18        :LSINC  CLC
B526  98            TYA                     ; Y PLUS
B527  6595          ADC     SRCADR          ; SRCADR
B529  8595          STA     SRCADR          ; IS

;----------217

B52B  A8            TAY                     ; NEW
B52C  A596          LDA     SCRADR+1        ; SCRADR
B52E  6900          ADC     #0
                ;
B530  8596      :LSST   STA     SCRADR+1    ; STORE NEW SCRADR
B532  8495          STY     SCRADR          ; AND
B534  60            RTS                     ; RETURN

;LPRTOKEN - Print a Token

B535            LPRTOKEN
B535            :LPRTOKEN
B535  A0FF          LDY     #$FF            ; INITIALIZE INDEX TO ZERO
BC37  84AF          STY     SCANT
                ;
B539  E6F       :LPT1   INC     SCANT       ; INC INDEX
B53B  A4AF          LDY     SCANT           ; GET INDEX
B53D  B195          LDA     [SCRADR],Y      ; GET TOKEN CHAR
B53F  48            PHA                     ; SAVE CHAR
B540  C998          CMP     #CR             ; IF ATARI CR
B542  F004 ^B548    BEQ     :LPT1A          ; THEN DON'T AND
B544  297F          AND     #$7F            ; TURN OFF MSB
B546  F003 ^B54B    BEQ     :LPT2           ; BR OF NON-PRINTING
B548            :LPT1A
B548  209FBA        JSR     PRCHAR          ; GO PRINT CHAR
B54B            :LPT2
B54B  68            PLA                     ; GET CHAR
B54C  10EB ^B539    BPL     :LPT1           ; BR IF NOT END CHAR
B54E  60            RTS                     ; GO BACK TO MY BOSS

;LPTWB - Print Token with Blank Before and After

B54F            :LPTWB
B54F  A920          LDA     #$20            ; GET BLANK
B551  209FBA        JSR     PRCHAR          ; GO PRINT IT
B554  2035B5    :LPTTB  JSR     :LPRTOKEN   ; GO PRINT TOKEN
B557  A920      :LPBLNK LDA     #$20        ; GET BLANK
B559  4C9FBA        JMP     PRCHAR          ; GO PRINT IT AND RETURN
                ;
                ;
                ;
;LLINE - List  Line

B55C            LLINE
B55C            :LLINE
B55C  A000          LDY     #0
B55E  B18A          LDA     [STMCUR],Y      ; MOVE LINE NO
B560  85D4          STA     FR0             ; TO FR0
B562  C8            INY
B563  B18A          LDA     [STMCUR],Y
B565  85D5          STA     FR0+1
B567  20AAD9        JSR     CVIFP           ; CONVERT TO FP
B56A  20E6D8        JSR     CVFASC          ; CONVERT TO ASCII
B56D  A5F3          LDA     INBUFF          ; MOVE INBUFF ADR
B56F  8595          STA     SCRADR          ; TO SCRADR
B571  A5F4          LDA     INBUFF+1
B573  8596          STA     SCRADR+1
B575  2054B5        JSR     :LPTTB          ; AND PRINT LINE NO
                ;
B578            LDLINE
B578  A002          LDY     #2
B57A  B18A          LDA     [STMCUR],Y      ; GET LINE LENGTH
B57C  859F          STA     LLNGTH          ; AND SAVE
B57E  C8            INY
B57F  B18A      :LL1    LDA     [STMCUR],Y      ; GET STMT LENGTH
B581  85A7          STA     NXTSTD          ; AND SAVE AS NEXT ST DISPL
B583  C8            INY                     ; INC TO STMT TYPE
B584  84A8          STY     STINDEX         ; AND SAVE DISPL
B586  2090B5        JSR     :LSTMT          ; GO LIST STMT

;----------218

B589  A4A7          LDY     NXTSTD          ; DONE LINE
B58B  C49F          CPY     LLNGTH
B58D  90F0 ^B57F    BCC     :LL1            ; BR IF NOT
B58F  60            RTS                     ; ELSE RETURN

;LSTMT - List a Statement

B590            :LSTMT
B590  2031B6        JSR     :LGCT           ; GET CURRENT TOKEN
B593  C936          CMP     #CILET          ; IF IMP LET
B595  F017 ^B517    BEQ     :LADV           ; BR
B597  203DB6        JSR     LSTMC           ; GO LIST STMT CODE
                ;
B59A  2031B6        JSR     :LGCT           ; GO GET CURRENT TOKEN
B59D  C937          CMP     #CERR           ; BR IF ERROR STMT
B59F  F004 ^B5A5    BEQ     :LDR
B5A1  C902          CMP     #2              ; WAS IT DATA OR REM
B5A3  B009 ^B5AE    BCS     :LADV           ; BR IF NOT
                ;
B5A5  202FB6    :LDR    JSR     :LGNT       ; OUTPUT DATA/REM
B5A8  209FBA        JSR     PRCHAR          ; THEN PRINT THE CR
B5AB  4CA5B5        JMP     :LDR
                ;
B5AE  202FB6    :LADV   JSR     :LGNT       ; GET NEXT TOKEN
B5B1  101A ^B5CD    BPL     :LNVAR          ; BR IF NOT VARIABLE
                ;
B5B3  297F          AND     #$7F            ; TURN OFF MSB
B5B5  84AF          STA     SCANT           ; AND SET AS SCAN COUNT
B5B7  A200          LDX     #0              ; SCAN VNT FOR
B5B9  A593          LDA     VNTP+1          ; VAR NAME
B58B  A482          LDY     VNTP
B5BD  200CB5        JSR     :LSCAN          ;
B5C0  2035B5    :LS1    JSR     :LPRTOKEN   ; PRINT VAR NAME
B5C3  C9A8          CMP     #$A8            ; NAME END IN LPAREN
B5C5  D0E7 ^B5AE    BNE     :LADV           ; BR IF NOT
B5C7  202FB6        JSR     :LGNT           ; DON'T PRINT NEXT TOKEN
B5CA  4CAEB5        JMP     :LADV           ; IF IT IS A PAREN
                ;
B5CD            :LNVAR
B5CD  C90F          CMP     #$0F            ; TOKEN, $0F
B5CF  F018 ^B5E9    BEQ     :LSTC           ; BR IF 0F, STR CONST
                ;
B5D1  B036 ^B609    BCS     :LOP            ; BR IF TOKEN > $0F
                ;                                 ELSE IT'S NUM CONST
B5D3  204DAB        JSR     NCTOFR0         ; GO MOVE FR0
B5D6  C6A8          DEC     STINDEX         ; BACK INDEX TO LAST CHAR
B5D8  20E6D8        JSR     CVFASC          ; CONVERT FR0 TO ASCII
B5DB  A5F3          LDA     INBUFF          ; POINT SCRADR
B5DD  8595          STA     SCRADR          ; TO INBUFF WHERE
B5DF  A5F4          LDA     INBUFF+1        ; CHAR IS
B5E1  8596          STA     SCRADR+1        ;
B5E3  2035B5    :LSX    JSR     :LPRTOKEN   ; GO PRINT NUMBER
B5E6  4CAEB5        JMP     :LADV           ; GO FOR NEXT TOKEN
                ;
B5E9  202FB6    :LSTC   JSR     :LGNT       ; GET NEXT TOKEN
B5EC  85AF          STA     SCANT           ; WHICH IS STR LENGTH
B5EE  A922          LDA     #$22            ; PRINT DOUBLE QUOTE CHAR
B5F0  209FBA        JSR     PRCHAR
B5F3  A5AF          LDA     SCANT
B5F5  F00A ^B601    BEQ     :LS3
                ;
B5F7  202FB6    :LS2    JSR     :LGNT       ; OUTPUT STR CONST
B5FA  209FBA        JSR     PRCHAR          ; CHAR BY CHAR
B5FD  C6AF          DEC     SCANT           ; UNTIL COUNT =0
B5FF  D0F6 ^B5F7    BNE     :LS2
                ;
B601            :LS3
B601  A922          LDA     #$22            ; THEN OUTPUT CLOSING
B603  209FBA        JSR     PRCHAR          ; DOUBLE QUOTE
B606  4CAEB5        JMP     :LADV

;----------219

B609  38        :LOP    SEC
B60A  E910          SBC     #$10            ; SUBSTRACT THE 10
B60C  85AF          STA     SCANT           ; SET FOR SCAN COUNT
B60E  A200          LDX     #0
B610  A9A7          LDA     #OPNTAB/256
B612  A0E3          LDY     #OPNTAB&255
B614  200CB5        JSR     :LSCAN          ; SCAN OP NAME TABLE
B617  2031B6        JSR     :LGCT           ; GO GET CURRENT TOKEN
B61A  C93D          CMP     #CFFUN          ; IS IT FUNCTION
B61C  B0C5 ^B5E3    BCS     :LSX            ; BR IF FUNCTION
B61E  A000          LDY     #0
B620  B195          LDA     [SCRADR],Y      ; GET FIRST CHAR
B622  297F          AND     #$7F            ; TURN OFF MSB
B624  20F7A3        JSR     TSTALPH         ; TEST FOR ALPHA
B627  B0BA ^B5E3    BCS     :LSX            ; BR NOT ALPHA
B629  204FB5        JSR     :LPTWB          ; LIST ALPHA WITH
B62C  4CAEB5        JMP     :LADV           ; BLANKS FOR AND AFTER
                ;
B62F            :LNGT                       ; GET NEXT TOKEN
B62F  E6A8          INC     STINDEX         ; INC TO NEXT
B631  A4A8      :LGCT   LDY     STINDEX     ; GET DISPL
B633  C4A7          CPY     NXTSTD          ; AT END OF STMT
B635  B003 ^B63A    BCS     :LNGTE          ; BR IF AT END
B637  B18A          LDA     [STMCUR],Y      ; GET TOKEN
B639  60            RTS                     ; AND RETURN
                ;
B63A  68        :LGNTE  PLA                 ; POP CALLERS ADR
B63B  68            PLA                     ; AND
B63C  60            RTS                     ; GO BACK TO LIST LINE
                ;
B63D            LSTMC
B63D  85AF          STA     SCANT           ; SET INSCAN COUNT
B63F  A202          LDX     #2              ; AND
B641  A9A4          LDA     #SNTAB/256
B643 A0AF           LDY     #SNTAB&255      ; STATEMENT NAME TABLE
B645  200CB5        JSR     :LSCAN
B648  4C54B5        JMP     :LPTTB          ; GO LIST WITH FOLLOWING BLANK

;XFOR - Execute FOR

B64B                LOCAL
B64B            XFOR
B64B  208AB8        JSR     :SAVDEX         ; SAVE STINDEX
B64E  20E0AA        JSR     EXEXPR          ; DO ASSIGNEMENT
B651  A5D3          LDA     VNUM            ; GET VARIABLE #
B653  0980          ORA     #$80            ; OR IN HIGH ORDER BIT
B655  48            PHA                     ; SAVE ON CPU STACK
B656  2025B8        JSR     FIXRSTK         ; FIX RUN STACK
                ;
                ;       BUILD STACK ELEMENT
                ;
B659  A90C          LDA     #FBODY          ; GET # OF BYTES
B65B  2078B8        JSR     :REXPAN         ; EXPAND RUN STACK
                ;
B65E  200FAC        JSR     POP1            ; EVAL EXP & GET INTO FR0
                ;
                ;       PUT LIMIT [INFR0] ON STACK
                ;
B661  A2D4          LDX     #FR0            ; POINT TO FR0
B663  A000          LDY     #FLIM           ; GET DISPL
B665  208FB8        JSR     :MV6RS          ; GO MOVE LIMIT
                ;
                ;       SET DEFAULT STEP
                ;
B668 2044DA         JSR     ZFR0            ; CLEAR FR0 TO ZEROS
B66B  A901          LDA     #1              ; GET DEFAULT STEP
B66D  85D5          STA     FR0+1           ; SET DEFAULT STEP VALUE
B66F  A940          LDA     #$40            ; GET DEFAULT EXPONENT
B671  85D4          STA     FR0             : STORE
                ;

;----------220

                ;       TEST FOR END OF STMT
                ;
B673  2010B9        JSR     TSTEND          ; TEST FOR END OF START
B676  B003 ^B67B    BCS     :NSTEP          ; IF YES, WE ARE AT END OF
                                              STMT
                ;
                ;       ELSE GET STEP VALUE
                ;
B678  200FAC        JSR     POP1            ; EVAL EXP & GET INTO FR0
B67B            :STEP
                ;
                ;       PUT STEP [IN FR0] ON STACK
                ;
B67B  A2D4          LDX     #FR0            ; POINT TO FR0
B67D  A006          LDY     #FSTEP          ; GET DISPL
B67F  208FB8        JSR     :MV6RS          ; GO MOVE STEP
                ;
B682  68            PLA                     ; GET VARIABLE #
                ;
                ;       PSHRSTK - PUSH COMMON PORT OF FOR/GOSUB
                ;               - ELEMENT ON RUN STACK
                ;
                ;       ON ENTRY  A - VARIABLE # OR 0 [FOR GOSUB]
                ;                 TSLNUM - LINE #
                ;                 STINDEX - DISPL TO STMT TOKEN +1
B683            PSHRSTK
                ;
                ;       EXPAND RUN STACK
                ;
B683  48            PHA                     ; SAVE VAR # / TYPE
B684  A904          LDA      #GFHEAD        ; GET # OF BYTES TO EXPAND
B686  2078B8        JSR      :REXPAN        ; EXPAND [OLD TOP RETURN IN
                                              ZTEMP1]
                ;
                ;       PUT ELEMENT ON STACK
                ;
B689 68             PLA                     ; GET VARIABLE #/TYPE
B68A  A000          LDY      #GFTYPE        ; GET DISPL TO TYPE IN HEADER
B68C  91C4          STA      [TEMPA],Y      ; PUT VAR#/TYPE ON STACK
B68E  B18A          LDA      [STMCUR],Y     ; GET LINE # LOW
B690  C8            INY                     ; POINT TO NEXT HEADER BYTE
B691  91C4          STA      [TEMPA],Y      ; PUT LINE # LOW IN HEADER
B693  B18A          LDA      [STMCUR],Y     ; GET LINE # HIGH
B695  C8            INY
B696  91C4          STA      [TEMPA],Y      ; PUT IN HEADER
B698  A6B3          LDX      SAVDEX         ; GET SAVED INDEX INTO LINE
B69A  CA            DEX                     ; POINT TO TOKEN IN LINE
B69B  8A            TXA                     ; PUT IN A
B69C  C8            INY                     ; POINT TO DISPL IN HEADER
B69D  91C4          STA      [TEMPA],Y      ; PUT IN HEADER
B69F  60            RTS

;XGOSUB - Execute GOSUB

B6A0            XGOSUB
B6A0  20C7B6        JSR      XGS            ; GO TO XGS ROUTINE

;XGOTO - Execute GOTO

B6A3            XGOTO
B6A3  20D5AB        JSR      GETPINT        ; GET POSITIVE INTEGER IN FR0
                ;
                ;       GET LINE ADRS & POINTERS
                ;
B6A6            XGO2
B6A6  A5D5          LDA      FR0+1          ; X
B6A8  85A1          STA      TSLNUM+1       ; X
B6AA  A5D4          LDA      FR0            ; PUT LINE # IN TSLNUM
B6AC  85A0          STA      TSLNUM         ; X

;----------221

                ;
B6AE            XGO1
B6AE  20A2A9        JSR      GETSTMT        ; LINE POINTERS AND STMT ADDRESS
B6B1  B005 ^B6B8    BCS      :ERLN          ; IF NOT FOUND ERROR
B6B3  68            PLA                     ; CLEAN UP STACK
B6B4  68            PLA
B6B5  4C5FA9        JMP      EXECNL         ; GO TO EXECUTE CONTROL
                ;
B6B8            :ERLN
B6B8  20BEB6        JSR      RESCUR         ; RESTORE STMT CURRENT
                ;
                ;
                ;
B6BB 2028B9         JSR      ERNOLN         ; LINE # NOT FOUND
B6BE            RESCUR
B6BE  A5BE          LDA      SAVCUR         ; RESTORE STMCUR
B6C0  858A          STA      STMCUR         ; X
B6C2  A5BF          LDA      SAVCUR+1       ; X
B6C4  858B          STA      STMCUR+1       ; X
B6C6  60            RTS

;XGS - Perform GOSUB [GOSUB, LIST, READ]

B6C7            XGS
B6C7  208AB8        JSR      ;SAVDEX        ; GET STMT INDEX
B6CA            XGS1
B6CA  A900          LDA      #0             ; GET GOSUB TYPE
B6CC  4C83B6        JMP      PSHRSTK        ; PUT ELEMENT ON RUN STACK

;XNEXT - Execute NEXT

B6CF            XNEXT
                ;
                ;       GET VARIABLE #
                ;
B6CF  A4A8          LDY      STINDEX        ; GET STMT INDEX
B6D1  B18A          LDA      [STMCUR],Y     ; GET VARIABLE #
B6D3  85C7          STA      ZTEMP2+1       ; SAVE
                ;
                ;       GET ELEMENT
                ;
B6D5            :XN
B6D5  2041B8        JSR      POPRSTK        ; PULL ELEMENT FROM RUN STACK
                                                  VAR#/TYPE RETURN IN A
B6D8  B03C ^B716    BCS      :ERNFOR        ; IF AT TOP OF STACK, ERROR
B6DA  F03A ^B716    BEQ      :ERNFOR        ; IF TYPE = GOSUB, ERROR
B6DC  C5C7          CMP      ZTEMP2+1       ; DOES STKVAR# = OUR VAR #
B6DE  D0F5 ^B6D5    BNE      :XN
                ;
                ;       GET STEP VALUES IN FR1
                ;
B6E0  A006          LDY      #FSTEP         ; GET DISPL INTO ELEMENT
B6E2  209EB8        JSR      :PL6RS         ; GET STEP INTO FR1
                ;
                ;       SAVE TYPE OF STEP [+ OR -]
                ;
B6E5  A5E0          LDA      FR1            ; GET EXP FR1 [CONTAINS SIGN]
B6E7  48            PHA                     ; PUSH ON CPU STACK
                ;
                ;       GET VARIABLE VALUE
                ;
B6E8  A5C7          LDA      ZTEMP2+1       ; GET VAR #
B6EA  2089AB        JSR      GETVAR         ; GET VARIABLE VALUE
                ;
                ;       GET NEW VALUE
                ;
B6ED  203BAD        JSR      FRADD          ; ADD STEP TO VALUE
B6F0  2016AC        JSR      RTNVAR         ; PUT IN VARIABLE TABLE
                ;
                ;       GET LIMIT IN FR1
                ;

;----------222

B6F3  A000          LDY      #FLIM          ; GET DISPL TO LIMIT IN ELEMENT
B6F5  209EB8        JSR      :PL6RS         ; GET LIMIT INTO FR1
B6F8  68            PLA                     ; GET SIGN OF STEP
B6F9  1006 ^B701    BPL      :STPPL         ; BR IF STEP +
                ;
                ;       COMPARE FOR NEGATIVE STEP
                ;
B6FB  2035AD        JSR      FRCMP          ; COMPARE VALUE TO LIMIT
B6FE  1009 ^B709    BPL      :NEXT          ; IF VALUE >= LIMIT, CONTINUE
B700  60            RTS                     ; ELSE DONE
                ;
                ;       COMPARE FOR POSITIVE STEP
                ;
B701            :STPPL
B701  2035AD        JSR      FRCMP          ; COMPARE VALUE TO LIMIT
B704  F003 ^B709    BEQ      :NEXT          ; IF = CONTINUE
B706  3001 ^B709    BMI      :NEXT          ; IF < CONTINUE
B708  60            RTS                     ; ELSE RETURN
                ;
B709            :NEXT
B709  A910          LDA      #GFHEAD+FBODY  ; GET # BYTES IN FOR ELEMENT
B70B  2078B8        JSR      :REXPAND       ; GO PUT IT BACK ON STACK
B70E  2037B7        JSR      :GETTOK        ; GET TOKEN [RETURN IN A]
B711  C908          CMP      #CFOR          ; IS TOKEN = FOR?
B713  D032 ^B747    BNE      :ERGFD         ; IF NOT IT'S AN ERROR
B715  60            RTS
                ;
B716            :ERNFOR
B716  2026B9        JSR      ERNOFOR

;XRTN - Execute RETURN

B719            XRTN
B719  2041B8        JSR      POPRSTK        ; GET ELEMENT FROM RUN STACK
B71C  B016 ^B734    BCS      :ERRTN         ; IF AT TOP OF STACK, ERROR
B71E  D0F9 ^B719    BNE      XRTN           ; IF TYPE NOT GOSUB, REPEAT
                ;
B720  2037B7        JSR      :GETTOK        ; GET TOKEN FROM LINE [IN A]
B723  C90C          CMP      #CGOSUB        ; IS IT GOSUB?
B725  F00C ^B733    BEQ      :XRTS          ; BR IF GOSUB
B727  C91E          CMP      #CON
B729  F008 ^B733    BEQ      :XRTS          ; BR IF ON
B72B  C904          CMP      #CLIST
B72D  F004 ^B733    BEQ      :XRTS          ; BR IF LIST
B72F  C922          CMP      #CREAD         ; MAYBE IT'S READ
B731  D014 ^B747    BNE      :ERGFD         ; IF NOT, ERROR
B733            :XRTS
B733  60            RTS
                ;
B734            :ERRTN
B734  2020B9        JSR      ERBRTN         ; BAD RETURN ERROR
                ;
                ;       :GETTOK - GET TOKEN POINTED TO BY RUN STACK ELEMENT
                ;
                ;       ON EXIT    A - CONTAINS TOKEN
                ;
B737            :GETTOK
B737  2018B8        JSR      SETLINE        ; SET UP FOR PROCESS LINE
B73A  B00B ^B747    BCS      :ERGFD         ; IF LINE # NOT FOUND, ERROR
                ;
B73C  A4B2          LDY      SVDISP         ; GET DISPL TO TOKEN
B73E  88            DEY                     ; POINT TO NXT STMT DISPL
B73F  B18A          LDA      [STMCUR],Y     ; GET NEXT STMT DISPL
B741  85A7          STA      NXTSTD         ; SAVE
                ;
B743  C8            INY                     ; GET DISPL TO TOKEN AGAIN
B744  B18A          LDA      [STMCUR],Y     ; GET TOKEN
B746  60            RTS
                ;
                ;
B747            :ERGFD

;----------223

B747  20BEB6        JSR      RESCUR         ; RESTORE STMT CURRENT
B74A  2022B9        JSR      ERGFDEL

;XRUN - Execute RUN

B74D            XRUN
                ;
                ;       TEST FOR END OF STMT
                ;
B74D  2010B9        JSR      TSTEND         ; CHECK FOR END OF STMT
B750  B003 ^B755    BCS      :NOFILE        ; IF END OF STMT, BR
B752  20F7BA        JSR      FRUN           ; ELSE HAVE FILE NAME
                ;
B755            :NOFILE
                ;
                ;       GET 1ST LINE OF PROGRAM
                ;
B755  A900          LDA      #0             ; GET SMALLEST POSSIBLE
                                              LINE NUM
B757  85A0          STA      TSLNUM         ; X
B759  85A1          STA      TLSNUM+1       ; X
B75B  2018B8        JSR      SETLINE        ; SET UP LINE POINTERS
B75E  20E2A9        JSR      TENDST         ; TEST FOR END OF STMT TABLE
B761  3012 ^B775    BMI      :RUNEND        ; IF AT END, BR
B763  20F8B8        JSR      RUNINIT        ; CLEAR SOME STORAGE

                                                  FALL THRU TO CLR

;XCLR - Execute CLR

B766            XCLR
B766  20C0B8        JSR      ZVAR           ; GO ZERO VARS
B769  20AFB8        JSR      RSTPTR         ; GO RESET STACK PTRS
B76C  A900          LDA      #0             ; CLEAR DATA VALUES
B76E  85B7          STA      DATALN
B770  85B8          STA      DATALN+1
B772  85B6          STA      DATAD
B774  60            RST
                ;
                ;
B775            :RUNEND
B775  4C50A0        JMP      SNX1           ; NO PROGRAM TO RUN

;XIF - Execute IF

B778            XIF
B778  200FAC        JSR      POP1           ; EVAL EXP AND GET VALUE
                                              INTO FR0
B77B  A5D5          LDA      FR0M           ; GET 1ST MANTISSA BYTE
B77D  F009 ^B788    BEQ      :FALSE         ; IF = 0, # = 0 AND IS FALSE
                ;
                ;       EXPRESSION TRUE
                ;
B77F  2010B9        JSR      TSTEND         ; TEST FOR END OF STMT
B782  B003          BCS      :TREOS         ; IF AT EOS, BRANCH
                ;
                ;       TRUE AND NOT EOS
                ;
B784  4CA3B6        JMP      XGOTO          ; JOIN GOTO
                ;
                ;       TRUE AND EOS
                ;
B787            :TREOS
B787  60            RTS
                ;
                ;       EXPRESSION FALSE
                ;
B788            :FALSE
B788  A59F          LDA      LLENGTH        ; GET DISPL TO END OF LINE
B78A  85A7          STA      NXTSTD         ; SAVE AS DISPL TO NEXT STMT
B78C  60            RTS

;----------224

;XEND - Execute END

B78D            XEND
B78D  20A7B7        JSR      STOP
B790  4C50A0        JMP      SNX1

;XSTOP - Execute STOP

B793            XSTOP
B793  20A7B7        JSR      STOP
                ;
                ;       PRINT MESSAGE
                ;
B796  206EBD        JSR      PRCR           ; PRINT CR
B799  A9B6          LDA      #:MSTOP&255^    ; SET POINTER FOR MESSAGE
B79B  8595          STA      SCRADR         ; X
B79D  A9B7          LDA      #:MSTOP/256    ; X
B79F  8596          STA      SCRADR+1       ; X
                ;
B7A1  2035B5        JSR      LPRTOKEN       ; PRINT IT
                ;
B7A4  4C74B9        JMP      :ERRM2         ; PRINT REST OF MESSAGE
                ;
                ;
                ;
B7A7            STOP
B7A7  20E2A9        JSR      TENDST         ; GET CURRENT LINE # HIGH
B7AA  3007          BMI      :STOPEND       ; IF -, THIS IS DIRECT STMT
                ;
B7AC  85BB          STA      STOPLN+1       ; SAVE LINE # HIGH FOR CON
B7AE  88            DEY                     ; DEC INDEX
B7AF  B18A          LDA      [STMCUR],Y     ; GET LINE # LOW
B7B1  85BA          STA      STOPLN         ; SAVE FOR CON
B7B3            :STOPEND
B7B3  4C72BD        JMP      SETDZ          ; SET L/D DEVICE = 0
                ;
                ;
                ;
B7B6  53544F5050 :MSTOP  DC      'STOPPED'
      4544A0

;XCONT - Execute Continue

B7BE            XCONT
B7BE  20E2A9        JSR      TENDST         ; IS IT INDIRECT STMT?
B7C1  10F0 ^B7B3    BPL      :STOPEND       ; IF YES, BR
B7C3  A5BA          LDA      STOPLN         ; SET LOOP LINE # AS LINE #
                                              FOR GET
B7C5  85A0          STA      TSLNUM         ; X
B7C7  A5BB          LDA      STOPLN+1       ; X
B7C9  85A1          STA      TSLNUM+1       ; X
                ;
B7CB  20A2A9        JSR      GETSTMT        ; GET ADR OF STMT WE
                                              STOPPED AT
B7CE  20E2A9        JSR      TENDST         ;AT END OF STMT TAB?
B7D1  30A2 ^B775    BMI      :RUNEND
B7D3  20DDA9        JSR      GETLL          ; GET NEXT LINE ADR IN CURSTM
B7D6  20D0A9        JSR      GNXTL          ; X
B7D9  20E2A9        JSR      TENDST         ; SEE IF WE ARE AT END OF
                                              STMT TABLE
B7DC  3097 ^B775    BMI      :RUNEND        ; BR IF MINUS
B7DE  4C1BB8        JMP      SETLN1         ; SET UP LINE POINTERS

;XTRAP - Execute TRAP

B7E1            XTRAP
B7E1  20E0AB        JSR      GETINT         ; CONVERT LINE # TO POSITIVE
                                              INT
B7E4  A5D4          LDA      FR0            ; SAVE LINE # LOW AS TRAP LINE
B7E6  85BC          STA      TRAPLN         ; IN CASE OF LATER ERROR
B7E8  A5D5          LDA      FR0+1          ; X
B7EA  85BD          STA      TRAPLN+1       ; X
B7EC  60            RTS

;----------225

;XON - Execute ON

B7ED            XON
B7ED  208AB8        JSR      :SAVDEX        ; SAVE INDEX INTO LINE
B7F0  20E9AB        JSR      GET1INT        ; GET 1 BYTE INTEGER
B7F3  A5D4          LDA      FR0            ; GET VALUE
B7F5  F020 ^B817    BEQ      :ERV           ; IF ZERO, FALL THROUGH TO
                                              NEXT STATEMENT
B7F7  A4A8          LDY      STINDEX        ; GET STMT INDEX
B7F9  88            DEY                     ; BACK UP TO GOSUB/GOTO
B7FA  B18A          LDA      [STMCUR],Y     ; GET CODE
B7FC  C917          CMP      #CGTO          ; IS IT GOTO?
B7FE  F003 ^B803    BEQ      :GO            ; IF YES, DON'T PUSH ON
                                              RUN STACK
                ;
                ;
                ;       THIS IS ON - GOSUB:  PUT ELEMENT ON RUN STACK
                ;
B800  20CAB6        JSR      XGS1           ; PUT ELEMENT ON RUN STACK
                                            ; FOR RETURN
                ;
B803            :GO
B803  A5D4          LDA      FR0            ; GET INDEX INTO EXPRESSIONS
B805  85B3          STA      ONLOOP         ; SAVE FOR LOOP CONTROL
B807            :ON1
B807  20D5AB        JSR      GETPINT        ; GET + INTEGER
B80A  C6B3          DEC      ONLOOP         ; IS THIS THE LINE # WE WANT?
B80C  F006 ^B814    BEQ      :ON2           ; IF YES, GO DO IT
B80E  2010B9        JSR      TSTEND         ; ARE THERE MORE EXPRESSIONS
B811  90F4          BCC      :ON1           ; IF YES, THEN EVAL NEXT ONE
B813  60            RTS                     ; ELSE FALL THROUGH TO
                                              NEXT STMT
B814            :ON2
B814  4CA6B6        JMP      XGO            ; JOIN GOTO
                ;
                ;
B817            :ERV
B817  60            RTS                     ; FALL THROUGH TO NEXT STATEMENT

;              Execution Control Statement Subroutines

;SETLINE - Set Up Line Pointers
                ;       ON ENTRY   TSLNUM - LINE #
                ;
                ;       ON EXIT    STMCUR - CONTAIN PROPER VALUES
                ;                  LLNGTH - X
                ;                  NXTSTM - X
                ;                  CARRY SET BY GETSTMT IF LINE # NOT FOUND
                ;
B818            SETLINE
B818  20A2A9        JSR      GETSTMT        ; GET STMCUR
                ;
B81B            SETLN1
B81B  A002          LDY      #2             ; GET DISP IN LINE TO LENGTH
B81D  B18A          LDA      [STMCUR],Y     ; GET LINE LENGTH
B81F  859F          STA      LLNGTH         ; SET LINE LENGTH
                ;
B821  C8            INY                     ; POINT TO NEXT STMT DISPL
B822  84A7          STY      NXTSTD         ; SET NXT STMT DISPL
                ;
B824  60            RTS

;FIXRSTK - Fix Run Stack - Remove Old FORs
                ;       ON ENTRY    A - VARIABLE # IN CURRENT FOR
                ;
                ;       ON EXIT     RUNSTK CLEAR OF ALL FOR'S
                ;

;----------226

B825            FIXRSTK
B825  85C7          STA      ZTEMP2+1       ; SAVE VAR # OF THIS FOR
                ;
                ;       SAVE TOP OF RUN STACK
                ;
B827  2081B8        JSR      :SAVRTOP       ; SAVE TOP OF RUN STACK IN
                                              ZTEMP
                ;
                ;
B82A            :FIXR
B82A  2041B8        JSR      POPRSTK        ; POP AN ELEMENT FROM RUNSTK
B82D  B008 ^B837    BCS      :TOP           ; IF AT TOP - WE ARE DONE
B82F  F006 ^B837    BEQ      :TOP           ; IF CC = 08 ELEMENT WAS GOSUB
B831  C5C7          CMP      ZTEMP2+1       ; IS STK VAR # = OUR VAR #?
B833  F00B ^B840    BEQ      :FNVAR         ; IF YES, WE ARE DONE
B835  D0F3 ^B85A    BNE      :FIXR          ; ELSE LOOK AT NEXT ELEMENT
                ;
                ;       FOR VAR # NOT ON STACK ABOVE TOP GOSUB
                ;               [RESTORE TOP OF STACK]
                ;
B837            :TOP
B837  A5C4          LDA      TEMPA          ; RESTORE TOPRSTK
B839  8590          STA      TOPRSTK        ; X
B83B  A5C5          LDA      TEMPA+1        ; X
B83D  8591          STA      TOPRSTK+1      ; X
B83F  60            RTS
                ;
                ;       FOR VAR # FOUND ON STACK
                ;
B840            :FNVAR
B840  60            RTS

;POPRSTK - Pop Element from Run Stack

                ;       ON EXIT    A - TYPE OF ELEMENT OR VAR #
                ;                  X - DISPL INTO LINE OF FOR/GOSUB TOKEN
                ;                  CUSET - CARRY SET STACK WAS EMPTY
                ;                  CARRY CLEAR - ENTRY POPED
                ;                  EQ SET - ELEMENT IS GOSUB
                ;                  TSLNUM - LINE #
                ;
B841            XPOP
B841            POPRSTK
                ;
                ;       TEST FOR STACK EMPTY
                ;
B841  A58F          LDA      RUNSTK+1       ; GET START OF RUN STACK HIGH
B843  C591          CMP      TOPRSTK+1      ; IS IT < TOP OF STACK HIGH
B845  9008 ^B84F    BCC      :NTOP          ; IF YES, WE ARE NOT AT TOP
B847  A58E          LDA      RUNSTK         ; GET START OF RUN STACK LOW
B849  C590          CMP      TOPRSTK        ; IS IT < TOP OF STACK LOW
B84B  9002 ^B84F    BCC      :NTOP          ; IF YES, WE ARE NOT AT TOP
                ;
B84D  38            SEC                     ; ELSE AT TOP: SET CARRY
B84E  60            RTS                     ; RETURN
                ;
                ;       GET 4 BYTE HEADER
                ;               [COMMON TO GOSUB AND FOR]
                ;
B84F            :NTOP
B84F  A904          LDA      #GFHEAD        ; GET LENGTH OF HEADER
B851  2072B8        JSR      :RCONT         ; TAKE IT OFF STACK
                ;
B854  A003          LDY      #GFDISP        ; GET INDEX TO SAVED LINE
                                              DISPL
B856  B190          LDA      [TOPRSTK],Y    ; GET SAVED LINE DISPL
B858  85B2          STA      SVDISP         ; SAVE
B85A  88            DEY                     ; POINT TO LINE # IN HEADER
B85B  B190          LDA      [TOPRSTK],Y    ; GET LINE # HIGH
B85D  85A1          STA      TSLNUM+1       ; SAVE LINE # HIGH
B85F  88            DEY                     ; GET DISPL TO LINE # LOW

;----------227

B860  B190          LDA      [TOPRSTK],Y    ; GET LINE # LOW
B862  85A0          STA      TSLNUM         ; SAVE LINE # LOW
                ;
B864  88            DEY                     ; POINT TO TYPE
B865  B190          LDA      [TOPRSTK],Y    ; GET TYPE
B867  F007 ^B870    BEQ      :FND           ; IF TYPE = GOSUB, SET ELEMENT
                ;
                ;       GET 12 BYTE FOR BODY
                ;
B869  48            PHA                     ; SAVE VAR #
B86A  A90C          LDA      #FBODY         ; GET # BYTES TO POP
B86C  2072B8        JSR      :RCONT         ; POP FROM RUN STACK
B86F  68            PLA                     ; GET VAR #
                ;
B870            :FND
B87018              CLC                     ; CLEAR CARRY [ENTRY POPPED]
B871  60            RTS

;:RCONT - Contract Run Stack
                ;
                ;       ON ENTRY   A - # OF BYTES TO SUBSTRACT
                ;
B872            :RCONT
B872  A8            TAY                     ; Y=LENGTH
B873  A290          LDX      #TOPRSTK       ;X = PTR TO RUN STACK
B875  4CFBA8        JMP      CONTLOW

;:REXPAN - Expand Run Stack
                ;       ON ENTRY    A - # OF BYTES TO ADD
                ;
                ;       ON EXIT     ZTEMP1 - OLD TOPRSTK
                ;
B878            :REXPAN
B878  2081B8        JSR      :SAVRTOP       ; SAVE RUN STACK TOP
B87B  A8            TAY                     ; Y=LENGTH
B87C  A290          LDX      #TOPRSTK       ; X=PTR TO TOP RUN STACK
B87E  4C7FA8        JMP      EXPLOW         ; GO EXPAND

;:SAVRTOP - Save Top of Run Stack in ZTEMP1

B881            :SAVRTOP
B881  A690          LDX      TOPRSTK        ; SAVE TOPRSTK
B883  86C4          STX      TEMPA          ; X
B885  A691          LDX      TOPRSTK+1      ; X
B887  86C5          STX      TEMPA+1
B889  60            RTS

;:SAVDEX - Save Line Displacement

B88A            :SAVDEX
B88A  A4A8          LDY      STINDEX        ; GET STMT INDEX
B88C  84B3          STY      SAVDEX         ; SAVE IT
B88E  60            RTS

;:MV6RS - Move 6-Byte Value to Run Stack
                ;       ON ENTRY    X - LOCATION TO MOVE FROM
                ;                   Y - DISPL FROM ZTEMP1 TO MOVE TO
                ;                   ZTEMP1 - LOCATION OF RUN STK ELEMENT
                ;
B88F            :MV6RS
B88F  A906          LDA      #6             ; GET # OF BYTE TO MOVE
B891  85C6          STA      ZTEMP2         ; SAVE AS COUNTER
B893            :MV
B893  B500          LDA      0,X            ; GET A BYTE
B895  91C4          STA      [TEMPA],Y      ; PUT ON STACK
B897  E8            INX                     ; POINT TO NEXT BYTE
B898  C8            INY                     ; POINT TO NEXT LOCATION
B899  C6C6          DEC      ZTEMP2         ; DEC COUNTER
B89B  D0F6 ^B893    BNE      :MV            ; IF NOT = 0 DO AGAIN
B89D  60            RTS

;----------228

;:PL6RS - Pull 6 Byte from Run Stack to FR1
                ;       ON ENTRY    Y = DISPL FROM TOPRSTK TO MOVE FROM
                ;                   TOPRSTK - START OF ELEMENT
                ;
B89E            :PL6RS
B89E  A906          LDA      #6             ; GET # OF BYTES TO MOVE
B8A0  85C6          STA      ZTEMP2         ; SAVE AS COUNTER
B8A2  A2E0          LDX      #FR1
B8A4            :PL
B8A4  B190          LDA      [TOPRSTK],Y    ; GET A BYTE
B8A6  9500          STA      0,X            ; SAVE IN Z PAGE
B8A8  E8            INX                     ; INC TO NEXT LOCATION
B8A9  C8            INY                     ; INC TO NEXT BYTE
B8AA  C6C6          DEC      ZTEMP2         ; DEC COUNTER
B8AC  D0F6 ^B8A4    BNE      :PL            ; IF NOT =0, DO AGAIN
B8AE  60            RTS

;RSTPTR - Reset Stack Pointers [STARP and RUNSTK]

B8AF            RSTPTR
B8AF  A58C          LDA      STARP          ; GET BASE OF STR/ARRAY
                                              SPACE LOW
B8B1  858E          STA      RUNSTK         ; RESET
B8B3  8590          STA      MEMTOP
B8B5  850E          STA      APHM           ; SET APPLICATION HIMEM
B8B7  A58D          LDA      STARP+1        ; GET BASE STR/ARRAY SPACE
                                              HIGH
B8B9  858F          STA      RUNSTL+1       ; RESET
B8BB  8591          STA      MEMTOP+1       ; X
B8BD  850F          STA      APHM+1         ; SET APPLICATION HIMEM
B8BF  60            RTS

;ZVAR - Zero Variable

B8C0            ZVAR
B8C0  A686         LDX       VVTP           ; MOVE VARIABLE TABLE POINTER
B8C2  86F5         STX       ZTEMP1         ; X
B8C4  A487         LDY       VVTP+1         ; X
B8C6  84F6         STY       ZTEMP1+1       ; X
                ;
                ;      ARE WE AT END OF TABLE ?
                ;
B8C8            :ZVAR1
B8C8  A6F6          LDX      ZTEMP1+1       ; GET NEXT VARIABLE ADDR HIGH
B8CA  E489          CPX      ENDVVT+1       ; IS IT < END VALUE HIGH
B8CC  9007 ^B8D5    BCC      :ZVAR2         ; IF YES, MORE TO DO
B8CE  A6F5          LDX      ZTEMP1         ; GET NEXT VARIABLE ADDR LOW
B8D0  E488          CPX      ENDVVT         ; IS IT < END VALUE LOW
B8D2  9001 ^B8D5    BCC      :ZVAR2         ; IF YES, MORE TO DO
B8D4  60            RTS                     ; ELSE DONE
                ;
                ;       ZERO A VARIABLE
                ;
B8D5            :ZVAR2
B8D5  A000          LDY      #0             ; TURN OFF
B8D7  B1F5          LDA      [ZTEMP1],Y     ; DIM FLAG
B8D9  29FE          AND      #$FE
B8DB  91F5          STA      [ZTEMP1],Y
B8DD  A002          LDY      #2             ; INDEX PAST VARIABLE HEADER
B8DF  A206          LDX      #6             ; GET # OF BYTES TO ZERO
B8E1  A900          LDA      #0             ; CLEAR A
                ;
B8E3            :ZVAR3
B8E3  91F5          STA      [ZTEMP1],Y     ; ZERO BYTE
B8E5  C8            INY                     ; POINT TO NEXT BYTE
B8E6  CA            DEX                     ; DEC POINTER
B8E7  D0FA ^B8E3    BNE      :ZVAR3         ; IF NOT = 0, ZERO NEXT BYTE
                ;

;----------229

B8E9  A5F5          LDA      ZTEMP1         ; GET CURRENT VARIABLE
                                              POINTER LOW
B8EB  18            CLC
B8EC  6908          ADC      #8             ; INC TO NEXT VARIABLE
B8EE  85F5          STA      ZTEMP1         ; SAVE NEW VARIABLE POINTER
                                              LOW
B8F0  A5F6          LDA      ZTEMP1+1       ; GET CURRENT VARIABLE
                                              POINTER HIGH
B8F2  6900          ADC      #0             ; ADD IN CARRY
B8F4  85F6          STA      ZTEMP1+1       ; SAVE NEW VARIABLE POINTER
                                              HIGH
B8F6  D0D0 ^B8C8    BNE      :ZVAR          ; UNCONDITIONAL BRANCH

;RUNINIT - Initialize Storage Locations for RUN

B8F8            RUNINIT
B8F8 A000           LDY      #0             ; CLEAR A
B8FA  84BA          STY      STOPLN         ; CLEAR LINE # STOPPED AT
B8FC  84BB          STY      STOPLN+1       ; X
B8FE  84B9          STY      ERRNUM         ; CLEAR ERROR #
B900  84FB          STY      RADFLG         ; CLEAR FLAG TOR TRANSENDENTALS
B902  84B6          STY      DATAD          ; CLEAR DATA POINTERS
B904  84B7          STY      DATALN         ; X
B906  84B8          STY      DATALN+1       ; X
B908  88            DEY
B909  84BD          STY      TRAPLN+1       ; SET TRAP FLAG TO NO TRAP
B90B  8411          STY      BRKBYT         ; SET BRK BYTE OFF [$FF]
B90D  4C41BD        JMP      CLSALL         ; GO CLOSE ALL DEVICES

;TSTEND - Test for End of Statement
                ;       ON EXIT     CC SET
                ;                   CARRY SET - END OF STMT
                ;                   CARRY SET - NOT END OF STMT
                ;
B910            TSTEND
B910  A6A8          LDX      STINDEX
B912  E8            INX
B913  E4A7          CPX      NXTSTD
B915  60            RTS

;                       ERROR MESSAGE ROUTINE

;Error Messages

B916  E6B9      ERRNSF  INC     ERRNUM      ; FILE NOT SAVE FILE
B918  E6B9      ERRDNO  INC     ERRNUM      ; #DN0 > 7
B91A  E6B9      ERRPTL  INC     ERRNUM      ; LOAD PGM TOO BIG
B91C  E6B9      ERSVAL  INC     ERRNUM      ; STRING NOT VALID
B91E  E6B9      XERR    INC     ERRNUM      ;EXECUTION OF GARBAGE
B920  E6B9      ERBRTN  INC     ERRNUM      ; BAD RETURNS
B922  E6B9      ERGFDE  INC     ERRNUM      ; GOSUB/FOR LINE DELETED
B924  E6B9      ERLTL   INC     ERRNUM      ; LINE TO LONG
B926  E6B9      ERNOFOR INC     ERRNUM      ; NO MATCHING FOR
B928  E6B9      ERNOLN  INC     ERRNUM      ; LINE NOT FOUND [GOTO/GOSUB]
B92A  E6B9      EROVFL  INC     ERRNUM      ; FLOATING POINT OVERFLOW
B92C  E6B9      ERRAOS  INC     ERRNUM      ; ARG STACK OVERFLOW
B92E  E6B9      ERRDIM  INC     ERRNUM      ; ARRAY/STRING DIM ERROR
B930  E6B9      ERRINP  INC     ERRNUM      ; INPUT STMT ERROR
B932  E6B9      ERRLN   INC     ERRNUM      ;VALUE NOT <32768
B934  E6B9      ERROOD  INC     ERRNUM      ; READ OUT OF DATA
B936  E6B9      ERRSSL  INC     ERRNUM      ; STRING LENGTH ERROR
B938  E6B9      ERRVSF  INC     ERRNUM      ; VARIABLE TABLE FULL
B93A  E6B9      ERVAL   INC     ERRNUM      ; VALUE ERROR
B93C  E6B9      MEMFULL INC     ERRNUM      ; MEMORY FULL
B93E  E6B9      ERON    INC     ERRNUM      ; NO LINE # FOR EXP IN ON

;----------230

;Error Routine

B940            ERROR
B940  A900          LDA      #0
B942  8DFE02        STA      DSPFLG         ; FLAG
B945  20A7B7        JSR      STOP           ; SET LINE * STOPPED AT
                ;
B948  A5BD          LDA      TRAPLN+1       ; GET TRAP LINE # HIGH
B94A  3015 ^B961    BMI      :ERRM1         ; IF NO LINE # PRINT MESSAGE
                ;
                ;  TRAP SET  GO TO SPECIFIED LINE #
                ;
B94C  85A1          STA      TSLNUM+1       ; SET TRAP LINE # HIGH FOR
                                              GET STMT
B94E  A5BC          LDA      TRAPLN         ; GET TRAP LINE # LOW
B950  85A0          STA      TSLNUM         ; SET FOR GET STMT
B952  A980          LDA      #$80           ; TURN OFF TRAP
B954  85BD          STA      TRAPLN+1
B956  A5B9          LDA      ERRNUM         ; GET ERROR #
B958  85C3          STA      ERRSAV         ; SAVE IT
B95A  A900          LDA      #0             ; CLEAR
B95C  85B9          STA      ERRNUM         ; ERROR #
B95E  4CAEB6        JMP      XGO1           ; JOIN GOTO
                ;
                ;
                ;      NO TRAP - PRINT ERROR MESSAGE
                ;
B961            :ERRM1

;Print Error Message Part 1 [**ERR]

B961  206EBD        JSR      PRCR           ; PRINT CR
B964  A937          LDA      #CERR          ; GET TOKEN FOR ERROR
B966  203DB6        JSR      LSTMC          ; GO PRINT CODE

;Print Error Number

B969  A5B9          LDA      ERRNUM         ; GET ERROR #
B96B  85D4          STA      FR0            ; SET ERROR # OF FR0 AS INTEGER
B96D  A900          LDA      #0             ; SET ERROR # HIGH
B96F  85D5          STA      FR0+1          ; X
                ;
B971  209CB9        JSR      :PRINUM        ; GO PRINT ERROR #
                ;
                ;
B974            :ERRM2
B974  20E2A9        JSR      TENDST         ; TEST FOR DIRECT STMT
B977  3019 ^B992    BMI      :ERRDONE       ; IF DIRECT STMTD DONE

;Print Message Part 2 [AT LINE]

B979  A9AE          LDA      #:ERRMS&255    ; SET POINTER TO MSG FOR PRINT
B97B  8595          STA      SRCADR         ; X
B97D  A9B9          LDA      #:ERRMS/256    ; X
B97F  8596          STA      SRCADR+1       ; X
                ;
B981  2035B5        JSR      LPRTOKEN

;Print Line Number

B984  A001          LDY      #1             ; SET DISPL
B986  B18A          LDA      [STMCUR],Y     ;GET LINE # HIGH
B986  85D5          STA      FR0+1          ; SET IN FR0 FOR CONVERT
B98A  88            DEY                     ; GET CURRENT LINE # LOW
B98B  B18A          LDA      [STMCUR],Y     ;GET UNUSED LINE # LOW
B98D  85D4          STA      FR0            ; SET IN FR0 LOW FOR CONVERT
B98F  209CB9        JSR     :PRINUM         ; PRINT LINE *

;----------231

B992            :ERRDONE
B992  206EBD        JSR      PRCR           ; PRINT CR
B995  A900          LDA      #0             ; CLEAR A
B997  85B9          STA      ERRNUM         ; CLEAR ERROR #
B999  4C60A0        JMP      SYNTAX

;Print Integer Number in FR0

B99C            :PRINUM
B99C  20AAD9        JSR      CVIFP          ; CONVERT TO FLOTING POINT
B99F  20E6D8        JSR      CVFASC         ; CONVERT TO ASCII
                ;
B9A2  A5F3          LDA      INBUFF         ; GET ADR OF # LOW
B9A4  8595          STA      SCRADR         ; SET FOR PRINT ROUTINE
B9A6  A5F4          LDA      INBUFF+1       ; GET ADR OF # HIGH
B9A8  8596          STA      SCRADR+1       ; SET FOR PRINT ROUTINE
B9AA  2035B5        JSR      LPRTOKEN       ; GO PRINT ERROR #
B9AD  60            RTS
                ;
                ;
                ;
B9AE  204154204C :ERRMS  DC      ' AT LINE '
      494E45A0

;                     Execute Graphics Routines

;XSETCOLOR - Execute SET COLOR

B9B7            XSETCOLOR
B9B7  20E9AB        JSR      GETINT         ; GET REGISTER #
B9BA  A5BA          LDA      FR0            ; GET #
B9BC  C905          CMP      #5             ; IS IT <5?
B9BE  B01A ^B9DA    BCS      :ERCOL         ; IF NOT, ERROR
B9C0  48            PHA                     ; SAVE
                ;
B9C1  20E0AB        JSR      GETINT         ; GET VALUE
                ;
B9C4  A5D4          LDA      FR0            ; GET VALUE*16+6
B9C6                ASLA                    ; X
B9C6 +0A            ASL      A
B9C7                ASLA                    ; X
B9C7 +0A            ASL      A
B9C8                ASLA                    ; X
B9C8 +0A            ASL      A
B9C9                ASLA                    ; X
B9C9 +0A            ASL      A
B9CA  48            PHA                     ; SAVE ON STACKS
B9CB  20E0AB        JSR      GETINT         ; GET VALUE 3
B9CE  68            PLA                     ; GET VALUE 2+16 FROM STACK
B9CF  18            CLC
B9D0  65D4          ADC      FR0            ; ADD IN VALUE 3
B9D2  A8            TAY                     ; SAVE VALUE 2+16 + 5 VALUE 5
B9D3  68            PLA                     ; GET INDEX
B9D4  AA            TAX                     ; PUT IN X
B9D5  98            TYA                     ; GET VALUE
                ;
B9D6  9DC402        STA      CREGS,X        ; SET VALUE IN REGS
B9D9  60            RTS
                ;
                ;
B9DA            :ERSND
B9DA            :ERCOL
B9DA  203AB9        JSR      ERVAL

;XSOUND - Execute SOUND

B9DD            XSOUND
B9DD  20E9AB        JSR      GETINT         ; GET 1 BYTE INTEGER
B9E0  A5D4          LDA      FR0            ; X
B9E2  C904          CMP      #4             ; IS IT <4?
B9E4  B0F4 ^B9DA    BCS      :ERSND         ; IF NOT, ERROR

;----------232

B9E6                ASLA                    ; GET VALUE +2
B9E6 +0A            ASL      A
B9E7  48            PHA
                ;
B9E8  A900          LDA      #0             ; SET TO ZERO
B9EA  8D08D2        STA      SREG1          ; X
                ;
B9ED  A903          LDA      #3
B9EF  8D0FD2        STA      SKCTL
                ;
B9F2  20E0AB        JSR      GETINT         ; GET EXP2
B9F5  68            PLA                     ; GET INDEX
B9F6  48            PHA                     ; SAVE AGAIN
B9F7  AA            TAX                     ; PUT IN INDEX REG
B9F8  A5D4          LDA      FR0            ; GET VALUE
B9FA  9D00D2        STA      SREG2,X        ; SAVE IT
                ;
B9FD  20E0AB        JSR      GETINT         ; GET EXP3
BA00  A5D4          LDA      FR0            ; GET 16+EXP3
BA02                ASLA                    ; X
BA02 +0A            ASL      A
BA03                ASLA                    ; X
BA03 +0A            ASL      A
BA04                ASLA                    ; X
BA04 +0A            ASL      A
BA05                ASLA                    ; X
BA05 +0A            ASL      A
BA06  48            PHA                     ; SAVE IT
                ;
BA07  20E0AB        JSR      GETINT         ; GET EXP4
BA0A  68            PLA                     ; GET 16 EXP3
BA0B  A8            TAY                     ; SAVE IT
BA0C  68            PLA                     ; GET INDEX
BA0D  AA            TAX                     ; PUT IN X
BA0E  98            TYA                     ; GET EXP3*16
BA0F  18            CLC
BA10  65D4          ADC      FR0            ; GET 16*EXP3+EXP4
BA12  9D01D2        STA      SREG3,X        ; STORE IT
BA15  60            RTS

;XPOS - Execute POSITION

BA16            XPOS
BA16  20E0AB        JSR      GETINT         ; GET INTEGER INTO FR0
BA19  A5D4          LDA      FR0            ; SET X VALUE
BA1B  8555          STA      SCRX           ; X
BA1D  A5D5          LDA      FR0+1          ; X
BA1F  8556          STA      SCRX+1         ; X
                ;
BA21  20E9AB        JSR      GET1INT        ; SET VALUE
BA24  A5D4          LDA      FR0            ; X
BA26  8554          STA      SCRY           ; X
BA28  60            RTS

;XCOLOR - Execute COLOR

BA29            XCOLOR
BA29  20E0AB        JSR      GETINT         ; GET INTEGER INTO FR0
BA2C  A5D4          LDA      FR0
BA2E  85C8          STA      COLOR
BA30  60            RTS

;XDRAWTO - Execute DRAWTO

BA31            XDRAWTO
BA31  2016BA        JSR      XPOS           ; GET X,Y POSITION
BA34  A5C8          LDA      COLOR          ; GET COLOR

BA36  8DFB02        STA      SVCOLOR        ; SET IT

;----------233

BA39  A911          LDA      #ICDRAW        ; GET COMMAND
BA3B  A206          LDX      #6             ; SET DEVICE
BA3D  20C4BA        JSR      GLPCX          ; SET THEM
                ;
BA40  A90C          LDA      #$0C           ; SET AUX 1
BA42  9D4A03        STA      ICAUX1,X
BA45  A900          LDA      #0             ; SET AUX 2
BA47  9D4B03        STA      ICAUX2,X
BA4A  2024BD        JSR      IO7
BA4D  4CB3BC        JMP      IOTEST

;XGR - Execute GRAPHICS

BA50            XGR
BA50  A206          LDX      #6             ; GET DEVICE
BA52  86C1          STX      IODVC          ;SAVE DEVICE #
BA54  20F1BC        JSR      CLSYS1         ; GO CLOSE IT
BA57  20E0AB        JSR      GETINT         ; GET INTEGER INTO FR0
                ;
BA5A  A273          LDX      #SSTR&255      ; SET INBUFF TO POINT
BA5C  A0BA          LDY      #SSTR/256      ; TO FILE SPEC STRING
BA5E  86F3          STX      INBUFF         ; X
BA60  84F4          STY      INBUFF+1       ; X
                ;
BA62  A206          LDX      #6             ; GET DEVICE #
BA64  A5D4          LDA      FR0            ;SET SOME BITS FOR GRAPHICS
BA66  29F0          AND      #$F0           ;
BA68  491C          EOR      #ICGR          ;
BA6A  A8            TAY                     ;
BA6B  A5D4          LDA      FR0            ; GET AUX2 [GRAPHICS TYPE]
BA6D  20D1BB        JSR      SOPEN          ; OPEN
BA70  4CB3BC        JMP      IOTEST         ; TEST I/O OK
                ;
                ;
                ;
BA73  533A9B    SSTR    DB      'S:',CR

;XPLOT - Execute PLOT

BA76            XPLOT
BA76  2016BA        JSR      XPOS           ; SET X,Y POSITION
                ;
BA79  A5C8          LDA      COLOR          ; GET COLOR
BA7B  A206          LDX      #6             ; GET DEVICE #
BA7D  4CA1BA        JMP      PRCX           ; GO PRINT IT

                ;      Input/Output Routines

BA80                LOCAL

;GETLINE - Get a Line of Input

                ;      GLINE - GET LINE [PROMPT ONLY]
                ;      GNLINE - GET NEW LINE [CR, PROMPT]
                ;
BA80            GNLINE
BA80  A6B4          LDX      ENTDTD         ; IF ENTER DEVICE NOT ZERO
BA82  D00E ^BA92    BNE      GLGO           ; THEN DO PROMPT
BA84  A99B          LDA      #CR            ; PUT EOL
BA86  209FBA        JSR      PUTCHAR
                ;
BA89            GLINE
BA89  A6B4          LDX      ENTDTD         ; IF ENTER DEVICE NOT ZERO
BA8B  D005 ^BA92    BNE      GLGO           ; THEN DON'T PROMPT
BA8D  A5C2          LDA      PROMPT         ; PUT PROMPT
BA8F  209FBA        JSR      PUTCHAR
                ;
BA92            GLGO
BA92  A6B4          LDX      ENDTD
BA94  A905          LDA      #ICGTR

;----------234

BA96  20C4BA        JSR      GLPCX
BA99  200ABD        JSR      IO1            ; GO DO I/O
BA9C  4CB3BC        JMP      IOTEST         ; GO TEST RESULT

;PUTCHAR - Put One Character to List Device

BA9F            PRCHAR
BA9F            PUTCHAR
BA9F  A6B5          LDX      LISTDTD        ; GET LIST DEVICE
BAA1            PRCX
BAA1  48            PHA                     ; SAVE IO BYTE
BAA2  20C6BA        JSR      GLPX           ; SET DEVICE
                ;
BAA5  BD4A03        LDA      ICAUX1,X       ; SET UP ZERO PAGE IOCB
BAA8  852A          STA      ICAUX1-IOCB+ZICB ; X
BAAA  BD4B03        LDA      ICAUX2,X       ; X
BAAD  852B          STA      ICAUX2-IOCB-ZICB ; X
                ;
BAAF  68            PLA
BAB0  A8            TAY
BAB1  20B8BA        JSR      :PDUM
                ;
                ;       RETURN HERE FROM SUBROUTINE
BAB4  98            TYA                     ; TEST STATUS
BAB5  4CB6BC        JMP      IOTES2
                ;
                ;
BAB8            :PDUM
BAB8BD4703          LDA      ICPUT+1,X      ; GO TO PUT ROUTINE
BABB  48            PHA                     ; X
BABC  BD4603        LDA      ICPUT,X        ; X
BABF  48            PHA                     ; X
BAC0  98            TYA                     ; X
BAC1  A092          LDY      #$92           ;LOAD VALUE FOR CIO ROUTINE
BAC3  60            RTS
                ;
BAC4  85C0      GLPCX   STA      IOCMD
BAC6            GLPX
BAC6  86C1          STX      IODVC          ; AS I/O DEVICE
BAC8  4CA6BC        JMP      LDDVX          ; LOAD DEVICE X

;XENTER - Execute ENTER
BACB            XENTER
BACB  A904          LDA      #$04           ; OPEN INPUT
BACD  20DDBA        JSR      ELADVC         ; GO OPEN ALT DEVICE
BAD0  85B4          STA      ENTDTD         ; SET ENTER DEVICE
BAD2  4C60A0        JMP      SYNTAX

;FLIST - Open LIST Device

BAD5            FLIST
BAD5  A908          LDA      #$8            ; OPEN OUTPUT
BAD7  20DDBA        JSR      ELADVC         ; GO OPEN ALT DEVICE
BADA  85B5          STA      LISTDTD        ; SET LIST DEVICE
BADC  60            RTS                     ; DONE
                ;
BADD            ELADVC
BADD  48            PHA
BADE  A007          LDY      #7             ; USE DEVICE 7
BAE0  84C1          STY      IODVC          ; SET DEVICE
                ;
BAE2  20A6BC        JSR      LDDVX          ;BEFORE
BAE5  A90C          LDA      #ICCLOSE       ;GO CLOSE DEVICE
BAE7  2026BD        JSR      IO8            ;OPEN OP NEW ONE
                ;
BAEA  A003          LDY      #ICOIO         ; CMD IS OPEN
BAEC  84C0          STY      IOCMD          ;
BAEE  68            PLA
BAEF  A000          LDY      #0             ; GET AUX2
BAF1  20FBBB        JSR      XOP2           ; GO OPEN

;----------235

BAF4  A907          LDA      #7             ; LOAD DEVICE
BAF6  60            RTS                     ; AND RETURN

;RUN from File

BAF7  A9FF      FRUN    LDA        #$FF     ;SET RUN MODE
BAF9  D002 ^BAFD    BNE      :LD0

;XLOAD - Execute LOAD Command

BAFB            XLOAD
BAFB  A900          LDA      #0             ; SET LOAD MODE
BAFD  48        :LD0    PHA                 ; SAVE R/L TYPE
BAFE  A904          LDA      #04            ; GO OPEN FOR INPUT
BB00  20DDBA        JSR      ELADVC         ; THE SPECIFIED DEVICE
BB03  68            PLA                     ; GET R/L TYPE
                ;
BB04            XLOAD1
BB04  48            PHA                     ; SAVE R/L TYPE
BB05  A907          LDA      #ICGTC         ; CMD IS GET TEXT CHARS
BB07  85C0          STA      IOCMD
BB09  85CA          STA      LOADFLG        ; SET LOAD IN PROGRESS
                ;
BB0B  20A6BC        JSR      LDDVX          ; LOAD DEVICE X REG
BB0E  A00E          LDY      #ENDSTAR-OUTBUFF ; Y=REC LENGTH
BB10  2010BD        JSR      IO3            ; GO GET TABLE BLOCK
BB13  20B3BC        JSR      IOTEST         ; TEST I/O
BB16  AD8005        LDA      MISCRAM+OUTBUFF ; IF FIRST 2
BB19  0D8105        ORA      MISCRAM+OUTBUFF+1 ; BYTES NOT ZERO
BB1C  D038 ^BB56    BNE      :LDFER         ; THEN NOT SAVE FILE
                ;
BB1E  A28C          LDX      #STARP         ; START AT STARP DISPL
BB20  18        :LD1    CLC
BB21  A580          LDA      OUTBUFF        ; ADD LOMEM TO
BB23  7D0005        ADC      MISCRAM,X      ; LOAD TABLE DISPL
BB26  A8            TAY
BB27  A581          LDA      OUTBUFF+1
BB29  7D0105        ADC      MISCRAM+1,X
                ;
BB2C  CDE602        CMP      HIMEM+1        ; IF NEW VALUE NOT
BB2F  900A ^BB3B    BCC      :LD3           ; LESS THAN HIMEM
BB31  D005 ^BB38    BNE      :LD2           ; THEN ERROR
BB33  CCE502        CPY      HIMEM
BB36  9003 ^BB3B    BCC      :LD3
BB38  4C1AB9    :LD2    JMP      ERRPTL
                ;
BB3B  9501      :LD3    STA      1,X        ; ELSE SET NEW TABLE VALUE
BB3D  9400          STY      0,X
BB3F  CA            DEX                     ; DECREMENT TO PREVEOUS TEL
                                              ENTRY
BB40  CA            DEX
BB41  E082          CPX      #VNTP          ; IF NOT AT LOWER ENTRY
BB43  B0DB ^BB20    BCS      :LD1           ; THEN CONTINUE
                ;
BB45  2088BB        JSR      :LSBLK         ; LOAD USER AREA
BB48  2066B7        JSR      XCLR           ; EXECUTE CLEAR
BB4B  A900          LDA      #0             ; RESET LOAD IN-PROGRESS
BB4D  85CA          STA      LOADFLG        ; X
BB4F  68            PLA                     ; LOAD R/S STATUS
BB50  F001 ^BB53    BEQ      :LD4           ; BR IF LOAD
BB52  60            RTS                     ; RETURN TO RUN
BB53            :LD4
BB53  4C50A0        JMP      SNX1           ; GO TO SYNTAX
                ;
BB56            :LDFER
BB56  A900          LDA      #0             ; RESET LOAD IN PROGRESS
BB58  85CA          STA      LOADFLG        ; X
BB5A  2016B9        JSR      ERRNSF         ; NOT SAVE FILE

;----------236

XSAVE - Execute SAVE Command

BB5D            XSAVE
BB5D  A95D          LDA      #08            ; GO OPEN FOR OUTPUT
BB5F  20DDBA        JSR      ELADVC         ; THE SPECIFIED DEVICE
                ;
BB62            XSAVE1
BB62  A90B          LDA      #ICPTC         ; I/O CMD IS PUT TEXT CHARS
BB64  85C0          STA      IOCMD          ; SET I/O CMD
                ;
BB66  A280          LDX      #OUTBUFF       ; MOVE RAM TABLE PTRS
BB68  38        :SV1    SEC                 ; [OUTBUFF THRU ENSTAR]
BB69  B500          LDA      0,X            ; TO LBUFF
BB6B  E580          SBC      OUTBUFF        ; AS DISPLACEMENT
BB6D  9D0005        STA      MISCRAM,X      ; FROM LOW MEM
BB70  E8            INX
BB71  B500          LDA      0,X
BB73  E581          SBC      OUTBUFF+1
BB75  9D0005        STA      MISCRAM,X
BB78  E8            INX
BB79  E08E          CPX      #ENDSTAR
BB7B  90EB ^BB68    BCC      :SV1
                ;
BB7D  20A6BC        JSR      LDDVX          ; OUTPUT LBUFF
BB80  A00E          LDY      #ENDSTAR-OUTBUFF ; FOR PROPER LENGTH
BB82  2010BD        JSR      IO3
BB85  20B3BC        JSR      IOTEST         ; TEST GOOD I/O

;LSBLK - LOAD or SAVE User Area as a Block

BB88            :LSBLK
BB88  20A6BC        JSR      LDDVX          ; LOAD DEVICE X REG
BB8B  A582          LDA      VNTP           ; SET VAR NAME TBL PTR
BB8D  85F3          STA      INBUFF         ; AS START OF BLOCK ADR
BB8F  A583          LDA      VNTP+1
BB91  85F4          STA      INBUFF+1
BB93  AC8D05        LDY      MISCRAM+STARP+1 ; A,Y = BLOCK LENGTH
BB96  88            DEY
BB97  98            TYA
BB98  AC8C05        LDY      MISCRAM+STARP
BB9B  2012BD        JSR      IO4            ; GO DO BLOCK I/O
BB9E  20B3BC        JSR      IOTEST
BBA1  4CF1BC        JMP      CLSYS1         ; GO CLOSE DEVICE
                ;
;XCSAVE - Execute CSAVE

BBA4            XCSAVE
BBA4  A908          LDA      #8             ; GET OPEN FOR OUTPUT
BBA6  20B6BB        JSR      COPEN          ; OPEN CASSETTE
                ;
BBA9  4C62BB        JMP      XSAVE1         ; DO SAVE

;XCLOAD - Execute CLOAD

BBAC             CLOAD
BBAC  A904          LDA      #4             ; GET OPEN FOR OUTPUT
BBAE  20B6BB        JSR      COPEN          ; OPEN CASSETTE
                 ;
BBB1  A900          LDA      #0             ; GET LOAD TYPE
BBB3  4C04BB        JMP      XLOAD1         ; DO LOAD
                 ;
;COPEN - Open Cassette
                 ;      ON ENTRY:   A - TYPE OF OPEN [IN OR OUT]
                 ;      ON EXIT:    A - DEVICE #7
                 ;
BBB6             COPEN
BBB6  48             PHA                    ;
BBB7  A2CE           LDX     #:CSTR&255
BBB9  86F3           STX     INBUFF

;----------237

BBBB  A2BB           LDX     #:CSTR/256
BBBD  86F4           STX     INBUFF+1
                 ;
BBBF  A207           LDX     #7
BBC1  68             PLA
BBC2  A8             TAY                    ; SET COMMAND TYPE
BBC3  A980           LDA     #$80           ; GET AUX 2
                 ;
BBC5  20D1BB         JSR     SOPEN          ; GO OPEN
BBC8  20B3BC         JSR     IOTEST
BBCB  A907           LDA     #7             ; GET DEVICE
BBCD  60             RTS
                 ;
                 ;
                 ;
BBCE  433A9B     :CSTR   DB         'C:',CR

;SOPEN - OPEN System Device
                 ;       ON ENTRY    X - DEVICE
                 ;                   Y - AUX1
                 ;                   A - AUX2
                 ;                   INBUFF - POINTS TO FILE SPEC
                 ;
BBD1             SOPEN
BBD1  48             PHA                    ; SAVE AUX2
BBD2  A903           LDA     #ICOIO         ; GET COMMAND
BBD4  20C4BA         JSR     GLPCX          ; GET DEVICE/COMMAND
BBD7  68             PLA                    ; SET AUX2 & AUX 1
BBD8  9D4B03         STA     ICAUX2,X       ; X
BBDB  98             TYA
BBDC  9D4A03         STA     ICAUX1,X
                 ;
BBDF  2019BD         JSR     IO5            ; DO COMMAND
BBE2  4C51DA         JMP     INTLBF         ; RESET INBUFF

;XXIO - Execute XIO Statement

BBE5             XXIO
BBE5  2004BD         JSR     GIOCMD         ; GET THE COMMAND BYTE
BBE8  4CEDBB         JMP     XOP1           ; CONTINUE AS IF OPEN

;XOPEN - Execute OPEN Statement

BBEB             XOPEN
BBEB  A903           LDA     #ICOIO         ; LOAD OPEN CODE
BBED  85C0       XOP1    STA     IOCMD
BBEF  209FBC         JSR     GIODVC         ; GET DEVICE
                 ;
BBF2  2004BD         JSR     GIOCMD         ; GET AUX1
BBF5  48             PHA
BBF6  2004BD         JSR     GIOCMD         ; GET AUX2
BBF9  A8             TAY                    ; AUX IN Y
BBFA  68             PLA                    ; AUX IN A
BBFB             XOP2
BBFB  48             PHA                    ; SAVE AUX1
BBFC  98             TYA
BBFD  48             PHA                    ; SAVE AUX2
                 ;
BBFE  20E0AA         JSR     EXEXPR         ; GET FS STRING
BC01  2079BD         JSR     SETEOL         ; GIVE STRING AN EOL
                 ;
BC04  20A6BC         JSR     LDDVX          ; LOAD DEVICE X REG
BC07  68             PLA
BC08  9D4B03         STA     ICAUX2,X       ; SET AUX2
BC0B  68             PLA                    ; GET AUX1
BC0C  9D4A03         STA     ICAUX1,X
BC0F  200ABD         JSR     IO1            ; GO DO I/O
                 ;
BC12  2099BD         JSR     RSTSEOL        ; RESTORE STRING EOL

;----------238

BC15  2051DA         JSR     INTLBF
BC18  4CB3BC         JMP     IOTEST         ; GO TEST I/O STATUS

;XCLOSE - Execute CLOSE

BC1B             XCLOSE
BC1B  A90C           LDA     #ICCLOSE       ; CLOSE CMD

;GDVCIO - General Device I/O

BC1D             GDVCIO
BC1D  85C0           STA     IOCMD          ; SET CMD
BC1F  209FBC         JSR     GIODVC         ; GET DEVICE
BC22  2024BD     GDIO1   JSR     IO7        ; GO DO I/O
BC25  4CB3BC         JMP     IOTEST         ; GO TEST STATUS

;XSTATUS - Execute STATUS

BC28             XSTATUS
BC28  209FBC         JSR     GIODVC         ; GET DEVICE
BC2B  A90D           LDA     #ICSTAT        ; STATUS CMD
BC2D  2026BD         JSR     IO8            ; GO GET STATUS
BC30  20FBBC         JSR     LDIOSTA        ; LOAD STATUS
BC33  4C2DBD         JMP     ISVAR1         ; GO SET VAR

;XNOTE - Execute NOTE

BC36             XNOTE
BC36  A926           LDA     #$26           ; NOTE CMD
BC38  201DBC         JSR     GDVCIO         ; GO DO
BC3B  BD4C03         LDA     ICAUX3,X       ; GET SECTOR N/. LOW
BC3E  BC4D03         LDY     ICAUX4,X       ; AND HI
BC41  202FBD         JSR     ISVAR          ; GO SET VAR
BC44  20A6BC         JSR     LDDVX          ; GET DEVICE X REG
BC47  BD4E03         LDA     ICAUX5,X       ; GET DATA LENGTH
BC4A  4C2DBD         JMP     ISVAR1         ; GO SET VAR

;XPOINT - Execute POINT

BC4D             XPOINT
BC4D  209FBC         JSR     GIODVC         ; GET I/O DEVICE NO.
BC50  20D5AB         JSR     GETPINT        ; GET SECTOR NO.
BC53  20A6BC         JSR     LDDVX          ; GET DEVICE X
BC56  A5D4           LDA     FR0            ; SET SECTOR NO.
BC58  9D4C03         STA     ICAUX3,X
BC5B  A5D5           LDA     FR0+1
BC5D  9D4D03         STA     ICAUX4,X
BC60  20D5AB         JSR     GETPINT        ; GET DATA LENGTH
BC63  20A6BC         JSR     LDDVX          ; LOAD DEVICE X
BC66  A5D4           LDA     FR0            ; GET AL
BC68  9D4E03         STA     ICAUX5,X       ; SET DATA LENGTH
BC6B  A925           LDA     #$25           ; SET POINT CMD
BC6D  85C0           STA     IOCMD
BC6F  4C22BC         JMP     GDIO1          ; GO DO

;XPUT - Execute PUT

BC72             XPUT
BC72  209FBC         JSR     GIODVC         ; GET DEVICE #
                 ;
BC75  20E0AB         JSR     GETINT         ; GET DATA
BC78  A5D4           LDA     FR0            ; X
BC7A  A6C1           LDX     IODVC          ; LOAD DEVICE #
BC7C  4CA1BA         JMP     PRCX           ; GO PRINT

;XGET - Execute GET

BC7F             XGET
BC7F  209FBC         JSR     GIODVC         ; GET DEVICE
                 ;
BC82             GET1
BC82  A907           LDA     #ICGTC         ; GET COMMAND
BC84  85C0           STA     IOCMD          ; SET COMMAND

;----------239

BC86  A001           LDA     #1             ; SET BUFF LENGTH=1
BC88  2010BD         JSR     IO3            ; DO IO
BC8B  20B3BC         JSR     IOTEST         ; TEST I/O
BC8E  A000           LDY     #0             ; GET CHAR
BC90  B1F3           LDA     [INBUFF],Y     ; X
BC92  4C2DBD         JMP     ISVAR1         ; ASSIGN VAR

;XLOCATE - Execute LOCATE

BC95             XLOCATE
BC95  2016BA         JSR     XPOS           ; GET X,Y POSITION
BC98  A206           LDX     #6             ; GET DEVICE #
BC9A  20C6BA         JSR     GLPX           ; X
                 ;
BC9D  D0E3 ^BC82     BNE     GET1           ; GO GET

;GIODVC - Get I/O Device Number

BC9F             GIODVC
BC9F  2002BD         JSR     GIOPRM         ; GET PARM
BCA2  85C1           STA     IODVC          ; SET AS DEVICE
BCA4  F00A ^BCB0     BEQ     DNERR          ; BR IF DVC=0

;LDDVX - Load X Register with I/O Device Offset

BCA6             LDDVX
BCA6  A5C1           LDA     IODVC          ; GET DEVICE
BCA8                 ASLA                   ; MULT BY 16
BCA8 +0A             ASL     A
BCA9                 ASLA
BCA9 +0A             ASL     A
BCAA                 ASLA
BCAA +0A             ASL     A
BCAB                 ASLA
BCAB +0A             ASL     A
BCAC  AA             TAX                    ; PUT INTO X
BCAD  3001 ^BCB0     BMI     DNERR          ; BR DN0>7
BCAF  60             RTS                    ; AND RETURN
BCB0  2018B9     DNERR   JSR     ERRDNO

;IOTEST - Test I/O Status

BCB3             IOTEST
BCB3  20FBBC         JSR     LDIOSTA        ; LOAD I/O STATUS
BCB6             IOTES2
BCB6  3001 ^BCB9     BMI     SICKIO         ; BR IF BAD
BCB8  60             RTS                    ; ELSE RETURN
BCB9             SICKIO
BCB9  A000           LDY     #0             ; RESET DISPLAY FLAG
BCBB  8CFE02         STY     DSPFLG
                 ;
BCBE  C980           CMP     #ICSBRK        ; IF BREAK
BCC0  D00A ^BCCC     BNE     :SIO1          ; SIMULATE ASYNC
BCC2  8411           STY     BRKBYT         ; BREAK
BCC4  A5CA           LDA     LOADFLG        ;IF LOAD FLAG SET
BCC6  F003 ^BCCB     BEQ     :SIOS          ;
BCC8  4C00A0         JMP     COLDSTART      ;DO COLDSTART
BCCB             :SIOS
BCCB  60             RTS
                 ;
BCCC  A4C1       :SIO1   LDY     IODVC      ; PRE-LOAD I/O DEVICE
BCCE  C988           CMP     #$88           ; WAS ERROR EOF
BCD0  F00F ^BCE1     BEQ     :SIO4          ; BR IF EOF
BCD2  85B9       :SIO2   STA     ERRNUM     ; SET ERROR NUMBER
                 ;
BCD4  C007           CPY     #7             ; WAS THIS DEVICE #7
BCD6  D003 ^BCDB     BNE     :SIO3          ; BR IF NOT
BCD8  20F1BC         JSR     CLSYSD         ; CLOSE DEVICE 7
                 ;
BCDB  2072BD     :SIO3   JSR     SETDZ      ; SET L/D DEVICE = 0
BCDE  4C40B9         JMP     ERROR          ; REPORT ERROR
                 ;

;----------240

BCE1  C007       :SIO4   CPY     #7         ; WAS EOF ON DEVICE 7
BCE3  D0ED ^BCD2     BNE     :SIO2          ; BR IF NOT
BCE5  A25D           LDX     #EPCHAR        ; WERE WE IN ENTER
BCE7  E4C2           CPX     PROMPT         ;
BCE9  D0E7 ^BCD2     BNE     :SIO2          ; BR NOT ENTER
BCEB  20F1BC         JSR     CLSYSD         ; CLOSE DEVICE 7
BCEE  4C53A0         JMP     SNX2           ; GO TO SYNTAX

;CLSYSD - Close System Device

BCF1             CLSYSD
                 ;
BCF1  20A6BC     CLSYS1  JSR       LDDVX
BCF4  F00B ^BD01     BEQ     NOCD0          ; DON'T CLOSE DEVICE0
BCF6  A90C           LDA     #ICCLOSE       ; LOAD CLOSE CORD
BCF8  4C26BD         JMP     IO8            ; GO CLOSE

;LDIOSTA - Load I/O Status

BCFB             LDIOSTA
BCFB  20A6BC         JSR     LDDVX          ; GET DEVICE X REG
BCFE  BD4303         LDA     ICSTA,X        ; GET STATUS
BD01             NOCD0
BD01  60             RTS                    ; RETURN

;GIOPRM - Get I/O Parameters

BD02             GIOPRM
BD02  E6A8           INC     STINDEX        ; SKIP OVER #
BD04  20D5AB     GIOCMD  JSR     GETPINT    ; GET POSITIVE INT
BD07  A5D4           LDA     FR0            ; MOVE LOW BYTE TO
BD09  60             RTS

;I/O Call Routine

BD0A  A0FF       IO1     LDY     #255       ; BUFL = 255
BD0C  D002 ^BD10     BNE     IO3
BD0E  A000       IO2     LDY     #0         ; BUFL = 0
BD10  A900       IO3     LDA     #0         ; BUFL < 256
BD12  9D4903     IO4     STA     ICBLH,X    ; SET BUFL
BD15  98             TAY
BD16  9D4803         STA     ICBLL,X
BD19  A5F4       IO5     LDA     INBUFF+1   ; LOAD INBUFF VALUE
BD1B  A4F3           LDY     INBUFF
BD1D  9D5403     IO6     STA     ICBAH,X    ; SE BUF ADR
BD20  98             TAY
BD21  9D4403         STA     ICBAL,X
BD24  A5C0       IO7     LDA     IOCMD      ; LOAD COMMAND
BD26  9D4203     IO8     STA     ICCOM,X    ; SET COMMAND
BD29  2056E4         JSR     CIO            ;GO DO I/O
BD2C  60             RTS                    ; DONE

;ISVAR - I/O Variable Set

BD2D             ISVAR1
BD2D  A000           LDY     #0             ; GET HIGH ORDER BYTE
BD2F             ISVAR
BD2F  48             PHA                    ; PUSH INT VALUE LOW
BD30  98             TYA
BD31  48             PHA                    ; PUSH INT VALUE HI
BD32  200FAC         JSR     POP1           ; GET VARIABLE
BD35  68             PLA
BD36  85D5           STA     FR0+1          ; SET VALUE LOW
BD38  68             PLA
BD39  85D4           STA     FR0            ; SET VALUE HI
BD3B  20AAD9         JSR     CVIFP          ; CONVERT TO FP
BD3E  4C16AC         JMP     RTNVAR         ; AND RETURN TO TABLE

;----------241

;CLALL - CLOSE All IOCBS [except 0]

BD41             CLSALL
                 ;
                 ; TURN OFF SOUND
                 ;
BD41  A900           LDA     #0
BD43  A207           LDX     #7
BD45             :CL
BD45  9D00D2         STA     SREG3-1,X
BD48  CA             DEX
BD49  D0FA ^BD45     BNE     :CL
                 ;
BD4B  A007           LDY     #7             ; START AT DEVICE 7
BD4D  84C1           STY     IODVC
BD4F  20F1BC     CLALL1  JSR     CLSYSD     ; CLOSE DEVICE
BD52  C6C1           DEC     IODVC          ; DEC DEVICE #
BD54  D0F9 ^BD4F     BNE     CLALL1         ; BR IF NOT ZERO
BD56  60             RTS

;PREADY - Print READY Message

BD57             PREADY
BD57  A206           LDX     #RML-1         ; GET READY MSG LENGTH-1
BD59  86F2       PRDY1   STX     CIX        ; SET LEN REM
BD5B  BD67BD         LDA     RMSG,X         ; GET CHAR
BD5E  209FBA         JSR     PRCHAR         ; PRINT IT
BD61  A6F2           LDX     CIX            ; GET LENGTH
BD63  CA             DEX
BD64  10F3 ^BD59     BPL     PRDY1          ; BR IF MORE
BD66  60             RTS
BD67  9B59444145 RMSG    DB      CR,'YDAER',CR
      529B
      = 0007     RML     EQU     *-RMSG

;PRCR - Print Carriage Return

BD6E  A200       PRCR    LDX     #0         ; SET FOR LAST CHAR
BD70  F0E7 ^BD59     BEQ     PRDY1          ; AND GO DO IT

;SETDZ - Set Device 0 as LIST/ENTER Device

BD72  A900       SETDZ   LDA     #0
BD74  85B4           STA     ENTDTD
BD76  85B5           STA     LISTDTD
BD78  60             RTS

;SETEOL - Set EOL [Temporarily] after String EOL

BD79             SETSEOL
BD79  2098AB         JSR     AAPSTR         ; GET STRING WITH ABS ADR
BD7C  A5D4           LDA     FR0-2+EVSADR   ; PUT IT'S ADR
BD7E  85F3           STA     INBUFF         ; INTO INBUFF
BD80  A5D5           LDA     FR0-1+EVSADR
BD82  85F4           STA     INBUFF+1
                 ;
BD84  A4D6           LDY     FR0-2+EVSLEN   ; GET LENGTH LOW
BD86  A6D7           LDX     FR0-1+EVSLEN   ; IF LEN < 256
BD88  F002 ^BD8C     BEQ     :SSE1          ; THEN BR
BD8A  A0FF           LDY     #$FF           ; ELSE SET MAX
                 ;
BD8C  B1F3       :SSE1   LDA     [INBUFF],Y ; GET LAST STR CHAR+1
BD8E  8597           STA     INDEX2         ; SAVE IT
BD90  8498           STY     INDEX2+1       ; AND IT'S INDEX
BD92  A99B           LDA     #CR            ; THEN REPLACE WITH EOL
BD94  91F3           STA     [INBUFF],Y
BD96  8592           STA     MEOFLG         ; INDICATE MODIFIED EOL
BD98  60             RTS                    ; DONE
                 ;
BD99             RSTSEOL                    ; RESTORE STRING CHAR
BD99  A498           LDY     INDEX2+1       ; LOAD INDEX

;----------242

BD9B  A597           LDA     INDEX2         ; LOAD CHAR
BD9D  91F3           STA     [INBUFF],Y     ; DONE
BD9F  A900           LDA     #0             ;
BDA1  8592           STA     MEOFLG         ; RESET EOL FLAG
BDA3  60             RTS                    ; DONE
BDA4  =0001      PATCH   DS     PATSIZ

                 ;        SIN[X] and COS[X]
                 ;
BDA5  38         SINERR  SEC    ;ERROR - SET CARRY
BDA6  60             RTS
                 ;
                 ;
BDA7  A904       SIN     LDA    #4          ; FLAG SIN[X] ENTRY RIGHT NOW
BDA9  24D4           BIT     FR0
BDAB  1006 ^BDB3     BPL     BOTH
BDAD  A902           LDA     #2             ; SIN[-X]
BDAF  D002 ^BDB3     BNE     BOTH
BDB1  A901       COS     LDA     #1         ;FLAG COS[X] ENTRY
BDB3  85F0       BOTH    STA     SGNFLG
BDB5  A5D4           LDA     FR0            ; FORCE POSITIVE
BDB7  297F           AND     #$7F
BDB9  85D4           STA     FR0
BDBB  A95F           LDA     #PIOV2&$FF
BDBD  18             CLC
BDBE  65FB           ADC     DEGFLG
BDC0  AA             TAX
BDC1  A0BE           LDY     #PIOV2/$100
BDC3  2098DD         JSR     FLD1R
BDC6  2028DB         JSR     FDIV           ; X/[PI/2] OR X/90
BDC9  9001 ^BDCC     BCC     SINF7
BDCB  60         SINOVF  RTS                ; OVERFLOW
BDCC             SIN7
BDCC  A5D4           LDA     FR0
BDCE  297F           AND     #$7F           :CHECK EXPONENT
BDD0  38             SEC
BDD1  E940           SBC     #$40
BDD3  302B ^BE00     BMI     SINF3          ; QUADRANT 0 - USE AS IS
BDD5  C904       SIN6    CMP     #FPREC-2   ; FIND QUAD NO & REMAINDER
BDD7  10CC ^BDA5     BPL     SINERR         ; OUT OF RANGE
BDD9  AA             TAX                    ; X->LSB OR FR0
BDDA  B5D5           LDA     FR0+1,X        ; LSB
BDDC  85F1           STA     XFMLG
BDDE  2910           AND     #$10           ; CHECK 10'S DIGIT
BDE0  F002 ^BDE4     BEQ     SINF5
BDE2  A902           LDA     #2             ; ODD -ADD 2 TO QUAD #
BDE4  18         SINF5   CLC
BDE5  65F1           ADC     XFMFLG
BDE7  2903           AND     #3             ; QUADRANT = 0,1,2,3
BDE9  65F0           ADC     SGNFLG         ; ADJUST FOR SINE VS COSINE
BDEB  85F0           STA     SGNFLG
BDED  86F1           STX     XFMFLG         ; SAVE DEC PT LOC
BDEF  20B6DD         JSR     FMOVE          ; COPY TO FR1
BDF2  A6F1           LDX     XFMFLG
BDF4  A900           LDA     #0
BDF6  95E2       SINF1   STA     FR1+2,X    ; CLEAR FRACTION
BDF8  E8             INX
BDF9  E003           CPX     #FPREC-3
BDFB  90F9 ^BDF6     BCC     SINF1
BDFD  2060DA         JSR     FSUB           ; LEAVE REMAINDER
BE00  46F0       SINF3   LSR     SGNFLG     ; WAS QUAD ODD
BE02  900D ^BE11     BCC     SINF4          ; NO
BE04  20B6DD         JSR     FMOVE          ; YES - USE 1.0 - REMAINDER
BE07  A271           LDX     #FPONE&FF
BE09  A0BE           LDY     #FPONE/$100
BE0B  2089DD         JSR     FLD0R
BE0E  2060DA         JSR     FSUB
BE11             SINF4                      ; NOW DO THE SERIES THING
BE11  A2E6           LDX     #FPSCR&$FF     ; SAVE ARG
BE13  A005           LDY     #FPSCR/$100

;----------243

BE15  20A7DD         JSR     FST0R
BE18  20B6DD         JSR     FMOVE          ;X->FR1
BE1B  20DBDA         JSR     FMUL           ;X**2->FR0
BE1E  B085 ^BDA5     BCS     SINERR
BE20  A906           LDA     #NSCF
BE22  A241           LDX     #SCOEF&FF
BE24  A0BE           LDY     #SCOEF/$100
BE26  2040DD         JSR     PLYEVL         ; EVALUATE P[X**2]
BE29  A2E6           LDX     #FPSCR&$FF
BE2B  A005           LDY     #FPSCR/$100
BE2D  2098DD         JSR     FLD1R          ; X-> FR1
BE30  20DBDA         JSR     FMUL           ; SIN[X] = X*P[X**2]
BE33  46F0           LSR     SGNFLG         ; WAS QUEAD 2 OR 3?
BE35  9009 ^BE40     BCC     SINDON         ; NO - THRU
BE37  18             CLC                    ; YES
BE38  A5D4           LDA     FR0            ; FLIP SIGN
BE3A  F004 ^BE40     BEQ     SINDON         ; [UNLESS ZERO]
BE3C  4980           EOR     #$80
BE3E  85D4           STA     FR0
BE40  60         SINDON  RTS                ; RETURN
BE41  BD03551599 SCOEF   .BYTE   $BD,$03,$55,$14,$99,$39 ; -.0000035419939
      39
BE47  3E01604427     .BYTE   $3E,$01,$60,$44,$27,$52 ; 0.000160442752
      52
BE4D  BE46817543     .BYTE   $BE,$46,$81,$75,$43,$55 ; -.004681754355
      55
BE53  3F07968262     .BYTE   $3F,$07,$96,$92,$62,$39 ; 0.0796926239
      39
BE59  BF64596408     .BYTE   $BF,$64,$59,$64,$08,$67 ; -.6459640867
      67
BE5F  4001570796 PIOV2   .BYTE    $40,$01,$57,$07,$96,$32 ;PI/2
      32
      = 0006     NSCF    EQU      (*-SCOEF)/FPREC
BE65  4090000000     .BYTE   $40,$90,0,0,0,0 ; 90 DEG
      00
BE6B  3F01745329     .BYTE   $3F,$01,$74,$53,$29,$25 ;PI/180
      25
BE71  4001000000 FPONE   .BYTE    $40,$1,0,0,0,0  ;1.0
      00

                 ;        ATAN[X] - Arctangent

BE77  A900       ATAN    LDA    #0          ; ARCTAN[X]
BE79  85F0           STA     SGNLFG         ; SIGN FLAG OFF
BE7B  85F1           STA     XFMFLG         ; & TRANSFORM FLAG
BE7D  A5D4           LDA     FR0
BE7F  297F           AND     #$7F
BE81  C940           CMP     #$40           ; CHECK X VS 1.0
BE83  3015 ^BE9A     BMI     ATAN1          ; X<1.0 - USE SERIES DIRECTLY
BE85  A5D4           LDA     FR0            ; X>=1.0 - SAVE SIGN & TRANSFORM
BE87  2980           AND     #$80
BE89  85F0           STA     SGNFLG         ; REMEMBER FLAG
BE8B  E6F1           INC     XFMFLG
BE8D  A97F           LDA     #$7F
BE8F  25D4           AND     FR0
BE91  85D4           STA     FR0            ; FORCE PLUS
BE93  A2EA           LDX     #FPS&$FF
BE95  A0DF           LDY     #FP9S/$100
BE97  2095DE         JSR     XFORM          ; CHANGE ARG TO [X-1]/[X+1]
BE9A             ATAN1
BE9A  A2E6           LDX     #FPSCR&$FF     ; ARCTAN[X], -1<X<1 BY SERIES
                                              OF APPROXIMATIONS
BE9C  A005           LDY     #FPSCR/$100
BE9E  20A7DD         JSR     FST0R          ;X->FSCR
BEA1  20B6DD         JSR     FMOVE          ; X->FR1
BEA4  20DBDA         JSR     FMUL           ; X*X->FR0
BEA7  B039 ^BEE2     BCS     ATNOUT         ; 0'FLOW
BEA9  A90B           LDA     #NATCF
BEAB  A2AE           LDX     #ATCOEF&$FF
BEAD  A0DF           LDY     #ATCOEF/$100

;----------244

BEAF  2040DD         JSR     PLYEVL         ;P[X*X]
BEB2  B02E ^BEE2     BCS     ATNOUT
BEB4  A2E6           LDX     #FPSCR&$FF
BEB6  A005           LDY     #FPSCR/$100
BEB8  2098DD         JSR     FLD1R          ;X->FR1
BEBB  20DBDA         JSR     FMUL           ;X*P[X*X]
BEBE  B022 ^BEE2     BCS     ATNOUT         ; O'FLOW
BEC0  A5F1           LDA     XFMFLG         ; WAS ARG XFORM'D
BEC2  F010 ^BED4     BEQ     ATAN2          ; NO
BEC4  A2F0           LDX     #PIOV4&$FF     ; YES-ADD ARCTAN [1.0] = PI/4
BEC6  A0DF           LDY     #PIOV4/$100
BEC8  2098DD         JSR     FLD1R
BECB  2066DA         JSR     FADD
BECE  A5F0           LDA     SGNFLG         ; GET ORG SIGN
BED0  05D4           ORA     FR0
BED2  85D4           STA     FR0            ; ATAN[-X] = - ATAN[X]
BED4  A5FB       ATAN4   LDA     DEGFLAG    ; RADIANS OR DEGREES
BED6  F00A ^BEE2     BEQ     ATNOUT         ; RAD - FINI
BED8  A26B           LDX     #PIOV18&$FF    ; DEG - DIVIDE BY PI/100
BEDA  A0BE           LDY     #PIOV18/$100
BEDC  2098DD         JSR     FLD1R
BEDF  2028DB         JSR     FDIV
BEE2  60         ATNOUT  RTS

                 ;       SQR[X] - Square Root
                 ;
BEE3  38         SQRERR  SEC                ; SET FAIL
BEE4  60             RTS
                 ;
BEE5  A900       SQR     LDA     #0
BEE7  85F1           STA     XFMFLG
BEE9  A5D4           LDA     FR0
BEEB  30F6 ^BEE3     BMI     SQRERR
BEED  C93F           CMP     #$3F
BEEF  F017           BEQ     FSQR           ; X IN RANGE OF APPROX - GO DO
BEF1  18             CLC
BEF2  6901           ADC     #1
BEF4  85F1           STA     XFMFLG         ; NOT IN RANGE - TRANSFORM
BEF6  85E0           STA     FR1            ; MANTISSA = 1
BEF8  A901           LDA     #1
BEFA  85E1           STA     FR1+1
BEFC  A204           LDX     #FPREC-2
BEFE  A900           LDA     #0
BF00  95E2       SQR1    STA     FR1+2,X
BF02  CA             DEX
BF03  10FB ^BF00     BPL     SQR1
BF05  2028DB         JSR     FDIV           ; X/100**N
BF08             FSQR                       ;SQR[X], 0.1<=X<1.0
BF08  A906           LDA     #6
BF0A  85EF           STA     SQRCNT
BF0C  A2E6           LDX     #FSCR&$FF
BF0E  A005           LDY     #FSCR/$100
BF10  20A7DD         JSR     FST0R          ;STASH X IN FSCR
BF13  20B6DD         JSR     FMOVE          ;X->FR1
BF16  A293           LDX     #FTWO&$FF
BF18  A0BF           LDY     #FTWO/$100
BF1A  2089DD         JSR     FLD0R          ;2.0->FR0
BF1D  2060DA         JSR     FSUB           ;2.0-X
BF20  A2E6           LDX     #FSCR&$FF
BF22  A005           LDY     #FSCR/$100
BF24  2098DD         JSR     FLD1R          ;X->FR1
BF27  20DBDA         JSR     FMUL           ;X*[2.0-X] :1ST APPROX
BF2A  A2EC       SQRLP   LDX     #FSCR1&$FF
BF2C  A005           LDY     #FSCR1/$100
BF2E  20A7DD         JSR     FST0R          ;Y->FSCR1
BF31  20B6DD         JSR     FMOVE          ;Y->FR1
BF34  A2E6           LDX     #FSCR&$FF
BF36  A005           LDY     #FSCR/$100
BF38  2089DD         JSR     FLD0R

;----------245

BF3B  2028DB         JSR     FDIV           ;X/Y
BF3E  A2EC           LDX     #FSCR1&$FF
BF40  A005           LDY     #FSCR1/$100
BF42  2098DD         JSR     FLD1R
BF45  2060DA         JSR     FSUB           ;[X/Y]-Y
BF48  A26C           LDX     #FHALF&$FF
BF4A  A0DF           LDY     #FHALF/$100
BF4C  2098DD         JSR     FLD1R
BF4F  20DBDA         JSR     FMUL           ;0.5*[[X/Y]-Y]=DELTAY
BF52  A5D4           LDA     FR0            ;DELTA 0.0
BF54  F00E ^BF64     BEQ     SQRDON
BF56  A2EC           LDX     #FSCR1&$FF
BF58  A005           LDY     #FSCR1/$100
BF5A  2098DD         JSR     FLD1R
BF5D  2066DA         JSR     FADD           ;Y=Y+DELTA Y
BF60  C6EF           DEC     SQRCNT         ; COUNT & LOOP
BF62  10C6 ^BF2A     BPL     SQRLP
BF64  A2EC       SQRDON  LDX     #FSCR1&$FF     ; DELTA = 0 - GET Y BACK
BF66  A005           LDY     #FSCR1/$100
BF68  2089DD         JSR     FLD0R
                 ;       WAS ARG TRANSFORMED
BF6B  A5F1           LDA     XFMFLG
BF6D  F023 ^BF92     BEQ     SQROUT         ; NO FINI
BF6F  38             SEC
BF70  E940           SBC     #$40
BF72  18             CLC                    ; YES - TRANSFORM RESULT
BF73                 RORA                   ; DEVIDE EXP BY 2
BF73 +6A             ROR     A
BF74  18             CLC
BF75  6940           ADC     #$40
BF77  297F           AND     #$7F
BF79  85E0           STA     FR1
BF7B  A5F1           LDA     XFMFLG
BF7D                 RORA
BF7D +6A             ROR     A
BF7E  A901           LDA     #1             ; MANTISSA = 1
BF80  9002 ^BF84     BCC     SQR2           ; WAS EXP ODD OR EVEN
BF82  A910           LDA     #$10           ; ODD - MANT = 10
BF84  85E1       SQR2    STA     F1+1
BF86  A204           LDX     #FPREC-2
BF88  A900           LDA     #0
BF8A  95E2       SQR3    STA     FR1+2,X    ; CLEAR REST OF MANTISSA
BF8C  CA             DEX
BF8D  10FB ^BF8A     BPL     SQR3
BF8F  20DBDA         JSR     FMUL           ; SQR[X] = SQR[X/100*N]
                                              * [10**N]
BF92  60         SQROUT  RTS
BF93  4002000000 FTWO    .BYTE   $40,2,0,0,0,0  ; 2.0
      00

                 ;           Floating Point

BF99  =D800          ORG     FPORG
D800                 LOCAL

;ASCIN - Convert ASCII Input to Internal Form
                 ;       ON ENTRY   INBUFF - POINTS TO BUFFER WITH ASCII
                 ;                  CIX - INDEX TO 1ST BYTE OF #
                 ;
                 ;       ON EXIT    CC SET - CARRY SET IF NOT #
                 ;                           CARRY CLEAR OF #
                 ;
D800             AFP
D800             CVAFP
D800             ASCIN
D800  20A1DB         JSR     SKPBLANK
D803  20BBDB         JSR     :TSTCHAR       ; SEE IF THIS COULD BE A NUMBER
D806  B039 ^D841     BCS     :NONUM         ; BR IF NOT A NUMBER

;----------246

                 ;
                 ;       SET INITIAL VALUES
                 ;
D808  A2ED           LDX     #EEXP          ; ZERO 4 VALUES
D80A  A004           LDY     #4             ; X
D80C  2048DA         JSR     ZXLY           ; X
D80F  A2FF           LDX     #$FF
D811  86F1           STX     DIGRT          ; SET TO $FF
                 ;
D813  2044DA         JSR     ZFR0           ; CLEAR FR0
                 ;
D816  F004 ^D81C     BEQ     :IN2           ; UNCONDITIONAL BR
                 ;
                 ;
D818             :IN1
D818  A9FF           LDA     #$FF           ; SET 1ST CHAR TO NON
                                              ZERO
D81A  85F0           STA     FCHRFLG        ; X
                 ;
D81C             :IN2
D81C  2094D8         JSR     :GETCHAR       ; GET INPUT CHAR
D81F  B21 ^D842      BCS     :NON1          ; BR IF CHAR NOT NUMBER
                 ;
                 ;
                 ;       IT'S A NUMBER
                 ;
D821  48             PHA                    ; SAVE ON CPU STACK
D822  A6D5           LDX     FR0M           ; GET 1ST BYTE
D824  D011 ^D837     BNE     :INCE          ; INCR EXPONENT
                 ;
D826  20EBDB         JSR     NIBSH0         ; SHIFT FR0 ONE NIBBLE LEFT
                 ;
D829  68             PLA                    ; GET DIGIT ON CPU STACK
D82A  05D9           ORA     FR0M+FMPREC-1  ; OR INTO LAST BYTE
D82C  85D9           STA     FR0M+FMPREC-1  ; SAVE AS LAST BYTE
                 ;
                 ;       COUNT CHARACTERS AFTER DECIMAL POINT
                 ;
D82E  A6F1           LDX     DIGRT          ; GET # OF DIGITS RIGHT
D830  30E6 ^D818     BMI     :IN1           ; IF = $FF, NO DECIMAL POINT
D832  E8             INX                    ; ADD IN THIS CHAR
D833  86F1           STX     DIGRT          ; SAVE
D835  D0E1 ^D818     BNE     :IN1           ; GET NEXT CHAR
                 ;
                 ;
                 ;       INCREMENT # OR DIGIT MAORE THAN 9
                 ;
                 ;
D837             :INCE
D837  68             PLA                    ; CLEAR CPU STACK
D838  A6F1           LDX     DIGRT          ; HAVE DP?
D83A  1002 ^D93E     BPL     :INCE2         ; IF YES, DON'T INCR E COUNT
D83C  E6ED           INC     EEXP           ; INCR EXPONENT
D83E             :INCE2
D83E  4C18D8         JMP     :IN1           ; GET NEXT CHAR
                 ;
                 ;
D841             :NONUM
D841  60             RTS                    ; RETURN FAIL
                 ;
                 ;       NON-NUMERIC IN NUMBER BODY
                 ;
D842             :NON1
D842  C92E           CMP     #'.'           ; IS IT DECIMAL POINT?
D844  F014 ^D85A     BEQ     :DP            ; IF YES, PROCESS IT
D846  C945           CMP     #'E'           ; IS IT E FOR EXPONENT?
D848  F019 ^D863     BEQ     :EXP           ; IF YES, DO EXPONENT
                 ;
D84A  A6F0           LDX     FCHRFLG        ; IS THIS THE 1ST CHAR
D84C  D068 ^D8B6     BNE     :EXIT          ; IF NOT, END OF NUMERIC INPUT
D84E  C92B           CMP     #'+'           ; IS IT PLUS?

;----------247

D850  F0C6 ^D818     BEQ     :IN1           ; GO FOR NEXT CHAR
D852  C92D           CMP     #'-'           ; IS IT MINUS?
D854  F000           BEQ     :MINUS
                 ;
                 ;
D856             :MINUS
D856  85EE           STA     NSIGN          ; SAVE SIGN FOR LATER
D858  F0BE ^D818     BEQ     :IN1           ; UNCONDITIONAL BRANCH FOR
                                              NEXT CHAR
                 ;
D85A             :DP
D85A  A6F1           LDX     DIGRT          ; IS DIGRT STILL = FF?
D85C  1050 ^D8B6     BPL     :EXIT          ; IF NOT, ALREADY HAVE DP
D85E  E8             INX                    ; INCR TO ZERO
D85F  86F1           STX     DIGRT          ; SAVE
D861  F0B5 ^D818     BEQ     :IN1           ; UNCONDITIONAL BR FOR NEXT
                                              CHAR
                 ;
D863             :EXP
D863  A5F2           LDA     CIX            ; GET INDEX
D865  85EC           STA     FRX            ; SAVE
D867  2094DB         JSR     :GETCHAR       ; GET NEXT CHAR
D86A  B037 ^D8A3     BCS     :NON2          ; BR IF NOT NUMBER
                 ;
                 ;       IT'S A NUMBER IN AN EXPONENT
                 ;
D86C             :EXP2
D86C  AA             TAX                    ; SAVE 1ST CHAR OF EXPONENT
D86D  A5ED           LDA     EEXP           ; GET # OF CHAR OVER 9
D86F  48             PHA                    ; SAVE IT
D870  86ED           STX     EEXP           ; SAVE 1ST CHAR OF EXPONENT
D872  2094DB         JSR     :GETCHAR       ; GET NEXT CHAR
                 ;
                 ;
D875  B017 ^D88E     BCS     :EXP3          ; IF NOT # NO SECOND DIGIT
D877  48             PHA                    ; SAVE SECOND DIGIT
                 ;
D878  A5ED           LDA     EEXP           ; GET 1ST DIGIT
D87A                 ASLA                   ; GET DIGIT * 10
D87A +0A             ASL     A
D87B  85ED           STA     EEXP           ; X
D87D                 ASLA                   ; X
D87D +0A             ASL     A
D87E                 ASLA                   ; X
D87E +0A             ASL     A
D87F  65ED           ADC     EEXP           ; X
D881  85ED           STA     EEXP           ; SAVE
D883  68             PLA                    ; GET SECOND DIGIT
D884  18             CLC
D885  65ED           ADC     EEXP           ; GET EXPONENT INPUTTED
D887  85ED           STA     EEXP           ; SAVE
                 ;
D889  A4F2           LDY     CIX            ; INC TO NEXT CHAR
D88B  209DDB         JSR     :GCHR1         ; X
                 ;
                 ;
D88E             :EXP3
D88E  A5EF           LDA     ESIGN          ; GET SIGN OF EXPONENT
D890  F009 ^D89B     BEQ     :EXP1          ; IF NO SIGN, IT IS +
D892  A5ED           LDA     EEXP           ; GET EXPONENT ENTERED
D894  49FF           EOR     #$FF           ; COMPLEMENT TO MAKE MINUS
D896  18             CLC                    ; X
D897  6901           ADC     #1             ; X
D899  85ED           STA     EEXP           ; SAVE
D89B             :EXP1
D89B  68             PLA                    ; GET # DIGITS MORE THAN 9
D89C  18             CLC                    ; CLEAR CARRY
D89D  65ED           ADC     EEXP           ; ADD IN ENTERED EXPONENT
D89F  85ED           STA     EEXP           ; SAVE EXPONENT
D8A1  D013 ^D8B6     BNE     :EXIT          ; UNCONDITIONAL BR

;----------248

                 ;
                 ;       NON NUMERIC IN EXPONENT
                 ;
D8A3             :NON2
D8A3  C92B           CMP     #'+'           ; IS IT PLUS?
D8A5  F006 ^D8AD     BEQ     :EPLUS         ; IF YES BR
D8A7  C92D           CMP     #'-'           ; IS IT A MINUS?
D8A9  D007 ^D8B2     BNE     :NOTE          ; IF NOT, BR
                 ;
                 ;
D8AB             :EMIN
D8AB  85EF           STA     ESIGN          ; SAVE EXPONENET SIGN
D8AD             :EPLUS
D8AD  2094DB         JSR     :GETCHAR       ; GET CHARACTER
D8B0  90BA ^D86C     BCC     :EXP2          ; IF A #, GO PROCESS EXPONENT
                 ;
                 ;
                 ;
                 ;       E IS NOT PART OF OUR #
                 ;
D8B2             :NOTE
D8B2  A5EC           LDA     FRX            ; POINT TO 1 PAST E
D8B4  85F2           STA     CIX            ; RESTORE CIX
                 ;
                 ;       FALL THRU TO EXIT
                 ;
                 ;       WHOLE # HAS BEEN INPUTTED
                 ;
D8B6             :EXIT
                 ;
                 ;       BACK UP ONE CHAR
                 ;
D8B6  C6F2           DEC     CIX            ; DECREMENT INDEX
                 ;
                 ;
                 ;       CALCULATE POWER OF 10 = EXP - DIGITS RIGHT
                 ;       WHERE EXP = ENTERED [COMPLEMENT OF -]
                 ;               + # DIGITS MORE THAN 9
                 ;
D8B8  A5ED           LDA     EEXP           ; GET EXPONENT
D8BA  A6F1           LDX     DIGRT          ; GET # DIGITS OF DECIMAL
D8BC  3005 ^D8C3     BMI     :EXIT1         ; NO DECIMAL POINT
D8BE  F003 ^D8C3     BEQ     :EXIT1         ; # OF DIGITS AFTER D.P.=0
D8C0  38             SEC                    ; GET EXP - DIGITS RIGHT
D8C1  E5F1           SBC     DIGRT          ; X
                 ;
                 ;       SHIFT RIGHT ALGEBRAIC TO DIVIDE BY 2 = POWER OF 100
                 ;
D8C3             :EXIT1
D8C3  48             PHA
D8C4                 ROLA                   ; SET CARRY WITH SIGN OF
                                              EXPONENT
D8C4 +2A             ROL     A
D8C5  68             PLA                    ; GET EXPONENT AGAIN
D8C6                 RORA                   ; SHIFT RIGHT
D8C6 +6A             ROR     A
D8C7  85ED           STA     EEXP           ; SAVE POWER OF 100
D8C9  9003 ^D8CE     BCC     :EVEN          ; IF NO CARRY # EVEN
                 ;
D8CB  20EBDB         JSR     NIBSH0         ; ELSE SHIFT 1 NIBBLE LEFT
D8CE             :EVEN
D8CE  A5ED           LDA     EEXP           ; ADD 40 FOR EXCESS 64 + 4
                                              FOR NORM
D8D0  18             CLC                    ; X
D8D1  6944           ADC     #$44           ; X
D8D3  85D4           STA     FR0            ; SAVE AS EXPONENT
                 ;
D8D5  2000DC         JSR     NORM           ; NORMALIZE NUMBER
D8D8  B00B ^D8E5     BCS     :IND2          ; IF CARRY SET, IT'S AN ERROR
                 ;

;----------249
                 ;       SET MANTISSA SIGN
                 ;
D8DA  A6EE           LDX     NSIGN          ; IS SIGN OF # MINUS
D8DC  F006 ^D8E4     BEQ     :INDON         ; IF NOT, BR
                 ;
D8DE  A5D4           LDA     FR0            ; GET EXPONENT
D8E0  0980           ORA     #$80           ; TURN ON MINUS # BIT
D8E2  85D4           STA     FR0            ; SET ON FR0 EXP
D8E4             :INDON
D8E4  18             CLC                    ; CLEAR CARRY
D8E5             :IND2
D8E5  60             RTS

;FPASC - Convert Floating Point to ASCII
                 ;       ON ENTRY    FR0 - # TO CONVERT
                 ;
                 ;       ON EXIT     INBUFF - POINTS TO START OF #
                 ;                   HIGH ORDER BIT OF LAST BYTE IS ON
                 ;
                 ;
D8E6             CVFASC
D8E6             FASC
D8E6  2051DA         JSR     INTLBF         ;SET INBUFF TO PT TO LBUFF
                 ;
D8E9  A930           LDA     #'0'           ; GET ASCII ZERO
D8EB  8D7F05         STA     LBUFF-1        ; PUT IN FRONT OF LBUFF
                 ;
                 ;       TEST FOR E FORMAT REQUIRED
                 ;
D8EE  A5D4           LDA     FR0            ; GET EXPONENT
D8F0  F028 ^D91A     BEQ     :EXP0          ; IF EXP = 0, # = 0, SO BR
D8F2  297F           AND     #$7F           ; AND OUT SIGN
D8F4  C93F           CMP     #$3F           ; IS IT LESS THAN 3F
D8F6  9028 ^D920     BCC     :EFORM         ; IF YES, E FORMAT REQUIRED
D8F8  C945           CMP     #$45           ; IF IT IS > 44
D8FA  B024 ^D920     BCS     :EFORM         ; IF YES, E FORMAT REQUIRED
                 ;
                 ;       PROCESS NOT E FORMAT
                 ;
D8FC  38             SEC                    ; SET CARRY
D8FD  E93F           SBC     #$3F           ; GET DECIMAL POSITION
                 ;
D8FF  2070DC         JSR     :CVFR0         ; CONVERT FR0 TO ASCII CHAR
                 ;
D902  20A4DC         JSR     :FNXERO        ; FIND LAST NON-ZERO CHARACTER
D905  0980           ORA     #$80           ; TURN ON HIGH ORDER BIT
D907  9D8005         STA     LBUFF,X        ; STORE IT BACK IN BUFFER
                 ;
D90A  AD8005         LDA     LBUFF          ; GET 1ST CHAR IN LBUFF
D90D  C92E           CMP     #'.'           ; IS IT DECIMAL?
D90F  F003 ^D914     BEQ     :FN6           ; BR IF YES
D911  4C88D9         JMP     :FN5           ; ELSE JUMP
D914             :FN6
D914  20C1DC         JSR     :DECINB        ; DECIMAL INBUFF
D917  4C9CD9         JMP     :FN4           ; DO FINAL ADJUSTMENT
                 ;
                 ;       EXPONENT IS ZERO - # IS ZERO
                 ;
                 ;
D91A             :EXP0
D91A  A9B0           LDA     #$80+$30       ; GET ASCII 0 WITH MSB = 1
D91C  8D8005         STA     LBUFF          ; PUT IN BUFFER
D91F  60             RTS
                 ;
                 ;       PROCESS E FORMAT
                 ;
D920             :EFORM
D920  A901           LDA     #1             ; GET DECIMAL POSITION
D922  2070DC         JSR     :CVFR0         ; CONVERT FR0 TO ASCII IN
                                              LBUFF

;----------250

                 ;
D925  20A4DC         JSR     :FNZERO        ; GET RID OF TRAILING ZEROS
D928  E8             INX                    ; INCR INDEX
D929  86F2           STX     CIX            ; SAVE INDEX TO LAST CHAR
                 ;
                 ;       ADJUST EXPONENT
                 ;
D92B  A5D4           LDA     FR0            ; GET EXPONENT
D92D                 ASLA                   ; MULT BY 2 [GET RID OF
                                              SIGN TOO]
D92D +0A             ASL     A
D92E  38             SEC
D92F  E980           SBC     #$40*2         ; SUB EXCESS 64
                 ;
D931  AE8005         LDX     LBUFF          ; GET 1ST CHAR IN LBUFF
D934  E030           CPX     #'0'           ; IS IT ASCII 0?
D936  F017 ^D94F     BEQ     :EF1
                 ;
                 ;       PUT DECIMAL AFTER 1ST CHAR [IT'S AFTER 2ND NOW]
                 ;
D938  AE8105         LDX     LBUFF+1        ; SWITCH D.P. + 2ND DIGIT
D93B  AC8205         LDY     LBUFF+2        ; X
D93E  8E8205         STX     LBUFF+2        ; X
D941  8C8105         STY     LBUFF+1        ; X
                 ;
                 ;
D944  A6F2           LDX     CIX            ; IF CIX POINTS TO D.P.
D946  E002           CPX     #2             ; THEN INC
D948  D002 ^D94C     BNE     :NOINC         ; X
D94A  E6F2           INC     CIX            ; X
                 ;
D94C             :NOINC
D94C  18             CLC                    ; X
D94D  6901           ADC     #1             ; X
                 ;
                 ;       CONVERT EXP TO ASCII
                 ;
D94F             :EP1
D94F  85ED           STA     EEXP           ; SAVE EXPONENT
D951  A945           LDA     #'E'           ; GET ASCII E
D953  A4F2           LDY     CIX            ; GET POINTER
D955  209FDC         JSR     :STCHAR        ; STORE CHARACTER
D958  84F2           STR     CIX            ; SAVE INDEX
                 ;
                 ;
D95A  A5ED           LDA     EEXP           ; GET EXPONENT
D95C  100B ^D969     BPL     :EPL           ; BR IF PLUS
                 ;
                 ;       EXPONENT OS MINUS - COMPLEMENT IT
                 ;
D95E  A900           LDA     #0             ; SUBSTRACT FROM 0 TO
                                              COMPLEMENT
D960  38             SEC                    ; X
D961  E5ED           SBC     EEXP           ; X
D963  85ED           STA     EEXP
                 ;
D965  A92D           LDA     #'-'           ; GET A MINUS
D967  D002 ^D96B     BNE     :EF2
                 ;
D969             :EPL
D969  A92B           LDA     #'+'           ; GET A PLUS
D96B             :EF2
D96B  209FDC         JSR     ;STCHAR        ; STORE A CHARACTER
                 ;
D96E  A200           LDX     #0             ; SET COUNTER FOR # OF TENS
D970  A5ED           LDA     EEXP           ; GET EXPONENT
                 ;
D972             :EF3
D972  38             SEC
D973  E90A           SBC     #10            ; SUBSTRACT 10

;----------251

D975  9003 ^D97A     BCC     :EF4           ; IF < 0, BRANCH
D977  E8             INX                    ; INC # OF 10'S
D978  D0F8 ^D972     BNE     :EF3           ; BR INCONDITIONAL
                 ;
D97A             :EF4
D97A  18             CLC                    ; ADD BACK IN 10
D97B  690A           ADC     #10            ; X
D97D  48             PHA                    ; SAVE
                 ;
D97E  8A             TXA                    ; GET # OF 10'S
D97F  209DDC         JSR     :STNUM         ; PUT 10'S IN EXP IN BUFFER
D982  68             PLA                    ; GET REMAINDER
D983  0980           ORA     #$80           ; TURN ON HIGH ORDER BIT
D985  209DDC         JSR     :STNUM         ; PUT IN BUFFER
                 ;
                 ;       FINAL ADJUSTMENT
                 ;
D988             :FN5
D988  AD8005         LDA     LBUFF          ; GET  1ST BYTE IN LBUFF
                                              [OUTPUT]
D98B  C930           CMP     #'0'           ; IS IT ASCII 0?
D98D  D00D ^D99C     BNE     :FN4           ; IF NOT BR
                 ;
                 ;       INCREMENT INBUFF TO POINT TO NON-ZERO
                 ;
D98F  18             CLC                    ; ADD 1 TO INBUFF
D990  A5F3           LDA     INBUFF         ; X
D992  6901           ADC     #1             ; X
D994  85F3           STA     INBUFF         ; X
D996  A5F4           LDA     INBUFF+1       ; X
D998  6900           ADC     #0             ; X
D99A  85F4           STA     INBUFF+1       ; X
D99C             :FN4
D99C  A5D4           LDA     FR0            ; GET EXPONENT OF #
D99E  1009 ^D9A9     BPL     :FADONE        ; IF SIGN +, WE ARE DONE
                 ;
D9A0  20C1DC         JSR     :DECINB        ; DECR INBUFF
D9A3  A000           LDY     #0             ; GET INDEX
D9A5  A92D           LDA     #'-'           ; GET ASCII -
D9A7  91F3           STA     [INBUFF],Y     ; SAVE - IN BUFFER
                 ;
D9A9             :FADONE
D9A9  60             RTS

;IFP - Convert Integer to Floating Point
                 ;       ON ENTRY   FR0 - CONTAINS INTEGER
                 ;
                 ;       ON EXIT    FR0 - CONTAINS FLOATING POINT
                 ;
                 ;
D9AA             CVIFP
D9AA             IFP
                 ;
                 ;       MOVE INTEGER AND REVERSE BYTES
                 ;
D9AA  A5D4           LDA     FR0              ; GET INTEGER LOW
D9AC  85F8           STA     ZTEMP4+1         ; SAVE AS INTEGER HIGH
D9AE  A5D5           LDA     FR0+1            ; GET INTEGER HIGH
D9B0  85F7           STA     ZTEMP4           ; SAVE AS INTEGER LOW
                 ;
D9B2  2044DA         JSR     ZFR0             ; CLEAR FR0
D9B5  F8             SED                      ; SET DECIMAL MODE
                 ;
                 ;       DO THE CONVERT
                 ;
D9B6  A010           LDY     #16              ; GET # BITS IN INTEGER
D9B8             :IFP1
D9B8  06F8           ASL     ZTEMP4+1         ; SHIFT LEFT INTEGER LOW
D9BA  26F7           ROL     ZTEMP4           ; SHIFT LEFT INTEGER HIGH

;----------252

                                              ; CARRY NOW SET IF THERE WAS A
                                                BIT
D9BC  A203           LDX     #3               ; BIGGEST INTEGER IS 3 BYTES
D9BE             :IFP2
                 ;
                 ;       DOUBLE # AND ADD IN 1 IF CARRY SET
                 ;
D9BE  B5D4           LDA     FR0,X            ; GET BYTE
D9C0  75D4           ADC     FR0,X            ; DOUBLE [ADDING IN CARRY
                                                FROM SHIFT
D9C2  95D4           STA     FR0,X            ; SAVE
D9C4  CA             DEX                      ; DECREMENT COUNT OF FR0 BYTES
D9C5  D0F7 ^D9BE     BNE     :IFP2            ; IF MORE TO DO, DO IT
                 ;
D9C7  88             DEY                      ; DECR COUNT OF INTEGER DIGITS
D9C8  D0EE ^D9B8     BNE     :IFP1            ; IF MORE TO DO, DO IT
D9CA  D8             CLD                      ; CLEAR DECIMAL MODE
                 ;
                 ;       SET EXPONENT
                 ;
D9CB  A942           LDA     #$42             ; INDICATE DECIMAL AFTER LAST
                                                DIGIT
D9CD  85D4           STA     FR0              ; STORE EXPONENT
                 ;
D9CF  4C00DC         JMP     NORM             ; NORMALIZE
                 ;
;FPI - Convert Floating Point to Integer
                 ;       ON ENTRY    FR0 - FLOATING POINT NUMBER
                 ;
                 ;       ON EXIT     FR0 - INTEGER
                 ;
                 ;
                 ;       CC SET  CARRY CLEAR - NO ERROR
                 ;               CARRY SET - ERROR
                 ;
                 ;
D9D2             FPI
                 ;
                 ;       CLEAR INTEGER
                 ;
D9D2  A900           LDA     #0               ; CLEAR INTEGER RESULT
D9D4  85F7           STA     ZTEMP4
D9D6  85F8           STA     ZTEMP4+1
                 ;
                 ;       CHECK EXPONENT
                 ;
D9D8  A5D4           LDA     FR0              ; GET EXPONENT
D9DA  3066 ^DA42     BMI     :ERVAL           ; IF SIGN OF FP# IS -, THEN
                                                ERROR
D9DC  C943           CMP     #$43             ; IS FP# TOO BIG TO BE INTEGER
D9DE  B062 ^DA42     BCS     :ERVAL           ; IF YES, THEN ERROR
D9E0  38             SEC                      ; SET CARRY
D9E1  E940           SBC     #$40             ; IS FP# LESS THAN 1?
D9E3  903F ^DA24     BCC     :ROUND           ; IF YES, THEN GO TEST FOR
                                                ROUND
                 ;
                 ;       GET # OF DIGITS TO CONVERT = [EXPONENT -40+1]*2
                 ;       [A CONTAINS EXPONENT -40]
                 ;       [CARRY SET]
                 ;
D9E5  6900           ADC     #0               ; ADD IN CARRY
D9E7                 ASLA                     ; MULT BY 2
D9E7 +0A             ASL     A
D9E8  85F5           STA     ZTEMP1           ; SAVE AS COUNTER
                 ;
                 ;       DO CONVERT
                 ;
D9EA             :FPI1
                 ;

;----------253

                 ;       MULT INTEGER RESULT BY 10
                 ;
D9EA  205ADA         JSR     :ILSHFT          ; GO SHIFT ONCE LEFT
D9ED  B053 ^DA42     BCS     :ERVAL           ; IF CARRY SET THEN # TOO BIG
                 ;
D9EF  A5F7           LDA     ZTEMP4           ; SAVE INTEGER *2
D9F1  85F9           STA     ZTEMP3           ; X
D9F3  A5F8           LDA     ZTEMP4+1         ; X
D9F5  85FA           STA     ZTEMP3+1         ; X
                 ;
D9F7  205ADA         JSR     :ILSHFT          ; MULT BY 2
D9FA  B046 ^DA42     BCS     :ERVAL           ; # TOO BIG
D9FC  205ADA         JSR     :ILSHFT          ; MULT BY *2 [NOW * 8 IN ZTEMP]
D9FF  B041 ^DA42     BCS     :ERVAL           ; BR IF # TO BIG
                 ;
DA01  18             CLC                      ; ADD IN * 2 TO = *10
DA02  A5F8           LDA     ZTEMP4+1         ; X
DA04  65FA           ADC     ZTEMP3+1         ; X
DA06  85F8           STA     ZTEMP4+1         ; X
DA08  A5F7           LDA     ZTEMP4           ; X
DA0A  65F9           ADC     ZTEMP3           ; X
DA0C  85F7           STA     ZTEMP4           ; X
DA0E  B032 ^DA42     BCS     :ERVAL           ; IF CARRY SET ERROR
                 ;
                 ;
                 ;       ADD IN NEXT DIGIT
                 ;
DA10  20B9DC         JSR     :GETDIG          ; GET DIGIT IN A
DA13  18             CLC
DA14  65F8           ADC     ZTEMP4+1         ; ADD IN DIGIT
DA16  85F8           STA     ZTEMP4+1         ; X
DA18  A5F7           LDA     ZTEMP4           ; X
DA1A  6900           ADC     #0               ; X
DA1C  B024 ^DA42     BCS     :ERVAL           ; BR IF OVERFLOW
DA1E  85F7           STA     ZTEMP4           ; X
                 ;
DA20  C6F5           DEC     ZTEMP1           ; DEC COUNTER OF DIGITS TO DO
DA22  D0C6 ^D9EA     BNE     :FPI1            ; IF MORE TO DO, DO IT
                 ;
                 ;       ROUND IF NEEDED
                 ;
DA24             :ROUND
DA24  20B9DC         JSR     ;GETDIG          ; GET NEXT DIGIT IN A
DA27  C905           CMP     #5               ; IS DIGIT <5?
DA29  900D ^DA38     BCC     :NR              ; IF YES, DON'T ROUND
DA2B  18             CLC                      ; ADD IN 1 TO ROUND
DA2C  A5F8           LDA     ZTEMP4+1         ; X
DA2E  6901           ADC     #1               ; X
DA30  85F8           STA     ZTEMP4+1         ; X
DA32  A5F7           LDA     ZTEMP4           ; X
DA34  6900           ADC     #0               ; X
DA36  85F7           STA     ZTEMP4           ; X
                 ;
                 ;       MOVE INTEGER TO FR0
                 ;
DA38             :NR
DA38  A5F8           LDA     ZTEMP4+1         ; GET INTEGER LOW
DA3A  85D4           STA     FR0              ; SAVE
DA3C  A5F7           STA     ZTEMP4           ; GET INTEGER HIGH
DA3E  85D5           STA     FR0+1            ; SAVE
                 ;
DA40  18             CLC                      ; CLEAR CC FOR GOOD RETURN
DA41  60             RTS
                 ;
                 ;
DA42             :ERVAL
DA42  38             SEC                      ; SET CARRY FOR ERROR RETURN
DA43  60             RTS
                 ;       ZFR0 - ZERO FR0
                 ;
                 ;       ZF1 - ZERO 6 BYTES AT LOC X

;----------254

                 ;
                 ;       ZXLY - ZERO PAGE ZERO LOC X FOR LENGTH Y
                 ;
                 ;
DA44             ZFR0
DA44  A2D4           LDX     #FR0             ; GET POINTER TO FR1
                 ;
DA46             ZF1
DA46  A006           LDY     #6               ; GET # OF BYTES TO CLEAR
DA48             ZXLY
DA48  A900           LDA     #0               ; CLEAR A
DA4A             :ZF2
DA4A  9500           STA     0,X              ; CLEAR A BYTE
DA4C  E8             INX                      ; POINT TO NEXT BYTE
DA4D  88             DEY                      ; DEC COUNTER
DA4E  D0FA ^DA4A     BNE     :ZF2             ; LOOP
DA50  60             RTS
                 ;
                 ;
                 ;
                 ;
                 ;       INTBLF - INIT LBUFF INTO INBUFF
                 ;
DA51             INTLBF
DA51  A905           LDA     #LBUFF/256
DA53  85F4           STA     INBUFF+1
DA55  A980           LDA     #LBUFF&255
DA57  85F3           STA     INBUFF
DA59  60             RTS
                 ;
                 ;       :ILSHFT - SHIFT INTEGER IN ZTEMP4 LEFT ONCE
                 ;
DA5A             ILSHFT
DA5A             :ILSHFT
DA5A  18             CLC                      ; CLEAR CARRY
DA5B  26F8           ROL     ZTEMP4+1         ; SHIFT LOW
DA5D  26F7           ROL     ZTEMP4           ; SHIFT HIGH
DA5F  60             RTS

                 ;       Floating Point Routines

;FADD - Floating Point Add Routine

                 ;              ADDS VALUES IN FR0 AND FR1
                 ;
                 ;       ON ENTRY    FR0 & FR1 - CONTAIN # TO ADD
                 ;
                 ;       ON EXIT     FR0 - RESULT

;FSUB - Floating Point Substract Routine

                 ;              SUBSTRACTS FR1 FROM FR0
                 ;
                 ;       ON ENTRY    FR0 & FR1 - CONTAIN # TO SUBSTRACT
                 ;
                 ;       ON EXIT     FR0 - RESULT
                 ;
                 ;       BOTH RETURN WITH CC SET:
                 ;               CARRY SET IF ERROR
                 ;               CARRY CLEAR IF NO ERROR
                 ;
                 ;
DA60             FSUB
DA60  A5E0           LDA     FR1              ; GET EXPONENT OF FR1
DA62  4980           EOR     #$80             ; CHANGE SIGN OF MANTISSA
DA64  85E0           STA     FR1              ; SAVE EXPONENT
                 ;
                 ;
                 ;
DA66             FADD
DA66             :FRADD

;----------255

DA66  A5E0           LDA     FR1              ; GET EXPONENT
DA68  297F           AND     #$7F             ; TURN OFF MANTISSA SIGN BIT
DA6A  85F7           STA     ZTEMP4           ; SAVE TEMPORARILY
DA6C  A5D4           LDA     FR0              ; GET EXPONENT FR0
DA6E  297F           AND     #$7F             ; TURN OFF MANTISSA SIGN BIT
DA70  38             SEC                      ; CLEAR CARRY
DA71  E5F7           SBC     ZTEMP4           ; SUB EXPONENTS
DA73  1010 ^DA85     BPL     :NSWAP           ; IF EXP[FR0]>= EXP[FR1],
                                                NO SWAP
                 ;
                 ;       SWAP FR0 AND FR1
                 ;
DA75  A205           LDX     #FMPREC          ; GET INDEX
                 ;
DA77             :SWAP
DA77  B5D4           LDA     FR0,X            ; GET BYTE FROM FR0
DA79  B4E0           LDY     FR1,X            ; GET BYTE FROM FR1
DA7B  95E0           STA     FR1,X            ; PUT FR0 BYTE IN FR1
DA7D  98             TYA                      ; GET FR1 BYTE
DA7E  95D4           STA     FR0,X            ; PUT FR1 BYTE IN FR0
DA80  CA             DEX                      ; DEC INDEX
DA81  10F4 ^DA77     BPL     :SWAP            ; IF MORE TO DO, GO SWAP
DA83  30E1 ^DA66     BMI     :FRADD           ; UNCONDITIONAL
                 ;
DA85             :NSWAP
DA85  F007 ^DA8E     BEQ     :NALIGN          ; IF DIFFERENCE = 0, ALREADY
                                                ALIGNED
DA87  C905           CMP     #FMPREC          ; IS DIFFERENCE < # OF BYTES
DA89  B019 ^DAA4     BCS     :ADDEND          ; IF NOT, HAVE RESULT IN FR0
                 ;
                 ;
DA8B  203EDC         JSR     RSHFT1           ; SHIFT TO ALIGN
                 ;
                 ;       TEST FOR LIKE SIGN OF MANTISSA
                 ;
DA8E             :NALIGN
DA8E  F8             SED                      ; SET DECIMAL MODE
DA8F  A5D4           LDA     FR0              ; GET FR0 EXPONENT
DA91  45E0           EOR     FR1              ; EOR WITH FR1 EXPONENT
DA93  301E ^DAB3     BMI     :SUB             ; IF SIGNS DIFFERENT - SUBSTRACT
                                              ; ELSE ADD
                 ;
                 ;       ADD FR0 & FR1
                 ;
DA95  A204           LDX     #FMPREC-1        ; GET POINTER FOR LAST BYTE
DA97  18             CLC                      ; CLEAR CARRY
DA98             :ADD1
DA98  B5D5           LDA     FR0M,X           ; GET BYTE OF FR0
DA9A  75E1           ADC     FR1M,X           ; ADD IN BYTE OF FR1
DA9C  95D5           STA     FR0M,X           ; STORE
DA9E  CA             DEX                      ; DEC POINTER
DA9F  10F7 ^DA98     BPL     :ADD1            ; ADD NEXT BYTE
                 ;
DAA1  D8             CLD                      ; CLEAR DECIMAL MODE
DAA2  B003 ^DAA7     BCS     :ADD2            ; IF THERE IS A CARRY, DO IT
DAA4             :ADDEND
DAA4  4C00DC         JMP     NORM             ; GO NORMALIZE
                 ;
                 ;       ADD IN FIND CARRY
                 ;
DAA7             :ADD2
DAA7  A901           LDA     #1               ; GET 1 TIMES TO SHIFT
DAA9  203ADC         JSR     RSHFT0           ; GO SHIFT
                 ;
DAAC   A901          LDA     #1               ; GET CARRY
DAAE  85D5           STA     FR0M             ; ADD IN CARRY
DAB0  4C00DC         JMP     NORM
                 ;
                 ;       SUBSTRACT FR1 FROM FR0
                 ;
DAB3             :SUB
DAB3  A204           LDX     #FMPREC-1        ; GET POINTER TO LAST BYTE
DAB5  38             SEC                      ; SET CARRY

;---------256

                 ;
DAB6             :SUB1
DAB6  B5D5           LDA     FR0M,X           ; GET FR0 BYTE
DAB8  F5E1           SBC     FR1M,X           ; SUB FR1 BYTE
DABA  95D5           STA     FR0M,X           ; STORE
DABC  CA             DEX                      ; DEC POINTER
DABD  10F7 ^DAB6     BPL     :SUB1            ; SUB NEXT BYTE
                 ;
DABF  9004 ^DAC5     BCC     :SUB2            ; IF THERE IS A BORROW DO IT
DAC1  D8             CLD                      ; CLEAR DECIMAL MODE
DAC2  4C00DC         JMP     NORM
                 ;
                 ;       TAKE COMPLEMENT SIGN
                 ;
DAC5             :SUB2
DAC5  A5D4           LDA     FR0              ; GET EXPONENT
DAC7  4980           EOR     #$80             ; CHANGE SIGN OF MANTISSA
DAC9  85D4           STA     FR0              ; PUT IT BACK
                 ;
                 ;       COMPLEMENT MANTISSA
                 ;
DACB  38             SEC                      ; SET CARRY
DACC  A204           LDX     #FMPREC-1        ; GET INDEX COUNTER
DACE             :SUB3
DACE  A900           LDA     #0               ; GET ZERO
DAD0  F5D5           SBC     FR0M,X           ; COMPLEMENT BYTE
DAD2  95D5           STA     FR0M,X           ; STORE
DAD4  CA             DEX                      ; MORE TO DO
DAD5  10F7 ^DACE     BPL     :SUB3            ; BR IF YES
                 ;
DAD7  D8             CLD                      ; CLEAR DECIMAL MODE
DAD8  4C00DC         JMP     NORM             ; GO NORMALIZE

;FMUL - Multiply FR0 by FR1
                 ;       ON ENTRY    # ARE IN FR0 AND FR1
                 ;
                 ;       ON EXIT     FR0 - CONTAINS PRODUCT
                 ;       RETURN WITH CC SET
                 ;               CARRY SET IF ERROR
                 ;               CARRY CLEAR IF NO ERROR
                 ;
                 ;
                 ;
DADB             FMUL
                 ;
                 ;       SET UP EXPONENT
                 ;
DADB  A5D4           LDA     FR0              ; GET EXP FR0
DADD  F045 ^DB24     BEQ     MEND3            ; IF = 0,DONE
DADF  A5E0           LDA     FR1              ; GET FR1 EXP
DAE1  F03E ^DB21     BEQ     MEND2            ; IF =0, ANSWER =0
                 ;
DAE3  20CFDC         JSR     MDESUP           ; DO COMMON SET FOR EXPONENT
DAE6  38             SEC                      ; SET CARRY
DAE7  E940           SBC     #$40             ; SUB EXCESS 64
DAE9  38             SEC                      ; SET CARRY TO ADD 1
DAEA  65E0           ADC     FR1              ; ADD 1 + FR1 EXP TO FR0 EXP
DAEC  3038 ^DB26     BMI     :EROV            ;IF - THEN OVERFLOW
                 ;
                 ;       FINISH MULTIPLY SET UP
                 ;
DAEE  20E0DC         JSR     MDSUP            ; DO SET UP COMMON TO DIVIDE
                 ;
                 ;
                 ;       DO THE MULTIPLY
                 ;
DAF1             :FRM
                 ;
                 ;       GET # OF TIMES TO ADD IN MULTIPLICAND
                 ;

;----------257

DAF1  A5DF           LDA     FRE+FMPREC       ; GET LAST BYTE OF FRE
DAF3  290F           AND     #$0F             ; AND OUT HIGH ORDER NIBBLE
DAF5  85F6           STA     ZTEMP1+1         ; SET COUNTER FOR LOOP CONTROL
                 ;
                 ;       ADD IN FR1
                 ;
DAF7             :FRM1
DAF7  C6F6           DEC     ZTEMP1+1         ; DEC MULT COUNTER
DAF9  3006 ^DB01     BMI     :FRM2            ; IF - THIS LOOP DONE
DAFB  2001DD         JSR     FRA10            ; ADD FR1 TO FR0 [6 BYTES]
DAFE  4CF7DA         JMP     :FRM1            ; REPEAT
                 ;
                 ;       GET # OF TIMES TO ADD IN MULTIPLICAND * 10
                 ;
DB01             :FRM2
DB01  A5DF           LDA     FRE+FMPREC       ; GET LAST BYTE OF FRE
DB03                 LSRA                     ; SHIFT OUT LOW ORDER NIBBLE
DB03 +4A             LSR     A
DB04                 LSRA                     ; X
DB04 +4A             LSR     A
DB05                 LSRA                     ; X
DB05 +4A             LSR     A
DB06                 LSRA                     ; X
DB06 +4A             LSR     A
DB07  85F6           STA     ZTEMP1+1         ; SAVE AS COUNTER
                 ;
                 ;       ADD IN FR2
                 ;
DB09             :FRM3
DB09  C6F6           DEC     ZTEMP1+1         ; DECREMENT COUNTER
DB0B  3006 ^DB13     BMI     :NXTB            ; IF -, DO NEXT BYTE
DB0D  2005DD         JSR     FRA20            ; ADD FR2 TO FR0 [6 BYTES]
DB10  4C08DB         JMP     :FRM3            ; REPEAT
                 ;
                 ;       SET UP FOR NEXT SET OF ADDS
                 ;
DB13             :NXTB
                 ;
                 ;       SHIFT FR0/FRE RIGHT ONE BYTE
                 ;               [THEY ARE CONTIGUOUS]
                 ;
DB13  2062DC         JSR     RSHFOE           ; SHIFT FR0/FRE RIGHT
                 ;
                 ;       TEST FOR # OF BYTES SHIFTED
                 ;
DB16  C6F5           DEC     ZTEMP1           ; DECREMENT LOOP CONTROL
DB18  D0D7 ^DAF1     BNE     :FRM             ; IF MORE ADDS TO DO, DO IT
                 ;
                 ;       SET EXPONENT
                 ;
DB1A             MDEND
DB1A  A5ED           LDA     EEXP             ; GET EXPONENT
DB1C  85D4           STA     FR0              ; STORE AS FR0 EXP
                 ;
                 ;
DB1E             MEND1
DB1E  4C04DC         JMP     NORM1            ; NORMALIZE
                 ;
                 ;
                 ;
DB21             MEND2
DB21  2044DA         JSR     ZFR0             ; CLEAR FR0
DB24             MEND3
DB24  18             CLC                      ; CLEAR CARRY FOR GOOD RETURN
DB25  60             RTS
                 ;
                 ;
                 ;
DB26             :EROV
DB26  38             SEC                      ; SET CARRY FOR ERROR ROUTINE
DB27  60             RTS                      ; RETURN

;----------258

;FDIV - Floating Point Divide
                 ;       ON ENTRY    FR0 - DIVIDEND
                 ;                   FR1 - DIVISOR
                 ;
                 ;       ON EXIT     FR0 - QUOTIENT
                 ;
                 ;       RETURNS WITH CC SET:
                 ;               CARRY CLEAR - ERROR
                 ;               CARRY SET - NO ERROR
                 ;
                 ;
DB28             FDIV
                 ;
                 ;       DO DIVIDE SET UP
                 ;
DB28  A5E0           LDA     FR1              ; GET FR1 EXP
DB2A  F0FA ^DB26     BEQ     :EROV            ; IF =0, THEN OVERFLOW
DB2C  A5D4           LDA     FR0              ; GET EXPONENT FR0
DB2E  F0F4           BEQ     MEND3            ; IF = 0, THEN DONE
                 ;
DB30  20CFDC         JSR     MDESUP           ; DO COMMON PART OF EXP SET UP
                 ;
DB33  38             SEC
DB34  E5E0           SBC     FR1              ; SUB FR1 EXP FROM FR0 EX
DB36  18             CLC
DB37  6940           ADC     #$40             ; ADD IN EXCESS 64
DB39  30EB ^DB26     BMI     :EROV            ; IF MINUS THEN OVERFLOW
                 ;
DB3B  20E0DC         JSR     MDSUP            ; DO SETUP COMMON FOR MULT
DB3E  E6F5           INC     ZTEMP1           ;LOOP 1 MORE TIME FOR DIVIDE
DB40  4C4EDB         JMP     :FRD1            ; SKIP SHIFT 1ST TIME THROUGH
                 ;
      = 00D9     QTEMP   EQU     FR0+FMPREC
DB43             :NXTQ
                 ;
                 ;       SHIFT FR0/FRE LEFT ONE BYTE
                 ;               [THEY ARE CONTIGUOUS]
                 ;
DB43  A200           LDX     #0               ; GET POINTER TO BYTE TO MOVE
DB45             :NXTQ1
DB45  B5D5           LDA     FR0+1,X          ; GET BYTE
DB47  95D4           STA     FR0,X            ; MOVE IT LEFT ONE BYTE
                 ;
DB49  E8             INX                      ; POINT TO NEXT BYTE
DB4A  E00C           CPX     #FMPREC*2+2      ; HAVE WE DONE THEM ALL?
DB4C  D0F7 ^DB45     BNE     :NXTQ1           ; IF NOT, BRANCH
                 ;
                 ;       DO DIVIDE
                 ;
DB4E             :FRD1
                 ;
                 ;       SUBSTRACT FR2 [DIVISOR *2] FROM FRE [DIVIDEND]
                 ;
                 ;
DB4E  A005           LDY     #FMPREC          ; SET LOOP CONTROL
DB50  38             SEC                      ; SET CARRY
DB51  F8             SED                      ; SET DECIMAL MODE
DB52             :FRS2
DB52  B9DA00         LDA     FRE,Y            ; GET A BYTE FROM FRE
DB55  F9E600         SBC     FR2,Y            ; SUB FR2
DB58  99DA00         STA     FRE,Y            ; STORE RESULT
DB5B  88             DEY                      ; DECREMENT COUNTER
DB5C  10F4 ^DB52     BPL     :FRS2            ; BR IF MORE TO DO
DB5E  D8             CLD                      ; CLEAR DECIMAL MODE
                 ;
DB5F  9004 ^DB65     BCC     :FAIL            ; IF RESULT <0 [FRE < FR2] BR
                 ;
DB61  E6D9           INC     QTEMP            ; INCR # TIMES SUB [QUOTIENT]
                 ;

;----------259

DB63  D0E9 ^DB4E     BNE     :FRD1            ; SUB AGAIN
                 ;
                 ;       SUBSTRACT OF FR2 DIDN'T GO
                 ;
DB65             :FAIL
DB65  200FDD         JSR     FRA2E            ; ADD FR2 BACK TO FR0
                 ;
                 ;       SHIFT LAST BYTE OF QUOTIENT ONE NIBBLE LEFT
                 ;
DB68  06D9           ASL     QTEMP            ; SHIFT 4 BITS LEFT
DB6A  06D9           ASL     QTEMP            ; X
DB6C  06D9           ASL     QTEMP            ; X
DB6E  06D9           ASL     QTEMP            ; X
DB70             :FRD2
                 ;
                 ;       SUBSTRACT FR1 [DIVISOR] FROM FRE [DIVIDEND]
                 ;
DB70  A005           LDY     #FMPREC          ; SET LOOP CONTROL
DB72  38             SEC                      ; SET CARRY
DB73  F8             SED                      ; SET DECIMAL MODE
DB74             :FRS1
DB74  B9DA00         LDA     FRE,Y            ; GET A BYTE FROM FRE
DB77  F9E000         SBC     FR1,Y            ; SUB FR1
DB7A  99DA00         STA     FRE,Y            ; STORE RESULT
DB7D  88             DEY
DB7E  10F4 ^DB74     BPL     :FRS1            ; BR IF MORE TO DO
DB80  D8             CLD                      ; CLEAR DECIMAL MODE
                 ;
DB81  9004 ^DB87     BCC     :FAIL2           ; IF RESULT <0 [FRE < FR1] BR
                 ;
DB83  E6D9           INC     QTEMP            ; INCR # TIMES SUB [QUOTIENT]
                 ;
DB85  D0E9 ^DB70     BNE     :FRD2            ; SUB AGAIN
                 ;
                 ;       SUBSTRACT OF FR1 DIDN'T GO
                 ;
DB87             :FAIL2
DB87  2009DD         JSR     FRA1E            ; ADD FR1 BACK TO FR0
                 ;
DB8A  C6F5           DEC     ZTEMP1           ; DEC LOOP CONTROL
DB8C  D0B5 ^DB43     BNE     :NXTQ            ; GET NEXT QUOTIENT BYTE
                 ;
DB8E  2062DC         JSR     RSHF0E           ;SHIFT RIGHT FR0/FRE TO CLEAR
                                               EXP
DB91  4C1AD8         JMP     MDEND            ; JOIN MULT END UP CODE

;:GETCHAR - Test Input Character
                 ;       ON ENTRY    INBUFF - POINTS TO BUFFER WITH INPUT
                 ;                   CIX - POINTS TO CHAR IN BUFFER
                 ;
                 ;       ON EXIT     CIX - POINTS TO NEXT CHAR
                 ;                   CC - CARRY CLEAR IF CHAR IS NUMBER
                 ;                        CARRY SET IF CHAR IS NOT NUMBER
                 ;
DB94             :GETCHAR
DB94  20AFD8         JSR     TSTNUM           ; GO TEST FOR NUMBER
DB97  A4F2           LDY     CIX              ; GET CHARACTER INDEX
DB99  9002 ^D89D     BCC     :GCHR1           ; IF CHAR = NUM, SKIP
                 ;
DB9B  B1F3           LDA     [INBUFF],Y       ; GET CHARACTER
                 ;
DB9D             :GCHR1
DB9D  C8             INY                      ; POINT TO NEXT CHAR
DB9E  84F2           STY     CIX              ; SAVE INDEX
DBA0  60             RTS
                 ;
                 ;SKPBLANK-SKIP BLANKS
                 ;       STARTS AT CIX AND SCANS FOR NON BLANKS
                 ;

 ;----------260

DBA1             SKBLANK
DBA1             SKPBLANK
DBA1  A4F2           LDY     CIX              ; GET CIX
DBA3  A920           LDA     #$20             ; GET A BLANK
                 ;
DBA5  D1F3       :SB1    CMP     [INBUFF],Y        ;IS CHAR A BLANK
DBA7  D003 ^DBAC     BNE     :SBRTS           ; BR IF NOT
DBA9  C8             INY                      ; INC TO NEXT
DBAA  D0F9 ^DBA5     BNE     :SB1             ; GO TEST
                 ;
DBAC  84F2       :SBRTS  STY     CIX          ;SET NON BLANK INDEX
DBAE  60             RTS                      ;RETURN
                 ;
                 ; TSTNUM-TEST CHAR AT CIX FOR NUM
                 ;       - RTNS CARRY SET IF NUM
DBAF             TSTNUM
DBAF  A4F2           LDY     CIX              ;GET INDEX
DBB1  B1F3           LDA     [INBUFF],Y       ;AND  GET CHAR
DBB3  38             SEC
DBB4  E930           SBC     #$30             ;SUBSTRACT ASCLT ZERO
DBB6  9018 ^D8D0     BCC     :TSNFAIL         ;BR CHAR<ASCLT ZERO
DBB8  C90A           CMP     #$0A             ;TEST GT ASCLT 9
DBBA  60             RTS                      ;DONE

;:TSTCHAR - Test to See if This Can Be a Number
                 ;       ON EXIT    CC - CARRY SET IF NOT A #
                 ;                       CARRY CLEAR IF A #
                 ;
DBBB             :TSTCHAR
DBBB  A5F2           LDA     CIX              ; GET INDEX
DBBD  48             PHA                      ; SAVE IT
DBBE  2094DB         JSR     :GETCHAR         ; GET CHAR
DBC1  901F ^DBE2     BCC     :RTSPASS         ; IF = #8 RETURN PASS
                 ;
DBC3  C92E           CMP     #'.'             ; IF = D.P., OK SO FAR
DBC5  F014 ^DBDB     BEQ     :TSTN
DBC7  C92B           CMP     #'+'             ; IF = +8 OK SO FAR
DBC9  F007 ^DBD2     BEQ     :TSTN1
DBCB  C92D           CMP     #'-'             ; IF = -8 OK SO FAR
DBCD  F003 ^DBD2     BEQ     :TSTN1
                 ;
                 ;
DBCF             :RTFAIL
DBCF  68             PLA                      ; CLEAR STACK
DBD0  38         :TSNFAIL                     ;SET FAIL
DBD1  60             RTS
                 ;
                 ;
DBD2             :TSTN1
DBD2  2094DB         JSR     :GETCHAR         ; GET CHAR
DBD5  900B ^DBE2     BCC     :RTPASS          ; IF #, RETURN PASS
DBD7  C92E           CMP     #'.'             ; IS IT D.P.
DBD9  D0F4 ^DBCF     BNE     :RTFAIL          ; IF NOT, RETURN
DBDB             :TSTN
DBDB  2094DB         JSR     :GETCHAR         ; ELSE GET NEXT CHAR
DBDE  9002 ^DBE2     BCC     :RTPASS          ; IF #, RETURN PASS
DBE0  B0ED ^DBCF     BCS     :RTFAIL          ; ELSE, RETURN FAIL
                 ;
                 ;
DBE2             :RTPASS
DBE2  68             PLA                      ; RESTORE CIX
DBE3  85F2           STA     CIX              ; X
DBE5  18             CLC                      ; CLEAR CARRY
DBE6  60             RTS                      ; RETURN PASS

;NIBSH0 - Shift FR0 One Nibble Left
                 ;       NIBSH0 - SHIFT FR2 ONE NIBBLE LEFT
                 ;
DBE7             NIBSH2
DBE7  A2E7           LDX     #FR2+1           ; POINT TO 1ST MANTISSA BYTE

;----------261

DBE9  D002 ^DBED     BNE     :NIB1
                 ;
DBEB             NIBSH0
DBEB  A2D5           LDX     #FROM            ; POINT TO MANTISSA OF FR0
DBED             :NIB1
DBED  A004           LDY     #4               ; GET # OF BITS TO SHIFT
DBEF             :NIBS
DBEF  18             CLC                      ; CLEAR CARRY
DBF0  3604           ROL     4,X              ; ROLL
DBF2  3603           ROL     3,X              ; X
DBF4  3602           ROL     2,X              ; X
DBF6  3601           ROL     1,X              ; X
DBF7  3700           ROL     0,X              ; X
DBFA  26EC           ROL     FRX              ; SVE SHIFTED NIBBLE
                 ;
DBFC  88             DEY                      ; DEC COUNT
DBFD  D0F0 ^DBEF     BNE     :NIBS            ; IF NOT = 0, REPEAT
DBFF  60             RTS

;NORM - Normalize Floating Point Number

DC00             NORM
DC00  A200           LDX     #0               ; GET ZERO
DC02  86DA           STX     FR0+FPREC        ; FOR ADD NORM SHIFT IN ZERO
DC04             NORM1
DC04  A204           LDX     #FMPREC-1        ; GET MAX # OF BYTES TO SHIFT
DC06  A5D4           LDA     FR0              ; GET EXPONENT
DC08  F02E ^DC38     BEQ     :NDONE           ; IF EXP=0, # =0
DC0A             :NORM
DC0A  A5D5           LDA     FR0M             ; GET 1ST BYTE OF MANTISSA
DC0C  D01A           BNE     :TSTBIG          ; IF NOT = 0 THEN NO SHIFT
                 ;
                 ;       SHIFT 1 BYTE LEFT
                 ;
DC0E  A000           LDY     #0               ; GET INDEX FOR 1ST MOVE BYTE
DC10             :NSH
DC10  B9D600         LDA     FR0M+1,Y         ; GET MOVE BYTE
DC13  99D500         STA     FR0M,Y           ; STORE IT
DC16  C8             INY
DC17  C005           CPY     #FMPREC          ; ARE WE DONE
DC19  90F5 ^DC10     BCC     :NSH             ; IF NOT SHIFT AGAIN
                 ;
                 ;       DECREMENT EXPONENT
                 ;
DC1B  C6D4           DEC     FR0              ; DECREMENT EXPONENT
                 ;
DC1D  CA             DEX                      ; DECREMENT COUNTER
DC1E  D0EA ^DC0A     BNE     :NORM            ; DO AGAIN IF NEEDED
                 ;
                 ;
                 ;
DC20  A5D5           LDA     FR0M             ; IS MANTISSA STILL 0
DC22  D004 ^DC28     BNE     :TSTBIG          ; IF NOT, SEE IF TOO BIG
DC24  85D4           STA     FR0              ; ELSE ZERO EXP
DC26  18             CLC
DC27  60             RTS
                 ;
DC28             :TSTBIG
DC28  A5D4           LDA     FR0              ; GET EXPONENT
DC2A  297F           AND     #$7F             ; AND OUT SIGN BIT
DC2C  C971           CMP     #49+64           ; IS IT < 49+64
DC2E  9001 ^DC31     BCC     :TSTUND          ; IF YES, TEST UNDERFLOW
DC30  60             RTS
DC31             :TSTUND
DC31  C90F           CMP     #-49+64          ; IS IT >=-49+64?
DC33  B003 ^DC38     BCS     :NDONE           ; IF YES, WE ARE DONE
DC35  2044DA         JSR     ZFR0             ; ELSE # IS ZERO
                 ;
DC38             :NDONE
DC38  18             CLC                      ; CLEAR CARRY FOR GOOD RETURN
DC39  60             RTS

;----------262

;RSHFT0 - Sift FR0 Right/Increment Exponent
;RSHFT1 - Sift FR1 Right/Increment Exponent
               ;         ON ENTRY    A - # OF PLACES TO SHIFT
               ;
               ;
DC3A           RDHIFT0
DC3A  A2D4           LDX     #FR0             ; POINT TO FR0
DC3C  D002 ^DC40     BNE     :RSH
               ;
DC3E           RSHFT1
DC3E  A2E0         LDX       #FR1             ; POINT TO FR1
               ;
DC40           :RSH
DC40  86F9         STX       ZTEMP3           ; SAVE FR POINTER
DC42  85F7         STA       ZTEMP4           ; SAVE # OF BYTES TO SHIFT
DC44  85F8         STA       ZTEMP4+1         ; SAVE FOR LATER
               ;
DC46           :RSH2
DC46  A004         LDY       #FMPREC-1        ; GET # OF BYTES TO MOVE
DC48           :RSH1
DC48  B504         LDA       4,X              ; GET CHAR
DC4A  9505         STA       5,X              ; STORE CHAR
DC4C  CA           DEX                        ; POINT TO NEXT BYTE
DC4D  88           DEY                        ; DEC LOOP CONTROL
DC4E  D0F8 ^DC48   BNE       :RSH1            ; IF MORE TO MOVE, DO IT
DC50  A900         LDA       #0               ; GET 1ST BYTE
DC52  9505         STA       5,X              ; STORE IT
               ;
DC54  A6F9         LDX       ZTEMP3           ; GET FR POINTER
DC56  C6F7         DEC       ZTEMP4           ; DO WE NEED TO SHIFT AGAIN?
DC58  D0EC ^DC46   BNE       :RSH2            ; IF YES, DO IT
               ;
               ;       FIX EXPONENT
               ;
DC5A  B500         LDA       0,X              ; GET EXPONENT
DC5C  18           CLC
DC5D  65F8         ADC       ZTEMP4+1         ; SUB # OF SHIFTS
DC5F  9500         STA       0,X              ; SAVE NEW EXPONENT
DC61  60           RTS

;RSHF0E - Shift FR0/FRE 1 Byte Right [They Are Contiguous]

DC62           RSHF0E
DC62  A20A         LDX       #FMPREC*2        ; GET LOOP CONTROL
               ;
DC64           :NXTB1
DC64  B5D4         LDA       FR0,X            ; GET A BYTE
DC66  95D5         STA       FR0+1,X          ; MOVE IT OVER 1
               ;
DC68  CA           DEX                        ; DEC COUNTER
DC69  10F9 ^DC64   BPL       :NXTB1           ; MOVE NEXT BYTE
DC6B  A900         LDA       #0               ; GET ZERO
DC6D  85D4         STA       FR0              ; SHIFT IT IN
DC6F  60           RTS

;:CVFR0 - Convert Each Byte in FR0 to 2 Charcters in LBUFF
               ;
               ;       ON ENTRY    A - DECIMAL POINT POSITION
               ;
               ;
DC70           :CVFR0
DC70  85F7         STA       ZTEMP4           ; SAVE DECIMAL POSITION
               ;
DC72  A200         LDX       #0               ; SET INDEX INTO FR0M
DC74  A000         LDY       #0               ; SET INDEX INTO OUTPUT
                                                LINE [LBUFF]
               ;
               ;       CONVERT A BYTE
               ;

;----------263

DC76           :CVBYTE
DC76  2093DC       JSR       :TSTOP           ; PUT IN D.P. NOW?
DC79           :CVB1
DC79  38           SEC                        ; DECREMENT DECIMAL POSITION
DC7A  E901         SBC       #1               ; X
DC7C  85F7         STA       ZTEMP4           ; SAVE IT
               ;
               ;       DO 1ST DIGIT
               ;
DC7E  B5D5         LDA       FR0M,X           ; GET FROM FR0
DC80               LSRA                       ; SHIFT OUT LOW ORDER BITS
DC80 +4A           LSR       A
DC81               LSRA                       ; TO GET 1ST DIGITS
DC81 +4A           LSR       A
DC82               LSRA                       ; X
DC82 +4A           LSR       A
DC83               LSRA                       ; X
DC83 +4A           LSR       A
DC84  209DDC       JSR       :STNUM           ; GO PUT # IN BUFFER
               ;
               ;       DO SECOND DIGIT
               ;
DC87  B5D5         LDA       FR0M,X           ; GET NUMBER FROM FR0
DC89  290F         AND       #$0F             ; AND OUT HIGH ORDER BITS
DC8D  209DDC       JSR       :STNUM           ; GO PUT # IN BUFFER
               ;
DC8E  E8           INX                        ; INCR FR0 POINTER
DC8F  E005         CPX       #FMPREC          ; DONE LAST FR0 BYTE?
DC91  90E3 ^DC76   BCC       :CVBYTE          ; IF NOT, MORE TO DO
               ;
               ;       PUT IN DECIMAL POINT NOW?
               ;
DC93           :TSTDP
DC93  A5F7         LDA       ZTEMP4           ; GET DECIMAL POSITION
DC95  D005 ^DC9C   BNE       :TST1            ; IF NOT = 0 RTN
DC97  A92E         LDA       #'.'             ; GET ASCII DECIMAL POINT
DC99  209FDC       JSR       :STCHAR          ; PUT D.P. IN BUFFER
DC9C           :TST1
DC9C  60           RTS

;:STNUM - Put ASCII Number in LBUFF
               ;       ON ENTRY    A - DIGIT TO BE CONVERTED TO ASCII
               ;                       AND PUT IN LBUFF
               ;                   Y - INDEX IN LBUFF

;:STCHAR - Store Character in A in LBUFF

DC9D           :STNUM
DC9D  0930         ORA       #$30             ; CONVERT TO ASCII
DC9F           :STCHAR
DC9F  998005       STA       LBUFF,Y          ; PUT IN LBUFF
DCA2  C8           INY                        ; INCR LBUFF POINTER
DCA3  60           RTS

;:FNZERO - Find Last Non-zero Character in LBUFF
               ;       ON EXIT    A - LAST CHAR
               ;                  X - POINT TO LAST CHAR
               ;
DCA4           :FNZERO
DCA4  A20A         LDX       #10              ; POINT TO LAST CHAR IN LBUFF
               ;
DCA6           :FN3
DCA6  BD8005       LDA       LBUFF,X          ; GET THE CHARACTER
DCA9  C92E         CMP       #'.'             ; ID IT DECIMAL?
DCAB  F007 ^DCB4   BEQ       :FN1             ; IF YES, BR
DCAD  C930         CMP       #'0'             ; IS IT ZERO?
DCAF  D007 ^DCB8   BNE       :FN2             ; IF NOT, BR
DCB1  CA           DEX                        ; DECREMENT INDEX
DCB2  D0F2 ^DCA6   BNE       :FN3             ; UNCONDITIONAL BR

;----------264

               ;
               ;
DCB4           :FN1
DCB4  CA           DEX                        ; DECREMENT BUFFER INDEX
DCB5  BD8005       LDA       LBUFF,X          ; GET LAST CHAR
DCB8           :FN2
DCB8  60           RTS

;:GETDIG - Get Next Digit from FR0
               ;       ON ENTRY    FR0 - #
               ;
               ;       ON EXIT     A - DIGIT
               ;
               ;
DCB9           :GETDIG
DCB9  20EBDB       JSR       NISH0            ; SHIFT FR0 LEFT ONE NIBBLE
               ;
DCBC  A5EC         LDA       FRX              ; GET BYTE CONTAINING
                                                SHIFTED NIBBLE
DCBE  290F         AND       #$0F             ; AND OUT HIGH ORDER NIBBLE
DCC0  60           RTS

;:DECINB - Decrement INBUFF

DCC1           :DECINB
DCC1  38           SEC                        ; SUBSTRACT ONE INBUFF
DCC2  A5F3         LDA       INBUFF           ; X
DCC4  E901         SBC       #1               ; X
DCC6  85F3         STA       INBUFF           ; X
DCC8  A5F4         LDA       INBUFF+1         ; X
DCCA  E900         SBC       #0               ; X
DCCC  85F4         STA       INBUFF+1         ; X
DCCE  60           RTS

;MDESUP - Common Set-up for Multiply and Divide Exponent
               ;       ON EXIT    FR1 - FR1 EXP WITH OUT SIGN
               ;                  A - FR0 EXP WITHOUT SIGN
               ;                  FRSIGN - SIGN FOR QUOTIENT
               ;
DCCF           MDESUP
DCCF  A5D4         LDA       FR0              ; GET FR0 EXPONENT
DCD1  45E0         EOR       FR1              ; GET FR1 EXPONENT
DCD3  2980         AND       #$80             ; AND OUT ALL BUT SIGN BIT
DCD5  85EE         STA       FRSIGN           ; SAVE SIGN
               ;
DCD7  06E0         ASL       FR1              ; SHIFT OUT SIGN IN FR1 EXP
DCD9  46E0         LSR       FR1              ; RESTORE FR1 EXP WITHOUT SIGN
DCDB  A5D4         LDA       FR0              ; GET FR0 EXP
DCDD  297F         AND       #$7F             ; AND OUT SIGN BIT
DCDF  60           RTS

;MDSUP - Common Set-up for Multiply and Divide
               ;       ON ENTRY    A - EXPONENT
               ;                   CC - SET BY ADD OR SUB TO GET A
               ;
               ;
DCE0           MDSUP
DCE0  05EE         ORA       FRSIGN           ; OR IN SIGN BIT
DCE2  85ED         STA       EEXP             ; SAVE EXPONENT FOR LATER
DCE4  A900         LDA       #0               ; CLEAR A
DCE6  85D4         STA       FR0              ; CLEAR FR0 EXP
DCE8  85E0         STA       FR1              ; CLEAR FR0 EXP
               ;
               ;
DCEA  2028DD       JSR       MVFR12           ; MOVE FR1 TO FR2
               ;
DCED  20E7DB       JSR       NIBSH2           ; SHIFT FR2 1 NIBBLE LEFT
DCF0  A5EC         LDA       FRX              ; GET SHIFTED NIBBLE

;----------265

DCF2  290f         AND       #$0F             ; AND OUT HIGH ORDER NIBBLE
DCF4  85E6         STA       FR2              ; STORE TO FINISH SHIFT
               ;
DCF6  A905         LDA       #FMPREC          ; SET LOOP CONTROL
DCF8  85F5         STA       ZTEMP1           ; X
               ;
DCFA  2034DD       JSR       MVFR0E           ; MOVE FR0 TO FRE
DCFD  2044DA       JSR       ZFR0             ; CLEAR FR0
               ;
DD00  60           RTS

;FRA
               ;       FRA10 - ADD FR1 TO FR0 [6 BYTES]
               ;
               ;       FRA20 - ADD FR2 TO FR0 [6 BYTES]
               ;
               ;       FRA1E - ADD FR1 TO FRE
               ;
               ;       FRA2E - ADD FR2 TO FRE
               ;
DD01           FRA10
DD01  A2D9         LDX       #FR0+FMPREC      ; POINT TO LAST BYTE OF SUM
DD03  D006 ^DD0B   BNE       :F1
               ;
DD05           FRA10
DD05  A2D9         LDX       #FR0+FMPREC      ; POINT TO LAST BYTE OF SUM
DD07  D008 ^DD0B   BNE       :F2
               ;
DD09           FRA1E
DD09  A2DF         LDX       #FRE+FMPREC
DD0B           :F1
DD0B  A0E5         LDY       #FR1+FMPREC
DD0D  D004 ^DD13   BNE       :FRA
DD0F           FRA2E
DD0F  A2DF         LDX       #FRE+FMPREC
DD11           :F2
DD11  A0EB         LDY       #FR2+FMPREC
               ;
               ;
DD13           :FRA
DD13  A905         LDA       #FMPREC          ; GET VALUE FOR LOOP CONTROL
DD15  85F7         STA       ZTEMP4           ; SET LOOP CONTROL
DD17  18           CLC                        ; CLEAR CARRY
DD18  F8           SED                        ; SET DECIMAL MODE
DD19           :FRA1
DD19  B500         LDA       0,X              ; GET 1ST BYTE OF
DD1B  790000       ADC       0,Y              ; ADD
DD1E  9500         STA       0,X              ; STORE
DD20  CA           DEX                        ; POINT TO NEXT BYTE
DD21  88           DEY                        ; POINT TO NEXT BYTE
DD22  C6F7         DEC       ZTEMP4           ; DEC COUNTER
DD24  10F3 ^DD19   BPL       :FRA1            ; IF MORE TO DO, DO IT
DD26  D8           CLD                        ; CLEAR DECIMAL MODE
DD27  60           RTS

;MVFR12 - Move FR1 to FR2

DD28           MVFR12
DD28  A005         LDY       #FMPREC          ; SET COUNTER
DD2A           :MV2
DD2A  B9E000       LDA       FR1,Y            ; GET A BYTE
DD2D  99E600       STA       FR2,Y            ; STORE IT
               ;
DD30  88           DEY
DD31  10F7 ^DD2A   BPL       :MV2             ; IF MORE TO MOVE, DO IT
DD33  60           RTS

;----------266

;MVFR0E - Move FR0 TO FRE

DD34           MVFR0E
DD34  A005         LDY       #FMPREC
DD36           :MV1
DD36  B9D400       LDA       FR0,Y
DD39  99DA00       STA       FRE,Y
               ;
DD3C  88           DEY
DD3D  10F7 ^DD36   BPL       :MV1
DD3F  60           RTS

               ;       Polynomial Evaluation

               ;       Y=A[0]+A[1]*X+A[2]*X**2+...+A[N]*X**N,N>0
               ;       =[[...[A[N]*X+A[N-1]]]*X+...+A[2]]*X+A[1]]*X+A[0]
               ;       INPUT: X IN FR0, N+1 IN A-REG
               ;       OUTPUT Y IN FR0
               ;       USES FPTR2, PLYCNT, PLYARG
               ;       CALLS FST0R, FMOVE, FLD1R, FADD, FMUL
DD40  86FE     PLYEVL  STX     FPTR2       ;SAVE POINTER TO COEFF'S
DD42  84FF         STY     FPTR2+1
DD44  85EF         STA PLYCNT
DD46  A2E0         LDX     #PLYARG&$FF
DD48  A005         LDY     #PLYARG/$100
DD4A  20A7DD       JSR     FST0R           ;SAVE ARG
DD4D  20B6DD       JSR     FMOVE           ;ARG->FR1
DD50  A6FE         LDX     FPTR2
DD52  A4FF         LDY     FPTR2+1
DD54  2089DD       JSR     FLD0R           ;COEF->FR0 [INIT SUM]
DD57  C6EF         DEC     PLYCNT
DD59  F02D ^DD88   BEQ     PLYOUT          ;DONE?
DD5B  20DBDA   PLYEV1  JSR     FMUL        ; SUM * ARG
DD5E  B028 ^DD88   BCS     PLTOUT          ; O'FLOW
DD60  18           CLC
DD61  A5FE         LDA     FPTR2           ;BUMP COEF POINTER
DD63  6906         ADC     #FPREC
DD65  85FE         STA     FPTR2
DD67  9006 ^DD6F   BCC     PLYEV2
DD69  A5FF         LDA     FPTR2+1         ;ACROSS PAGE
DD6B  6900         ADC     #0
DD6D  85FF         STA     FPTR2+1
DD6F  A6FE     PLYEV2  LDX     FPTR2
DD71  A4FF         LDY     FPTR2+1
DD73  2098DD       JSR     FLD1R           ;GET NEXT COEF
DD76  2066DA       JSR     FADD            ;SUM*ARG + COEF
DD79  B00D ^DD88   BCS     PLYOUT          ; O'FLOW
DD7B  C6EF         DEC     PLYCNT
DD7D  F009 ^DD88   BEQ     PLYOUT          ;DONE ?
DD7F  A2E0         LDX     #PLYARG&$FF
DD81  A005         LDY     #PLYARG/$100
DD83  2098DD       JSR     FLD1R           ;GET ARG AGAIN
DD86  30D3 ^DD5B   BMI     PLYEV1          ; [=JMP]
DD88  60       PLYOUT  RTS

               ;       Floating Load/Store
               ;      LOAD FR0 FROM [X,Y] X=LSB, Y=MSB, USES FLPTR [PG0]
DD89  86FC     FLD0R   STX    FLPTR        ; SET FLPTR => [X,Y]
DD8B  84FD         STY     FLPTR+1
DD8D  A005     FLD0P   LDY     #FPREC-1    ;# BYTES ENTER HERE W/FLPTR SET
DD8F  B1FC     FLD01   LDA     [FLPTR],Y   ; MOVE
DD91  99D400       STA     FR0,Y
DD94  88           DEY
DD95  10F8 ^DD8F   BPL     FLD01           ; COUNT & LOOP
DD97  60           RTS
               ;
               ;       LOAD FR1 FROM [X,Y] OR [FLPTR]
DD98  86FC     FLD1R   STX     FLPTR       ; FLPTR=>[X,Y]

;----------267

DD9A  84FD         STY     FLPTR+1
DD9C  A005     FLD1P   LDY     #FPREC-1    ; # BYTES ENTER W/FLPTR SET
DD9E  B1FC     FLD11   LDA     [FLPTR],Y   ; MOVE
DDA0  99E000       STA     FR1,Y
DDA3  88           DEY
DDA4  10F8 ^DD9E   BPL     FLD11           ; COUNT & LOOP
DDA6  60           RTS
               ;
               ;       STORE FR0 IN [X,Y] OR [FLPTR]
DDA7  86FC     FST0R   STX     FLPTR
DDA9  84FD         STY     FLPTR+1
DDAB  A005     FST0P   LDY     #FPREC-1    ; ENTRY W/FLPTR
DDAD  B9D400   FST01   LDA     FR0,Y
DDB0  91FC         STA     [FLPTR],Y
DDB2  88           DEY
DDB3  10F8 ^DDAD   BPL     FST01
DDB5  60           RTS
               ;
               ;       MOVE FR0 TO FR1
               ;
DDB6           MV0TO1
DDB6  A205     FMOVE   LDX     #FPREC-1
DDB8  B5D4     FMOVE1  LDA     FR0,X
DDBA  95E0         STA     FR1,X
DDBC  CA           DEX
DDBD  10F9 ^DDB8   BPL     FMOVE
DDBF  60           RTS

               ;       EXP[X] and EXP10[X]

DDC0  A289     EXP     LDX     #LOG10E&$FF ; E**X = 10**[X*LOG10[E]]
DDC2  A0DE         LDY     #LOG10E/$100
DDC4  2098DD       JSR     FLD1R
DDC7  20DBDA       JSR     FMUL
DDCA  B07F ^DE48   BCS     EXPERR
DDCC  A900     EXP10   LDA     #0          ; 10**X
DDCE  85F1         STA     XFMLG           ; CLEAR TRANSFORM FLAG
DDD0  A5D4         LDA     FR0
DDD2  85F0         STA     SGNFLG          ; REMEMBER ARG SGN
DDD4  297F         AND     #$7F            ; ; & MAKE PLUS
DDD6  85D4         STA     FR0
DDD8  38           SEC
DDD9  E940         SBC     #$40
DDDB  3026 ^DE03   BMI     EXP1            ; X<1 SO USE SERIES DIRECTLY
               ;       10**X = 10**[I+F] = [10**I] * [10**F]
DDDD  C904         CMP     #FPREC-2
DDDF  106A ^DE4B   BPL     EXPERR          ; ARG TOO BIG
DDE1  A2E6         LDX     #FPSCR&$FF
DDE3  A005         LDY     #FPSCR/$100
DDE5  20A7DD       JSR     FST0R           ; SAVE ARG
DDE8  20D2D9       JSR     FPI             ; MAKE INTEGER
DDEB  A5D4         LDA     FR0
DDED  85F1         STA     XFMFLG          ; SAVE MULTIPLIER EXP IN XFORM
DDEF  A5D5         LDA     FR0+1           ; CHECK MSB
DDF1  D058 ^DE4B   BNE     EXPERR          ; SHOULD HAVE NONE
DDF3  20AAD9       JSR     IFP             ; NOW TURN IT BACK TO FLPT
DDF6  20B6DD       JSR     FMOVE
DDF9  A2E6         LDX     #FPSCR&$FF
DDFB  A005         LDY     #FPSCR/$100
DDFD  2089DD       JSR     FLD0R           ; GET ARG BACK
DE00  2060DA       JSR     FSUB            ; ARG - INTEGER PART = FRACTION
               ;       NOW HAVE FRACTION PART OF ARG [F] IN FR0,
               ;       INTEGER PART [I]
               ;       IN XFMFLG, USE SERIES APPROX FOR
               ;       10**F, THEN MULTIPLY BY 10**I
DE03           EXP1
DE03  A90A         LDA     #NPCOEF
DE05  A24D         LDX     #P10COF&$FF
DE07  A0DE         LDY     #P10COF/$100

;----------268

DE09  2040DD       JSR     PLYEVL          ;P[X]
DE0C  20B6DD       JSR     FMOVE
DE0F  20DBDA       JSR     FMUL            ;P[X]*P[X]
DE12  A5F1         LDA     XFMFLG          ; DID WE TRANSFORM ARG
DE14  F023 ^DE39   BEQ     EXPSGN          ; NO SO LEAVE RESULT ALONE
DE16  18           CLC
DE17               RORA                    ; I/2
DE17 +6A           ROR     A
DE18  85E0         STA     FR1             ; SVE AS EXP-TO-BE
DE1A  A901         LDA     #1              ; GET MANTISSA BYTE
DE1C  9002 ^DE20   BCC     EXP2            ; CHECK BIT SHIFTED OUT OF A
DE1E  A910         LDA     #$10            ; I WAS ODD - MANTISSA = 10
DE20  85E1     EXP2    STA     FR1+1
DE22  A204         LDX     #FPREC-2
DE24  A900         LDA     #0
DE26  95E2     EXP3    STA     FR1+2,X     ; CLEAR REST OF MANTISSA
DE28  CA           DEX
DE29  10FB ^DE26   BPL     EXP3
DE2B  A5E0         LDA     FR1             ; BACK TO EXPONENT
DE2D  18           CLC
DE2E  6940         ADC     #$40            ; BAIS IT
DE30  B019 ^DE4B   BCS     EXPERR          ; OOPS...IT'S TOO BIG
DE32  3017 ^DE4B   BMI     EXPERR
DE34  85E0         STA     FR1             ; FR1 = 10**I
DE36  20DBDA       JSR     FMUL            ; [10**I]*[10**F]
DE39  A5F0     EXPSGN  LDA     SGNFLG      ; WAS ARG<0
DE3B  100D ^DE4A   BPL     EXPOUT          ; NO-DONE
DE3D  20B6DD       JSR     FMOVE           ; YES-INVERT RESULT
DE40  A28F         LDX     #FONE&$FF
DE42  A0DE         LDY     #FONE/$100
DE44  2089DD       JSR     FLD0R
DE47  2028D8       JSR     FDIV
DE4A  60       EXPOUT  RTS                 ; [PANT, PANT - FINISHED::]
DE4B  38       EXPERR  SEC                 ; FLAG ERROR
DE4C  60           RTS                     ; & QUIT
DE4D  3D17941900 P10COF .BYTE   $3D,$17,$94,$19,$0,$0 ;0.0000179419
      00
DE53  3D57330500   .BYTE   $3D,$57,$33,$05,$0,$0 ;0.0000573305
      00
DE59  3E05547662   .BYTE   $3E,$05,$54,$76,$62,$0 ;0.0005547662
      00
DE5F  3E32196227   .BYTE   $3E,$32,$19,$62,$27,$0 ;0.0032176227
      00
DE65  3F01686030   .BYTE   $3F,$01,$68,$60,$30,$36 ;0.0168603036
      36
DE6B  3F07320327   .BYTE   $3F,$07,$32,$03,$27,$41 ;0.0732032741
      41
DE71  3F25433456   .BYTE   $3F,$25,$43,$34,$56,$75 ;0.2543345675
      75
DE77  3F66273730   .BYTE   $3F,$66,$27,$37,$30,$50 ;0.663737350
      50
DE7D  4001151292   .BYTE   $40,$01,$15,$12,$92,$55 ;1.15129255
      55
DE83  3F99999999   .BYTE   $3F,$99,$99,$99,$99,$99 ;0.999999999
      99
      = 000A   NPCOEF  EQU     (*-P10COF)/FPREC
DE89  3F43429448 LOG10E .BYTE   $3F,$43,$42,$94,$48,$19  ; LOG10[E]
      19
DE8F  4001000000 FONE   .BYTE   $40,$1,0,0,0,0 ; 1.0
      00

               ;         Z=[X-C]/[X+C]

DE95  86FE     XFORM   STX     FPTR2
DE97  84FF         STY     FPTR2+1
DE99  A2E0         LDX     #PLYARG&$FF
DE9B  A005         LDY     #PLYARG/$100
DE9D  20A7DD       JSR     FST0R           ; STASH X IN PLYARG
DEA0  A6FE         LDX     FPTR2
DEA2  A4FF         LDY     FPTR2+1

;----------269

DEA4  2098DD       JSR     FLD1R
DEA7  2066DA       JSR     FADD            ; X+C
DEAA  A2E6         LDX     #FPSCR&$FF
DEAC  A005         LDY     #FPSCR/$100
DEQE  207DD        JSR     FST0R
DEB1  A2E0         LDX     #PLYARG&$FF
DEB3  A005         LDY     #PLYARG/$100
DEB5  2089DD       JSR     FLD0R
DEB8  A6FE         LDX     FPTR2
DEBA  A4FF         LDY     FPTR2+1
DEBC  2098DD       JSR     FLD1R
DEBF  2060DA       JSR     FSUB            ; X-C
DEC2  A2E6         LDX     #FPSCR&$FF
DEC4  A005         LDY     #FPSCR/$100
DEC6  2098DD       JSR     FLD1R
DEC9  2028DB       JSR     FDIV            ; [X-C]/[X+C] = Z
DECC  60           RTS

               ;         LOG10[X]

DECD  A901     LOG     LDA     #1          ; REMEMBER ENTRY POINT
DECF  D002 ^DED3   BNE     LOGBTH
DED1  A900     LOG10   LDA     #0          ; CLEAR FLAG
DED3  85F0     LOGBTH  STA     SGNFLG      ; USE SGNFLG FOR LOG/LOG10
                                             MARKER
DED5  A5D4         LDA     FR0
DED7  1002 ^DEDB   BPL     LOG5
DED9  38       LOGERR  SEC
DEDA  60           RTS
DEDB           LOG5
               ;       WE WANT X = F*[10**Y], 1<F<10
               ;       10**Y HAS SAME EXP BYTE AS X
               ;       & MANTISSA BYTE = 1 OR 10
DEDB  A5D4     LOG1    LDA     FR0
DEDD  85E0         STA     FR1
DEDF  38           SEC
DEE0  E940         SBC     #$40
DEE2               ASLA
DEE2 +0A           ASL     A
DEE3  85F1         STA     XFMFLG          ; REMEMBER Y
DEE5  A5D5         LDA     FR0+1
DEE7  29F0         AND     #$F0
DEE9  D004 ^DEEF   BNE     LOG2
DEEB  A901         LDA     #1
DEED  D004 ^DEF3   BNE     LOG3
DEEF  E6F1     LOG2    INC     XFMFLG      ; BUMP Y
DEF1  A910         LDA     #$10
DEF3  85E1     LOG3    STA     FR1+1       ; SET UP MANTISSA
DEF5  A204         LDX     #FPREC-2        ; CLEAR REST OF MANTISSA
DEF7  A900         LDA     #0
DEF9  95E2     LOG4    STA     FR1+2,X
DEFB  CA           DEX
DEFC  10FB ^DEF9   BPL     LOG4
DEFE  2028DB       JSR     FDIV            ; X = X/[10**Y] - S.B.
                                             IN [1,10]
DF01           FLOG10                      ;;LOG10[X],1<=X<=10
DF01  A266         LDX     #SQR10&$FF
DF03  A0DF         LDY     #SQR10/$100
DF05  2095DE       JSR     XFORM           ; Z = [X-C]/[X+C],C*C = 10
DF08  A2E6         LDX     #FPSCR&$FF
DF0A  A005         LDY     #FPSCR/$100
DF0C  20A7DD       JSR     FST0R           ; SAVE Z
DF0F  20B6DD       JSR     FMOVE
DF12  20DBDA       JSR     FMUL            ; Z*Z
DF15  A90A         LDA     #NLCOEF
DF17  A272         LDX     #LGCOEF&$FF
DF19  A0DF         LDY     #LGCOEF/$100
DF1B  2040DD       JSR     PLYEVL          ; P[Z*Z]
DF1E  A2E6         LDX     #FPSCR&$FF
DF20  A005         LDY     #FPSCR&$100
DF22  2098DD       JSR     FLDIR

;----------270

DF25  20DBDA       JSR     FMUL            ; Z*P[Z*Z]
DF28  A26C         LDX     #FHALF&$FF
DF2A  A0DF         LDY     #FHALF/$100
DF2C  2098DD       JSR     FLD1R
DF2F  2066DA       JSR     FADD            ; 0.5 + Z*P[Z*Z]
DF32  20B6DD       JSR     FMOVE
DF35  A900         LDA     #0
DF37  85D5         STA     FR0+1
DF39  A5F1         LDA     XFMFLG
DF3B  85D4         STA     FR0
DF3D  1007 ^DF46   BPL     LOG6
DF3F  49FF         EOR     #-1             ; FLIP SIGN
DF41  18           CLC
DF42  6901         ADC     #1
DF44  85D4         STA     FR0
DF46           LOG6
DF46  20AAD9       JSR     IFP             ; LEAVES FR1 ALONE
DF49  24F1         BIT     XFMFLG
DF4B  1006 ^DF53   BPL     LOG7
DF4D  A980         LDA     #$80            ; FLIP SIGN
DF4F  05D4         ORA     FR0
DF51  85D4         STA     FR0
DF53           LOG7
DF53  2066DA       JSR     FADD            ; LOG[X] = LOG[X] +Y
DF56           LOGOUT
DF56  A5F0         LDA     SGNFLG
DF58  F00A ^DF64   BEQ     LOGDON          ; WAS LOG10, NOT LOG
DF5A  A289         LDX     #LOG10E&255     ; LOG[X]/LOG10[E]
DF5C  A0DE         LDY     #LOG10E/$100
DF5E  2098DD       JSR     FLDIR
DF61  2028DB       JSR     FDIV
DF64  18       LOGDON  CLC
DF65  60           RTS
DF66  4003162277 SQR10 .BYTE $40,$03,$16,$22,$77,$66 ;SQUARE ROOT OF 10
      66
DF6C  3F50000000 FHALF .BYTE $3F,$50,$0,$0,$0,$0     ; 0.5 
      00
DF72  3F49155711 LGCOEF .BYTE $3F,$49,$15,$57,$11,$08 ;0.4915571108
      08
DF78  BF51704947        .BYTE $BF,$51,$70,$49,$47,$08 ;-0.5170494708
      08
DF7E  3F39205761        .BYTE $3F,$39,$20,$57,$61,$95 ;0.3920576195
      95
DF84  BF04396303        .BYTE $BF,$04,$39,$63,$03,$55 ;-0.0439630355
      55
DF8A  3F10093012        .BYTE $3F,$10,$09,$30,$12,$64 ;0.1009301264
      64
DF90  3F09390804        .BYTE $3F,$09,$39,$08,$04,$60 ; 0.0939080460
      60
DF96  3F12425847        .BYTE $3F,$12,$42,$58,$47,$42 ;0.1242584742
      42
DF9C  3F17371206        .BYTE $3F,$17,$37,$12,$06,$08 ;0.1737120608
      08
DFA2  3F28952971        .BYTE $3F,$28,$95,$29,$71,$17 ;0.28957117
      17
DFA8  3F86858896        .BYTE $3F,$86,$85,$88,$96,$44 ;0.8685889644
      44
DFAE  3E16054449        .BYTE $3E,$16,$05,$44,$49,$0 ;0.0016054449
      00
DFB4  BE95683845        .BYTE $BE,$95,$68,$38,$45,$0 ;-0.009568345
      00
DFBA  3F02687994        .BYTE $3F,$02,$68,$79,$94,$16 ;0.0268799416
      16
DFC0  BF04927890        .BYTE $BF,$04,$92,$78,$90,$80 ;-0.0492789080
      80
DFC6  3F07031520        .BYTE $3F,$07,$03,$15,$20,$0 ;0.0703152000
      00
DFCC  BF08922912        .BYTE $BF,$08,$92,$29,$12,$44 ;-0.0892291244
      44
DFD2  3F11084009        .BYTE $3F,$11,$08,$40,$09,$11 ;0.1108400911
      11

;----------271
;
DFD8  BF14283156        .BYTE $BF,14,28,31,56,04 ;-0.1428315604
      04
DFDE  3F19999877        .BYTE $3F,19,99,98,77,44 ;0.1999987744
      44
DFE4  BF33333331        .BYTE $BF,33,33,33,31,13 ;-0.3333333113
      13
DFEA  3F99999999  FP9S  .BYTE $3F,99,99,99,99,99 ;0.999999999
      99
      = 000B      NATCF  EQU     (*-ATCOEF)/FPREC
DFF0  3F78539816  PIOV4 .BYTE    $3F,78,53,98,16,34 ; PI/4 = ARCTAN[1.0]
      34
;
;                     Atari Cartridge Vectors
;
DFF6  = BFF9       ORG     CRTGI
BFF9           SCVECT
BFF9  60           RTS
BFFA  00A0         DW      COLDSTART       ; COLDSTART ADDR
BFFC  00           DB      0               ; CART EXISTS
BFFD  05           DB      5               ; FLAG
BFFE  F98F         DW      SVECT           ; COLDSTART ENTRY ADDR
;
;            End of BASIC
; 
C000               END


