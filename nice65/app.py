#!/usr/bin/python3

# optimizer concepts at:
# https://web.archive.org/web/20010721064530/http://www.heilbronn.netsurf.de/~dallmann/lunix/src/opt65.c

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, Action
import fnmatch

try:
    import importlib_metadata as metadata
except ImportError:
    from importlib import metadata

import os
import re
import sys

if 'nice65' in sys.modules:
    del sys.modules['nice65']
import nice65

from lark import Lark, Token, Transformer, Discard

# NMOS 6502 Opcodes
# https://www.masswerk.at/6502/6502_instruction_set.html
# https://www.westerndesigncenter.com/wdc/documentation/w65c02s.pdf (page 21)
# FIXME: add COP(rocessor) command, with implied 2-byte opcode
# FIXME: and the ability to place a two-byte code after a BRK
MOS_INSTRUCTIONS = [
    # fmt: off
    'adc', 'and', 'asl', 'bcc', 'bcs', 'beq', 'bit', 'bmi', 'bne', 'bpl',
    'brk', 'bvc', 'bvs', 'clc', 'cld', 'cli', 'clv', 'cmp', 'cpx', 'cpy',
    'dec', 'dex', 'dey', 'eor', 'ina', 'inc', 'inx', 'iny', 'jmp', 'jsr',
    'lda', 'ldx', 'ldy', 'lsr', 'nop', 'ora', 'pha', 'php', 'pla', 'plp',
    'rol', 'ror', 'rti', 'rts', 'sbc', 'sec', 'sed', 'sei', 'sta', 'stx',
    'sty', 'tax', 'tay', 'tsx', 'txa', 'txs', 'tya',
    # fmt: on
]

# NMOS "illegal" 6502 Opcodes
# https://www.masswerk.at/nowgobang/2021/6502-illegal-opcodes
# ane/xaa, lxa, sha/shx/shy and tas are not included as these are unstable
# USBC not included as it is essentially sbc
ILLEGAL_INSTRUCTIONS = [
    # fmt: off
    'alr', 'anc', 'arr', 'dcp', 'isc', 'las', 'lax', 'rla', 'rra',
    'sax', 'sbx', 'slo', 'sre',
    # fmt: on
]

# CMOS 65C02 Opcodes
# https://wilsonminesco.com/NMOS-CMOSdif/
# https://www.westerndesigncenter.com/wdc/documentation/w65c02s.pdf (page 21)
CMOS_INSTRUCTIONS = [
    # fmt: off
    'bbr0', 'bbr1', 'bbr2', 'bbr3', 'bbr4', 'bbr5', 'bbr6', 'bbr7',
    'bbs0', 'bbs1', 'bbs2', 'bbs3', 'bbs4', 'bbs5', 'bbs6', 'bbs7',
    'bra', 'phx', 'phy', 'plx', 'ply',
    'rmb0', 'rmb1', 'rmb2', 'rmb3', 'rmb4', 'rmb5', 'rmb6', 'rmb7',
    'smb0', 'smb1', 'smb2', 'smb3', 'smb4', 'smb5', 'smb6', 'smb7',
    'stp', 'stz', 'trb', 'tsb', 'wai',
    # fmt: on
]

# CMOS 65CE02 Opcodes
# https://web.archive.org/web/20221112231057if_/http://archive.6502.org/datasheets/mos_65ce02_mpu.pdf
# FIXME: is aug the same as cop?
CE_INSTRUCTIONS = [
    # fmt: off
    'aug', 'asr', 'bsr', 'bru', 'neg', 'idw', 'dew', 'inz', 'dez',
    'asw', 'row', 'rtn', 'cpz', 'cee', 'see', 'phw', 'phz', 'plz',
    'taz', 'tza', 'tab', 'tba', 'tsy', 'tys', 'ply',
    # fmt: on
]

instructions = MOS_INSTRUCTIONS + CMOS_INSTRUCTIONS + CE_INSTRUCTIONS

# assembler directives from the original MOS cross-assembler
# https://www.pagetable.com/docs/cbmasm/MCS6500%20Microcomputer%20Family%20Cross%20Assembler%20Manual.pdf
# dbyte is a 16-bit value in high-low format, the opposite of the 6502's normal low-high
# page does a page feed as well as printing the optional string constant on every following page
# skip prints nnn blank lines, used for cleaning up listings
# opt sets various printing and compiling options
# res(erve) sets aside nnn bytes, but does not set the value
# end marks the end, as in BASIC, and is not required
# FIXME: EQU NOT YET SUPPORTED
MOS_DIRECTIVES = { 'equ', 'byte', 'word', 'dbyte', 'page', 'skip', 'opt', 'res' 'end' }

# the *= style of org is handled below
CA65_DIRECTIVES = { 'org', 'set', 'segment', 'zeropage', 'data', 'code', 'bss', 'include', 'import', 'importzp', 'export', 'exportzp'}

# Atari Assembler/Editor User's Manual
# title is printed to every page, including those with a page directive
# tab is used to set column the spacing 
ATARI_DIRECTIVES = { 'title', 'tab' }

instructions_def = " | ".join(['"' + instr + '"i' for instr in instructions])

directives = MOS_DIRECTIVES.union(CA65_DIRECTIVES).union(ATARI_DIRECTIVES)

def main():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("infile", help='Input file, pass "-" to read from for stdin')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-o",
        "--outfile",
        metavar="outfile",
        help='Output file, defaults to "-" for stdout',
        default="-",
    )
    group.add_argument(
        "-m",
        "--modify-in-place",
        help="Use input file as output target",
        action="store_true",
    )
    group.add_argument(
        "-r",
        "--recursive",
        help="Recursively fix all files",
        action="store_true",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        help="Match file names by Unix shell-style wildcard when used with -r",
        default='*.s',
    )
    parser.add_argument(
        "-l",
        "--colonless-labels",
        help="Allow labels without a colon (this option breaks macros, use with legacy code only)",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--lowercase-mnemonics",
        help="Use lowercase mnemonics",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Show version",
        nargs=0,
        action=Version,
    )
    args = parser.parse_args()

    definition = (
        # fmt: off
        r"""
        %import common.NUMBER
        %import common.HEXDIGIT
        %import common.LETTER
        %import common.WS_INLINE -> _WS
        %ignore _WS

        start: line*

        line: linenum? (labeldef statement | statement | labeldef | numeric_var | constant_def)? comment? "\n"

        # doing this so a separate token node is created
        # FIXME: inline into the rule above
        linenum: LINE_NUMBER

        labeldef: LABEL ":" """ + ('?' if args.colonless_labels else '') + r""" | ":"

        statement: asm_statement | macro_start | macro_end | directive 

        asm_statement: INSTR (_WS+ operand ("," operand)?)?
        macro_start: ".macro" IDENT (IDENT ("," IDENT)*)?
        macro_end: ".endmacro"

        directive: ("." IDENT | "*=" expr) (_WS+ /[^\n]+/)?

        constant_def: LABEL /=|:=/ /[^\n]+/
        numeric_var: IDENT directive

        comment: INDENT* ";" COMMENT_TEXT?

        ?operand: REGISTER | (/#/? /[<>]/? expr)
        ?expr: OP? LITERAL (OP expr)? # OP in front for the .LOW. and .HIGH.
            | /\(/ expr /\)/ -> expr

        # terminals
        LINE_NUMBER: NUMBER
        COMMENT_TEXT: /[^\n]+/
        INSTR: """ + (instructions_def if args.colonless_labels else 'IDENT') + r"""
        REGISTER: "A"i | "X"i | "Y"i # FIXME: add Z if in CE mode

        # a literal is a number (in hex, binary, or octal), a label name, an offset from a label, ASCII values, or the *, which is the current location
        # the MOS cross-compiler allows -ve values, so this version allows signed values in general
        # the Atari OS uses some signed hex, all examples have the sign on the left of the type ($/%/@) so this is assumed to be the only syntax
        # ... it also has single-character ASCII literals which have only the leading quote
        LITERAL: ["+"|"-"]? NUMBER 
          | ["+"|"-"]? /\$/ [HEXDIGIT+] 
          | ["+"|"-"]? /%/ /[01]+/ 
          | ["+"|"-"]? /@/ /[01234567]+/ 
          | /'.'/ 
          | /'/ LETTER 
          | LABEL 
          | LABEL_REL 
          | /\*/
        
        # allow leading digits in lables if they have the @
        LABEL: IDENT | "@" /[a-zA-Z0-9_\?\.]+/
        LABEL_REL: /:[\+\-]+/

        # the MOS cross-compilers allows . and ? in identifiers
        IDENT: /[a-zA-Z_][a-zA-Z0-9_\?\.]*/

        # the MOS cross-compiler has the .LOW. and .HIGH. operations
        # As65 has .HI. and .BANK.
        OP: "+" | "-" | "*" | "/" | "|" | "&" | "^" | "," | ".LOW." | ".HIGH." | ".HI." | ".BANK." | ".AND." | ".OR."

        INDENT: /[ ]+/
    """
        # fmt: on
    )

    grammar = Lark(definition)#, parser="lalr")

    if args.recursive:
        for root, _, files in os.walk(args.infile):
            for file in files:
                if fnmatch.fnmatch(file, args.pattern):
                    path = os.path.join(root, file)
                    print("Fixing", path, file=sys.stderr)
                    fix(grammar, path, None, True, args.colonless_labels, args.lowercase_mnemonics)
    else:
        fix(
            grammar,
            args.infile,
            args.outfile,
            args.modify_in_place,
            args.colonless_labels,
            args.lowercase_mnemonics,
        )


class Version(Action):
    def __call__(self, parser, namespace, values, option_string):
        print('nice65 version', metadata.version("nice65"), file=sys.stderr)
        parser.exit()


def fix(grammar, infile, outfile, modify_in_place, colonless_labels, lowercase_mnemonics):
    if infile == "-":
        content = sys.stdin.read()
    else:
        with open(infile, "r") as fobj:
            content = fobj.read()
            options_match = re.findall(r'^[ \t]*;\s*nice65:([^\n]+)$', content, re.MULTILINE)
            if options_match:
                options_str = options_match[0].lower().replace(',', ' ')
                options = set(filter(None, map(str.strip, options_str.split(' '))))
                if 'ignore' in options:
                    print("Ignoring", infile)
                    return

    tree = grammar.parse(content)

    if modify_in_place:
        outfile = open(infile, "w")
    elif outfile == "-":
        outfile = sys.stdout
    else:
        outfile = open(outfile, "w")

    for line in tree.children:
        string = ""
        for i, child in enumerate(line.children):
            if child.data == "linenum":
                number = child.children[0].strip()
                string += number + " "
            elif child.data == "comment":
                is_tail = bool(len(string))
                if is_tail:
                    sentence = next(iter([x for x in child.children if x.type == "COMMENT_TEXT"]), "").strip()
                    s_len = len(string)
                    if '\n' in string:
                        s_len = s_len - string.rfind('\n') - 1
                    padding = (24 - s_len) if i > 0 else 0
                    string += " " * padding + ("; " + sentence).strip()
                else:
                    sentence = next(iter([x for x in child.children if x.type == "COMMENT_TEXT"]), "").strip()
                    indent = str(next(iter([x for x in child.children if x.type == "INDENT"]), ""))
                    if indent:
                        padding = ' ' * 8
                    else:
                        padding = ''
                    string += padding + '; ' + sentence
            elif child.data == "labeldef":
                if child.children:
                    # Named label definition
                    label = child.children[0].strip()
                else:
                    # Unnamed label
                    label = ''

                if label.startswith("@") or not label:
                    padding = " " * 4
                else:
                    padding = ""
                string += padding + label + ":"
            elif child.data == "statement":
                pad_count = 8 - len(string)
                if pad_count > 0:
                    padding = " " * pad_count
                else:
                    padding = "\n" + " " * 8

                statement = child.children[0]

                if statement.data == "directive":
                    name = statement.children[0].strip()
                    string += (
                        (padding if name not in CA65_DIRECTIVES else '')
                        + "."
                        + name.lower()
                        + " "
                        + " ".join(statement.children[1:])
                    )
                elif statement.data == "macro_start":
                    name = statement.children[0].strip()
                    string += ".macro ".ljust(8, ' ') + name + " " + ", ".join(map(str.strip, statement.children[1:]))
                elif statement.data == "macro_end":
                    string += ".endmacro"
                elif statement.data == "asm_statement":
                    mnemonic = statement.children[0]
                    string += padding + (
                        (mnemonic.lower() if lowercase_mnemonics else mnemonic.upper())
                        if mnemonic.lower() in instructions
                        else mnemonic
                    )
                    operands = statement.children[1:]
                    if operands:
                        args = []
                        for operand in operands:
                            args.append(flatten_expr(operand))
                        string += " " + ", ".join(args)
                else:
                    raise NotImplementedError("Unknown statement type: " + child.children[0].data)
            elif child.data == "numeric_var":
                name, cmd = child.children
                string = name.strip().ljust(8, ' ') + '.' + ' '.join(map(str.strip, cmd.children))
            elif child.data == "constant_def":
                name, assign, value = child.children
                string += name.strip() + " " + assign.strip() + " " + value.strip()
            else:
                raise NotImplementedError("Unknown child in line: " + child.data)

        print(string.rstrip(), file=outfile)

    outfile.close()

def flatten_expr(operand):
    parts = []
    if isinstance(operand, Token):
        if operand.type == "OP":
            if operand.value == ",":
                string = ", "
            else:
                string = f" {operand} "
        else:
            string = str(operand)
        if operand.type == 'REGISTER':
            string = string.upper()
        parts.append(string)
    else:
        for child in operand.children:
            parts.extend(flatten_expr(child))
    return "".join(parts)

if __name__ == "__main__":
    main()
