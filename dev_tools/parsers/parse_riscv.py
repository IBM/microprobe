#!/usr/bin/env python
# Copyright 2011-2021 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
docstring
"""

# imports
from __future__ import absolute_import
from __future__ import print_function
import argparse
import os
import tempfile
import sys
import re
from functools import reduce


class repos:
    def __init__(self):
        self.urls = {
            "riscv-opcodes": "https://github.com/riscv/riscv-opcodes",
            "rv8": "https://github.com/rv8-io/rv8"}

    def clone(self, url, branch, loc, args):
        os.system("git clone {} {} -b {} {}".format(
            args, self.urls[url], branch, loc))


class hashable:
    def __init__(self):
        raise NotImplementedError

    def __getitem__(self, k):
        return self.data[k]

    def __setitem__(self, k, v):
        self.data[k] = v

    def emit(self, *args):
        raise NotImplementedError


class regex(hashable):
    def __init__(self):
        self.data = {
            "num": "(0x[a-fA-F\d]+|\d+|ignore)",
            "name": "[\w.]+",
            "args": "(rd|rs[123]|[bj]?imm(20|12(lo|hi)?)|shamt[w]|rm|aqrl)",
            "type": ".+?\s",
            "ext": "rv(32|64|128)[a-z]",
            "end": "[ \t\n\r\f\v$]"}
        self["opcode"] = "(\d+\.\.\d+={n}|\d+={n}|{a}={n})".format(
            n=self.data["num"], a=self["args"])
        self["instr"] = re.compile(
            "^({n})\s+(({a}\s+)+)?(({o}\s+)+)({t})\s+({e}{end}+)".format(
                n=self["name"],
                a=self["args"],
                o=self["opcode"],
                t=self["type"],
                e=self["ext"],
                end=self["end"]))


class codec(hashable):
    def __init__(self, raw, fmts):
        def replace(a, b, x):
            if not isinstance(b, list):
                b = [b, ]
            i = x.index(a)
            tmp = list(x)
            return tmp[:i] + b + tmp[(i + 1):]

        x = raw.split()
        self.data = {}
        self['codec'] = x[0].replace('\xc2\xb7', '-')
        self['fmt'] = x[1]
        self['args'] = x[2:]

        codec = self['codec']
        if codec in fmts:
            self['operands'] = fmts[codec]['operands']
            (base_fmt, variance, sub_fmt) = (codec, None, None)
        else:
            m = re.match("^(.+?)([-+])(.+)?$", self["codec"])
            (base_fmt, variance, sub_fmt) = (
                m.group(1), m.group(2), m.group(3))

            if base_fmt not in fmts:
                raise RuntimeError("Cannot match codec '{}' to a base format".
                                   format(base_fmt))

            m = re.match('-sh(\d+)', variance + sub_fmt)
            if base_fmt == 'i':
                self['operands'] = fmts[base_fmt]['operands']
                if m is not None and m.group(1) is not None:
                    shift_bits = int(m.group(1))
                    self['operands'] = ['{}_imm{}'.format(
                        base_fmt, 12 - shift_bits),
                        '{}_shamt{}'.format(
                        base_fmt, shift_bits)] + fmts[
                        base_fmt]['operands'][1:]
                elif variance == '+' and sub_fmt == 'lf':
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '+' and sub_fmt in ('o', 'l'):
                    pass
                elif variance == '-' and sub_fmt == 'csr':
                    self['operands'] = ['csr12'] + \
                        fmts[base_fmt]['operands'][1:]
                elif variance == '-' and sub_fmt == 'csr+i':
                    self['operands'] = ['csr12', 'zimm5'] + fmts[
                        base_fmt]['operands'][2:]
                else:
                    self['operands'] = ''
                    raise RuntimeError(
                        "[TODO] Not determining operands for codec '{}'".
                        format(codec))
            # Handle fences
            elif base_fmt == 'r':
                self['operands'] = fmts[base_fmt]['operands']
                if variance == '+' and sub_fmt == 'fr':
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '+' and sub_fmt == 'rf':
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                elif variance == '+' and sub_fmt == 'rff':
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                elif variance == '+' and sub_fmt == '3f':
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '-' and sub_fmt == 'm+3f':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '-' and sub_fmt == 'm+fr':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '-' and sub_fmt == 'm+rf':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                elif variance == '-' and sub_fmt == 'm+ff':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                elif variance == '-' and sub_fmt == 'm+3f':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                elif variance == '-' and (sub_fmt == 'a' or sub_fmt == 'l'):
                    self['operands'] = replace(
                        'funct2', ['aq', 'rl'], self['operands'])
                elif variance == '-' and sub_fmt == 'f':
                    self['operands'] = replace(
                        'funct5', 'imm4', self['operands'])
                    self['operands'] = replace(
                        'funct2', 'pred', self['operands'])
                    self['operands'] = replace('rs2', 'succ', self['operands'])
                elif variance == '+' and sub_fmt == 'sf':
                    pass
                else:
                    raise RuntimeError(
                        "[TODO] Not determining operands for codec '{}'".
                        format(codec))
            elif base_fmt == 'r4':
                self['operands'] = fmts[base_fmt]['operands']
                if variance == '-' and sub_fmt == 'm':
                    self['operands'] = replace(
                        'funct3', 'rm', self['operands'])
                    self['operands'] = replace('rs1', 'frs1', self['operands'])
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                    self['operands'] = replace('rs3', 'frs3', self['operands'])
                    self['operands'] = replace('rd', 'frd', self['operands'])
                else:
                    raise RuntimeError(
                        "[TODO] Not determining oeprands for codec '{}'".
                        format(codec))
            elif base_fmt == 'u':
                if variance == '+':
                    self['operands'] = fmts[base_fmt]['operands']
                else:
                    raise RuntimeError(
                        "[TODO] Not determining oeprands for codec '{}'".
                        format(codec))
            elif base_fmt == 's':
                self['operands'] = fmts[base_fmt]['operands']
                if variance == '+' and sub_fmt == 'f':
                    self['operands'] = replace('rs2', 'frs2', self['operands'])
                else:
                    raise RuntimeError(
                        "[TODO] Not determining oeprands for codec '{}'".
                        format(codec))
            elif base_fmt in ('cb', 'ci', 'ciw', 'cj',
                              'cl', 'cr', 'cs', 'css'):
                self['operands'] = ''
                print((
                    "[WARN] Skipping oeprand generation "
                    "for compressed codec '{}'". format(codec)))
            else:
                self['operands'] = ''
                raise RuntimeError(
                    "[TODO] Not determining oeprands for codec '{}'".
                    format(codec))

        f = re.split('([,()])', self['fmt'])
        asm = 'OPC '
        if ('rm' in f):
            f.remove('rm')
            f.remove(',')
            print(("[TODO #19] Will not emit 'rm' fields in"
                   " floating-point instruction for '{}'".
                   format(self['codec'])))
        if ('aqrl' in f):
            f.remove('aqrl')
            f.remove(',')
            print((
                "[TODO #20] Will not emit 'aqrl' fields "
                "in atomic instruction for '{}'". format(
                    self['codec'])))
        for a in f:
            if a == 'none':
                continue
            m = re.match(r'(imm|offset)', a)
            if m is None or self['operands'] is '':
                asm += a
            else:
                # b = m.group(1)
                i = [re.match(
                    '^(.*(imm|shamt).*)$',
                    r) is not None for r in self['args']].index(True)
                imm = self['args'][i]
                m = re.match('(\w+)(imm(\d*))', imm)
                if m is not None and m.group(1) is not None:
                    imm = m.group(2)
                asm += "{}_{}".format(base_fmt, imm)
            if a in (','):
                asm += ' '

        self['fmt'] = asm

    def emit(self, *args):

        fields = reduce(lambda a, b: a + b,
                        ['\n  - {}'.format(c) for c in self['operands']])

        if self['codec'] in ['none', 'r-f']:
            fields = fields.replace('rs1', 'rs1c').replace('rd', "rdc")

        yaml = """- Name: "{n}"
  Fields:{f}
  Assembly: {a}
""".format(
            n=self['codec'],
            f=fields,
            a=self['fmt'])

        if (self['codec'] + '2') in args[0][0]:
            yaml = yaml + """- Name: "{n}"
  Fields:{f}
  Assembly: {a}
""".format(n=self['codec'] + '2',
                f=reduce(lambda a,
                         b: a + b,
                         ['\n  - {}'.format(c)
                          for c in self['operands']]).replace('rs2',
                                                              'rs2c'),
                a=self['fmt'])

        return yaml


class fmt(hashable):
    def __init__(self, raw):
        m = re.match("(.+?)\s+(\".+?\")(\s+(.+))?$", raw)
        if m is None:
            raise RuntimeError("Failed to create class 'format' from '{}'".
                               format(raw))
        self.data = {}
        self['name'] = m.group(1)
        self['description'] = m.group(2)
        # Special case 'none' as having I-type types
        if self['name'] == 'none':
            x = '31:20[11:0]=imm 19:15=rs1 '\
                '14:12=funct3 11:7=rd 6:0=opcode'.split()
        else:
            x = m.group(4).split()
        self['operands'] = []
        while len(x) > 0:
            (bits, operand) = x[0].split('=')
            m = re.match("(\d+):?(\d+)?", bits)
            hi = int(m.group(1))
            lo = hi
            if m.group(2) is not None:
                lo = int(m.group(2))
            if "imm" in operand:
                operand = '{}_{}{}'.format(
                    self['name'], operand, str(hi - lo + 1))
            self['operands'].append(operand.replace("'", '-c'))
            x = x[1:]


class field(hashable):
    sizes = {
        'opcode': 7,
        'rd': 5,
        'rs1': 5,
        'rs2': 5,
        'rs3': 5,
        'frd': 5,
        'frs1': 5,
        'frs2': 5,
        'frs3': 5,
        'pred': 4,
        'succ': 4,
        'rm': 3,
        'aq': 1,
        'rl': 1,
        'rc1': 5,
        'rc2': 5,
        'rc3': 5,
    }

    def __init__(self, name):
        self.data = {
            'name': name,
            'description': name
        }
        if name in self.sizes:
            self['size'] = self.sizes[name]
        else:
            m = re.match('^.+?(\d+)$', name)
            if m is None:
                raise RuntimeError("Failed to construct field from '{}'".
                                   format(name))
            self['size'] = m.group(1)

        m = re.match('f?rs\d|(.*)_(imm|shamt).*|(pred|succ)', name)
        if m is not None:
            self['direction'] = 'I'
            self['show'] = True
        elif name in ('rd', 'frd'):
            self['direction'] = 'O'
            self['show'] = True
        else:
            self['direction'] = '?'
            self['show'] = False

        # Fixes
        if name in ['sb_imm7', 's_imm7']:
            self['description'] += " (extended to 12)"

        if name in ['sb_imm5', 's_imm5']:
            self['description'] += " (dummy)"

        if name in ['i_imm6', 'i_imm7', 'none_imm12']:
            self['direction'] = '?'
            self['show'] = False

        if name in ['rc1', 'rc2', 'rc3']:
            self['direction'] = 'IO'
            self['show'] = True

        if name in ['funct7']:
            self['direction'] = 'I'
            self['show'] = True

        def bitsToSize(bits):
            size = 0
            b = bits.split(',')
            enc = re.compile('(\d+)(:(\d+))?')
            while len(b) > 0:
                m = enc.match(b[0])
                hi = m.group(1)
                lo = m.group(3)
                if lo is not None:
                    size += int(hi) - int(lo) + 1
                else:
                    size += 1
                b = b[1:]
            return size

    def toOperand(self):
        n = self['name']

        # Fixes
        if n in ['sb_imm7']:
            return '@I_12'
        if n in ['s_imm7']:
            return 's.imm12'
        if n in ['sb_imm5', 's_imm5']:
            return 'Zero'

        m = re.match(r'(([\w\d]+)_)?((.*?)imm|shamt|funct)(\d+)', n)

        if m is not None:
            if m.group(3) in ('shamt'):
                return 'u.' + 'imm' + m.group(5)
            if m.group(2) in ('s', 'sb', 'i', 'uj'):
                return 's.' + 'imm' + m.group(5)
            if m.group(2) in ('u',):
                return 'u.' + 'imm' + m.group(5)
            print(("[WARN] Assuming operand '{}' is unsigned".format(n)))
            return (m.group(4) or '') + 'imm' + m.group(5)
        if n in ('opcode'):
            return 'u.imm7'
        if n in ('pred'):
            return 'pred'
        if n in ('succ'):
            return 'succ'
        if n in ('rm'):
            return 'u.' + 'imm' + '3'
        if n in ('aq', 'rl'):
            return 'u.' + 'imm' + '1'
        if n in ('rd', 'rs1', 'rs2', 'rs3'):
            return 'reg'
        if n in ('frd', 'frs1', 'frs2', 'frs3'):
            return 'freg'
        if n in ('rc1', 'rc2', 'rc3'):
            return 'reg'

        raise RuntimeError("No known operand for field '{}'".format(n))

    def emit(self, *dummy_args):
        yaml = """- Name: "{n}"
  Size: {s}
  Description: "{d}"
  Show: {show}
  IO: "{io}"
  Operand: "{o}"
""".format(
            n=self['name'],
            s=self['size'],
            d=self['description'],
            show=self['show'],
            io=self['direction'],
            o=self.toOperand())

        if self['name'] in ['rs2', 'rs1', 'rd']:
            yaml = yaml + """- Name: "{n}c"
  Size: {s}
  Description: "{d}"
  Show: False
  IO: "?"
""".format(
                n=self['name'],
                s=self['size'],
                d=self['description'])

        return yaml


class register(hashable):
    def __init__(self, raw):
        m = re.match(r'^(.+?)\s+(.+?)\s+(.+?)\s+(.+?)\s+(.+?)$', raw)
        if m is None:
            raise RuntimeError("Failed to construct 'operand' from '{}'".
                               format(raw))
        self.data = {}
        self['name'] = m.group(1).upper()
        self['altname'] = m.group(2)
        self['type'] = m.group(3)
        self['save'] = m.group(4)
        self['description'] = m.group(5)


class operand(hashable):
    def __init__(self, name):
        self.data = {}
        self['name'] = name
        self['altname'] = name
        m = re.match('((\w*?)|(\w*?).)imm(\d+)', name)
        if name is 'reg':
            self['signed'] = None
            self['size'] = 32
            self['type'] = 'ireg'
        elif name is 'freg':
            self['signed'] = None
            self['size'] = 32
            self['type'] = 'freg'
        elif name is 'allreg':
            self['signed'] = None
            self['size'] = 32
            self['type'] = 'allreg'
        elif name in ('imm20'):
            self['signed'] = None
            self['size'] = int(m.group(4))
            self['type'] = "immediate"
        elif m is not None:
            self['type'] = "immediate"
            self['size'] = int(m.group(4))
            if m.group(2) is not None:
                s = False
            elif m.group(3) is not None:
                s = m.group(3) == 's'
            self['signed'] = s
        elif name in ('@I_12'):
            self['signed'] = None
            self['size'] = 12
            self['type'] = 'relative'
            self['shift'] = 1
        elif name in ('Zero'):
            self['type'] = 'zero'
        elif name in ('pred', 'succ'):
            self['type'] = "immediate"
            self['size'] = 4
            self['signed'] = False
            self['except'] = 0
        elif name in ('@sb_imm7'):
            self['signed'] = None
            self['size'] = 7
            self['type'] = 'relative'
            self['shift'] = 0
        elif name in ('@uj_imm20'):
            self['signed'] = None
            self['size'] = 20
            self['type'] = 'relative'
            self['shift'] = 0
        else:
            raise RuntimeError('No known operand with name "{}"'.format(name))

    def emit(self, *args):
        registers = args[0][0]
        yaml = ''
        if self['type'] in ('ireg', 'freg', 'allreg'):
            (n, d) = ('reg', 'Integer Registers')
            if self['type'] == 'freg':
                (n, d) = ('freg', 'Floating Point Registers')
            if self['type'] == 'allreg':
                (n, d) = ('allreg', 'All Registers')

            yaml = """- Name: {0}
  Description: {1}
  Registers:
""".format(n, d)

            for v in sorted(list(registers.values()),
                            key=lambda x: int(x['name'][1:])):
                if v['type'] == self['type'] or self['type'] == 'allreg':
                    yaml += "    {0} : ['{0}']\n".format(v['name'])

            if self['type'] == 'ireg':
                yaml = yaml + yaml.replace(
                    ': reg',
                    ': rega').replace(
                    "er Registers",
                    "er Register (address base)").replace(
                    "x0 : ['x0']\n    ",
                    ""
                ) + "  AddressBase: True\n"

        elif self['type'] is 'immediate':
            yaml = """- Name: {n}
  Description: {d}
  Min: {minimum}
  Max: {maximum}
""".format(
                n=self['name'],
                d="{}{}-bit immediate".format(
                    "signed " if self['signed'] else "",
                    self['size']),
                minimum=-
                (
                    1 << (
                        self['size'] -
                        1)) if self['signed'] else 0,
                maximum=(
                    1 << (
                        self['size'] -
                        1)) -
                1 if self['signed'] else (
                    1 << (
                        self['size'])) -
                1)

            if 'except' in self.data:
                yaml += "  Except:\n    - {}\n".format(self['except'])

        elif self['type'] is 'relative':

            yaml = """- Name: "{n}"
  Description: "{d}"
  Relative: True
  MinDisplacement: {minimum}
  MaxDisplacement: {maximum}
  Shift: {s}
""".format(
                n=self['name'],
                d="Relative displacement (bit size {})".format(self['size']),
                minimum=- (2 ** (self['size'] - 1)),
                maximum=(2 ** (self['size'] - 1)) - 1,
                s=self['shift']
            )
        elif self['type'] is 'zero':
            yaml = """- Name: Zero
  Description: Zero operand (special, not shown)
  Value: 0
"""
        else:
            raise NotImplementedError(
                "'emit' is unimplemented for operand type '{}'". format(
                    self['type']))
        return yaml


class instruction(hashable):
    def __init__(self, raw):
        self.data = {}

        def car(x): return x[0]

        def cdr(x): return x[1:]

        def parse_args(x):
            y = car(x)
            if "=" in y:
                return [x]
            return [y] + parse_args(cdr(x))

        def parse_opcodes(x):
            y = car(x)
            m = re.match(
                '(\d+)(..(\d+))?=(\d+|ignore)|(pred|succ|aq|rl|rs1|rm)', y)
            if m is None:
                return [x]
            return [y] + parse_opcodes(cdr(x))

        def parse_codecs(x):
            y = car(x)
            if "rv" in y:
                return [x]
            return [y] + parse_codecs(cdr(x))

        def atoi(x):
            return int(x, 16 if "0x" in x else 10)

        def gen_bits(match, mask, x):
            if len(x) == 0:
                return (match, mask)

            if car(x) in ('pred', 'succ', 'aq', 'rl', 'rs1', 'rm'):
                return gen_bits(match, mask, cdr(x))

            (bits, val) = car(x).split('=')

            # For codegen, 'ignore' means emit zeros
            if val == "ignore":
                val = '0'

            try:
                (hi, lo) = [atoi(a) for a in bits.split('..')]
            except ValueError:
                mask |= 1 << atoi(bits)
                match |= atoi(val) << atoi(bits)
            else:
                mask |= ~((~0) << (hi - lo + 1)) << lo
                match |= atoi(val) << lo

            return gen_bits(match, mask, cdr(x))

        self['raw'] = raw
        s = raw.split()
        (self['name'], t) = (car(s), parse_args(cdr(s)))
        (self['args'], t) = (t[0:-1], parse_opcodes(t[-1]))
        (self['opcodes'], t) = (t[0:-1], parse_codecs(t[-1]))
        (self['codecs'], self['isas']) = (t[0:-1], t[-1])

        self['codecs'] = [a.replace(
            '\xc2\xb7',
            '-') for a in self['codecs']]

        # Check that the parsing didn't fail
        if len(self['codecs']) is not 1:
            raise RuntimeError(
                "Found more than one codec, '{}', when parsing:\n'{}'". format(
                    self['codecs'], raw))

        (self['match'], self['mask']) = gen_bits(0, 0, self['opcodes'])

        self['description'] = descriptions.get(self['name'])

    def __extract(self, hi, lo, value):
        return (value & ~((~0 << (hi - lo + 1)) << lo)) >> lo

    def emit(self, *args):
        c = args[0][0]
        # o = args[0][1]
        f = args[0][2]

        bits = 32
        self['ops'] = []
        update_format = False
        for op in c[self['codecs'][0]]['operands']:
            size = int(f[op]['size'])
            (hi, lo) = (bits - 1, bits - size)
            mask = self.__extract(hi, lo, self['mask'])
            match = self.__extract(hi, lo, self['match'])

            if mask != 0 and op != 'opcode':
                if op == 'rs2':
                    self['ops'].append([op + 'c', match, '?'])
                    update_format = True
                else:
                    self['ops'].append([op, match, '?'])
            elif op == 'rm' and self['name'] in ['fcvt.d.s',
                                                 'fcvt.d.wu',
                                                 'fcvt.d.w']:
                # This never round
                self['ops'].append([op, '0', '?'])
            elif op == 'rm':  # Always set to dynamic rounding mode
                self['ops'].append([op, '7', '?'])
            elif op in ['aq', 'rl']:  # Always aq/rl to zero (need fix)
                self['ops'].append([op, '0', '?'])
            bits -= size

        memops = ""
        if "pc_offset = imm" in self['pcode']:

            if "sbimm12" in self['args']:
                of = 'sb_imm7'
            if "jimm20" in self['args']:
                of = 'uj_imm20'

            memops = """\n  MemoryOperands:
    MEM1 : [['{}'], [0], 0, 'B']""".format(of)
            self['ops'].append([of, "@" + of, 'I'])

        if "pc_offset = new_offset" in self['pcode']:
            memops = """\n  MemoryOperands:
    MEM1 : [['i_imm12', 'rs1'], [0], 0, 'B']"""
            self['ops'].append(['rs1', "rega", 'I'])

        if "mmu." in self['pcode']:

            x = re.match("^.*mmu\.(.*)<[suf](.*.)>\((.*.), .*$",
                         self['pcode'])

            (ls, size, form) = (x.group(1), x.group(2), x.group(3))

            size = int(size) / 8

            if ls == 'load':
                direction = 'I'
            elif ls == 'store':
                direction = 'O'
            elif ls == 'amo':
                direction = 'IO'

            form = form.replace("imm", "i_imm12")

            form = [elem for elem in form.strip().replace(' ', '').replace(
                ',', '+').split('+') if elem in ['rs1', 'imm']]

            memops = """\n  MemoryOperands:
    MEM1 : [{}, [{}], 8, '{}']""".format(
                form, size, direction
            )

            for elem in form:
                if elem in ['rs1']:
                    self['ops'].append([elem, 'rega', 'I'])

        mops = ""
        if len(self['ops']) > 0:
            mops = "\n  Operands:{ops}".format(
                ops=reduce(
                    lambda a, b: a + b, [
                        "\n    {0}: ['{1}', '{0}', '{2}']".format(
                            x[0], x[1], x[2]) for x in self['ops']]))

        format_str = self['codecs'][0]
        if update_format:
            format_str = self['codecs'][0] + '2'
        self['dformat'] = format_str

        yaml = """- Name: "{n}_V0"
  Mnemonic: "{n}"
  Opcode: "{o:x}"
  Description: "{d}"
  Format: "{f}"{ops}{mops}
""".format(
            n=self['name'].upper(),
            o=self.__extract(6, 0, self['match']),
            f=format_str,
            raw=self['raw'],
            d=self['description'],
            ops=mops,
            mops=memops)

        if format_str in ['none', 'r-f']:
            yaml = yaml.replace('rs1', 'rs1c').replace('rd', 'rdc')

        return yaml

    def isIsa(self, isaString):
        x = re.match("(rv(?:32|64|128))([a-z]+)", isaString)
        (base, extension) = (x.group(1), x.group(2))
        return reduce(lambda a, b: a or b,
                      [(base + e) in self['isas'] for e in extension])


def parse_arguments():
    def isaString(x):
        if re.match(r"rv(32|64|128)([a-z]+)", x) is None:
            raise argparse.ArgumentTypeError("Invalid ISA string")
        return x

    parser = argparse.ArgumentParser(
        description='Converts RV8 to Microprobe YAML formats',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '--branch', default='master',
        help="Branch/commit of repository to use")
    parser.add_argument(
        '--tmp-dir',
        help='Explicit temporary directory to use')
    parser.add_argument(
        '--no-cleanup', action='store_true',
        help='Do not cleanup the temporary directory')
    parser.add_argument(
        '-v', '--verbose', dest='v', action='store_true',
        help='Print verbose information about execution')
    parser.add_argument(
        '--march', type=isaString, default='rv64imafd',
        help='RISC-V base ISA and extensions to support')
    parser.add_argument(
        '--output-dir', required=True,
        help='Output directory to write *.yaml files')
    return parser.parse_args()


descriptions = {}


def parse_riscv_descriptions(file_fullnames, file_descriptions):
    with open(file_fullnames, 'r') as fid:
        for line in fid:
            if re.match("^#|^\s+$", line):
                continue
            x = re.split("\s+(?=\")", line.strip())
            x[1] = x[1].replace("\"", "")
            descriptions[x[0]] = x[1]
    with open(file_descriptions, 'r') as fid:
        lines = []
        for line in fid:
            lines.append(line)
            print(line)

        lines.append('custom0       "Custom instruction 0"')
        lines.append('custom1       "Custom instruction 1"')
        lines.append('custom2       "Custom instruction 2"')
        lines.append('custom3       "Custom instruction 3"')

        for line in lines:
            if re.match("^#|^\s+$", line):
                continue
            x = re.split("\s+(?=\")", line.strip())
            x[1] = x[1].replace("\"", "")
            if descriptions.get(x[0]) is not None:
                descriptions[x[0]] += ": " + x[1]
            else:
                descriptions[x[0]] = x[1]


def parse_riscv_codecs(file_codecs, fmts):
    codecs = {}
    with open(file_codecs, 'r') as fid:
        skip = re.compile("^(#.*|\s+)$")

        lines = []
        for line in fid:
            lines.append(line)

        lines.append("custom          rc1,rc2,rc3,funct7"
                     "             rc1 rc2 rc3 funct7")

        for line in lines:
            if skip.match(line):
                continue
            c = codec(line, fmts)
            codecs[c["codec"]] = c

    return codecs


def parse_riscv_fmts(file_fmts):
    fmts = {}
    with open(file_fmts, 'r') as fid:
        skip = re.compile("^(#.*|\s+|^\d.*)$")

        lines = []
        for line in fid:
            lines.append(line)

        lines.append(
            'custom    "custom"             '
            '31:25=funct7 24:20=rc3 '
            '19:15=rc2 14:12=funct3 11:7=rc1'
            '           6:0=opcode'
        )

        for line in lines:
            if skip.match(line):
                continue
            f = fmt(line)
            fmts[f["name"]] = f
    return fmts


def parse_riscv_pcode(file_pcode):
    pcodes = {}
    with open(file_pcode, 'r') as fid:
        skip = re.compile("^(#.*|\s+|^\d.*)$")

        lines = []
        for line in fid:
            lines.append(line)

        lines.append("custom0        \"Custom 0\"")
        lines.append("custom1        \"Custom 1\"")
        lines.append("custom2        \"Custom 2\"")
        lines.append("custom3        \"Custom 3\"")

        for line in lines:

            if skip.match(line):
                continue
            sline = line.strip().split('"')
            assert len(sline) in [1, 3], sline
            sline.append("")
            pcodes[sline[0].strip()] = sline[1].strip()
    return pcodes


def parse_riscv_fields(file_fields):
    fields = {}
    with open(file_fields, 'r') as fid:
        for line in fid:
            if re.match("^#|^\s+$", line):
                continue
            x = field(line)
            fields[x['name']] = x

    return fields


def gen_riscv_fields(f):
    fields = {}
    for g in f:
        x = field(g)
        fields[x['name']] = x
    return fields


def parse_riscv_registers(file_registers):
    registers = {}
    with open(file_registers, 'r') as fid:
        for line in fid:
            if re.match('^#|^\s+$', line):
                continue
            x = register(line)
            registers[x['name']] = x

    return registers


def p(x): print(x)


def parse_riscv_opcodes(file_opcodes, state, pcodes):
    insns = {}
    with open(file_opcodes, 'r') as fid:
        lines = []

        for line in fid:
            lines.append(line)

        lines.append("custom0        rc1 rc2 rc3 funct7      "
                     "14..12=7 6..2=0x02"
                     " 1..0=3            custom     rv32i rv64i rv128i")
        lines.append("custom1        rc1 rc2 rc3 funct7       "
                     "14..12=7 6..2=0x0A"
                     " 1..0=3            custom     rv32i rv64i rv128i")
        lines.append("custom2        rc1 rc2 rc3 funct7      "
                     "14..12=7 6..2=0x16"
                     " 1..0=3            custom     rv32i rv64i rv128i")
        lines.append("custom3        rc1 rc2 rc3 funct7      "
                     "14..12=7 6..2=0x1E"
                     " 1..0=3            custom     rv32i rv64i rv128i")

        for line in lines:

            if re.match("^#|^\s+$", line):
                continue
            i = instruction(line)
            if i.isIsa(state["isa"]):
                insns[i["name"]] = i
                insns[i["name"]]['pcode'] = pcodes[i["name"]]

    (codecs, fields) = ([], [])
    for (dummy_k, v) in insns.items():
        codecs.append(v['codecs'][0])
        fields.append(v['args'])

    return (insns, set(codecs), set(reduce(lambda a, b: a + b, fields)))


def main():
    a = parse_arguments()
    u = repos()
    state = {"isa": a.march}

    if state["isa"] == "rv64g":
        state["isa"] = "rv64imafd"

    def printInfo(s):
        if a.v:
            sys.stderr.write("[INFO] " + s + "\n")

    def printError(s):
        sys.stderr.write("[ERROR] " + s + "\n")

    repo = "rv8"
    dirs = {"tmp": a.tmp_dir if a.tmp_dir else tempfile.mkdtemp()}
    dirs[repo] = "{}/{}:{}".format(dirs["tmp"], repo, a.branch)

    if not os.path.exists(dirs[repo]):
        u.clone(repo, a.branch, dirs[repo], "--depth=1")

    parse_riscv_descriptions(dirs[repo] + "/meta/opcode-fullnames",
                             dirs[repo] + "/meta/opcode-descriptions")

    pcodes = parse_riscv_pcode(dirs[repo] + "/meta/opcode-pseudocode-c")

    (insns, c, f) = parse_riscv_opcodes(dirs[repo] + '/meta/opcodes',
                                        state,
                                        pcodes)

    # Modify all of these so that only what is required is emitted
    fmts = parse_riscv_fmts(dirs[repo] + "/meta/types")

    codecs = {
        k: v for k,
        v in parse_riscv_codecs(
            dirs[repo] +
            "/meta/codecs",
            fmts). items() if k in c}

    for k, v in codecs.items():
        f |= set(v['operands'])
    fields = gen_riscv_fields(f)
    registers = {
        k.upper(): v for k,
        v in parse_riscv_registers(
            dirs[repo] +
            "/meta/registers"). items()}

    operands = {v.toOperand(): operand(v.toOperand())
                for k, v in fields.items()}

    # Manual hack
    operands['@sb_imm7'] = operand('@sb_imm7')
    operands['@uj_imm20'] = operand('@uj_imm20')

    def write(f, x, *args):
        with open(f, 'w') as fid:
            for y in sorted(x):
                fid.write(x[y].emit(args))

    def write_property(ffile, name, dscr, default, values):
        with open(ffile, 'w') as fid:
            fid.write('---\n')
            fid.write('- Name: {}\n'.format(name))
            fid.write('  Description: {}\n'.format(dscr))
            fid.write('  Default: {}\n'.format(default))
            if len(values) > 0:
                fid.write('  Values:\n')

                for y in sorted(values):
                    fid.write("    {}: {}\n".format(y, values[y]))

    def _get_name(elem):
        return re.match('.*Name: "(.*)".*',
                        elem.emit([codecs, operands, fields])).groups(1)[0]

    def _check_exp(elem, exp):

        for ex1 in exp:
            m = re.match(ex1, elem.emit(
                [codecs, operands, fields]).replace("\n", " "))
            if m:
                return True

        return False

    try:

        write('{}/instruction.yaml'.format(a.output_dir),
              insns, codecs, operands, fields)
        write('{}/instruction_format.yaml'.format(a.output_dir), codecs,
              [ins.data['dformat'] for ins in insns.values()])
        write('{}/instruction_field.yaml'.format(a.output_dir), fields)

        write('{}/operand.yaml'.format(a.output_dir), operands, registers)

        prop_branch = {_get_name(k): True
                       for k in insns.values()
                       if _check_exp(k,
                                     [".*Branch.*",
                                      ".*Jump.*"])}

        prop_branchrel = {_get_name(k): True
                          for k in insns.values()
                          if _check_exp(k,
                                        [".*Branch to PC relative.*",
                                         ".*Jump to the PC plus.*"])}

        prop_branchcond = {_get_name(k): True
                           for k in insns.values()
                           if _check_exp(k,
                                         [".*Branch .* if .*"])}

        prop_disableasm = {}
        prop_memory = {_get_name(k): True
                       for k in insns.values()
                       if _check_exp(k,
                                     [".*MEM1.*"])}
        prop_memory_update = {}
        prop_priv = {}
        prop_unsup = {}

        properties = []
        properties.append((
            'branch.yaml',
            'branch',
            'Boolean indicating if the instruction is a branch',
            False,
            prop_branch))
        properties.append((
            'branch_relative.yaml',
            'branch_relative',
            'Boolean indicating if the instruction is '
            'a relative branch',
            False,
            prop_branchrel))
        properties.append((
            'branch_conditional.yaml',
            'branch_conditional',
            'Boolean indicating if the instruction is '
            'a branch confitional',
            False,
            prop_branchcond))
        properties.append((
            'disable_asm.yaml',
            'disable_asm',
            'Boolean indicating if ASM generation is disabled'
            ' for the instruction. If so, binary codification is used',
            False,
            prop_disableasm))
        properties.append((
            'memory.yaml',
            'access_storage',
            'Boolean indicating if the instruction has '
            'storage operands',
            False,
            prop_memory))
        properties.append((
            'memory_with_update.yaml',
            'access_storage_with_update',
            'Boolean indicating if the '
            'instruction accesses to storage and updates the source register'
            ' with the generated address',
            False,
            prop_memory_update))
        properties.append((
            'priviledged.yaml',
            'priviledged',
            'Boolean indicating if the instruction is privileged',
            False,
            prop_priv))
        properties.append((
            'unsupported.yaml',
            'unsupported',
            'Boolean indicating if the instruction is unsupported',
            False,
            prop_unsup))

        for fname, name, dscr, default, valuedict in properties:
            write_property(
                '{}/instruction.props/{}'.format(a.output_dir, fname),
                name, dscr, default, valuedict)

    except IOError as exc:
        printError('{}'.format(exc))
        printError('Check if directory exists or'
                   ' if you have write permissions.')
        exit(-1)

    if not a.no_cleanup:
        printInfo("Deleting temporary directory {}".format(dirs["tmp"]))
        os.system("rm -rf {}".format(dirs["tmp"]))


if __name__ == "__main__":
    main()
