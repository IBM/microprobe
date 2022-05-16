# Copyright EDT IBM Corporation
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
# Built-in modules
import datetime
import unicodedata
import xml.etree.ElementTree as ET

xmlFile = 'x86reference.xml'
instrFile = 'instruction.yaml'
formtFile = 'instruction_format.yaml'


def translate(word):
    if word == 'E':
        return ['r', 'm']
    if word == 'G':
        return ['r']
    if word == 'I':
        return ['imm']
    if word == 'V':
        return ['xmm']
    if word == 'A':
        return ['immptr']
    if word == 'C':
        return ['cntlr']
    if word == 'D':
        return ['dbgr']
    if word == 'N':
        return ['mm']
    if word == 'H':
        return ['r']
    if word == 'J':
        return ['immoffs']
    if word == 'M':
        return ['m']
    if word == 'O':
        return ['immoffs']
    if word == 'Q':
        return ['mm', 'm']
    if word == 'P':
        return ['mm']
    if word == 'S':
        return ['segr']
    if word == 'R':
        return ['r']
    if word == 'U':
        return ['xmm']
    if word == 'W':
        return ['xmm', 'm']
    if word == 'Z':
        return ['r']
    if word == 'ES':
        return ['str', 'm']
    if word == 'T':
        return ['testr']
    if word == 'rAX':
        return ['AX', 'EAX', 'RAX']
    if word == 'b':
        return [8]
    if word == 'vqp':
        return [16, 32, 64]
    if word == 'vds':
        return [16, 32]
    if word == 'vq':
        return [16, 64]
    if word == 'vs':
        return [16, 32]
    if word == 'er':
        return [80]
    if word == 'ptp':
        return [32, 48, 80]
    if word == 'ps':
        return [128]
    if word == 'psq':
        return [64]
    if word == 'dqp':
        return [32, 64]
    if word == 'pd':
        return [128]
    if word == 'pi':
        return [64]
    if word == 'di':
        return [32]
    if word == 'bss':
        return [8]
    if word == 'wi':
        return [16]
    if word == 'bs':
        return [8]
    if word == 'dr':
        return [64]
    if word == 'dq':
        return [128]
    if word == 'qp':
        return [64]
    if word == 'e':
        return [14, 28]
    if word == 'd':
        return [32]
    if word == 'bcd':
        return [80]
    if word == 'sr':
        return [32]
    if word == 'st':
        return [94, 108]
    if word == 'q':
        return [64]
    if word == 'p':
        return [32, 48]
    if word == 's':
        return [48, 80]
    if word == 'dq':
        return [128]
    if word == 'dq ':
        return [128]
    if word == 'w':
        return [16]
    if word == 'v':
        return [16, 32]
    if word == 'qi':
        return [64]
    if word == 'stx':
        return [512]
    unknowns.add(word)
    return [word]


def rexEligible(word):
    if word == 'vqp':
        return True
    if word == 'dqp':
        return True
    if word == 'ptp':
        return True
    if word == 'qp':
        return True
    return False


def write_2op_instruction(opc, oext, mnem, note, rexAble, opEn, type1, size1,
                          dst1, type2, size2, dst2):
    # if mnem == 'MOVUPS': print 'opc ' + repr(opc) + ' oext ' + repr(oext) +
    # ' mnem ' + repr(mnem) + ' rexAble ' + repr(rexAble) + ' opEn ' +
    # repr(opEn) + ' type1 ' + repr(type1) + ' size1 ' + repr(size1) + ' type2
    # ' + repr(type2) + ' size2 ' + repr(size2)
    formatname = 'O8'
    if len(opc) == 4:
        formatname = 'O16'
    if oext != '':
        return  # TODO
    rex = rexAble and (size1 >= 64 or size2 >= 64)
    if rex:
        formatname = 'REX' + formatname
    formatname += opEn
    if opEn == 'RM':
        if type2 == 'm':
            formatname += 'M'
        else:
            formatname += 'R'
    elif opEn == 'MR':
        if type1 == 'm':
            formatname += 'M'
        else:
            formatname += 'R'
    else:
        return  # TODO
    if formatname not in formats:
        formats.add(formatname)
        fmtFile.write('- Name: "' + formatname + '"\n')
        fmtFile.write('  Fields:\n')
        if rex:
            fmtFile.write('  - REX_header\n')
            fmtFile.write('  - REX_W\n')
            fmtFile.write('  - REX_R\n')
            fmtFile.write('  - REX_X\n')
            fmtFile.write('  - REX_B\n')
        if len(opc) == 4:
            fmtFile.write('  - opcode_16\n')
        else:
            fmtFile.write('  - opcode_8\n')
        fmtFile.write('  - ModRM_Mod\n')
        fmtFile.write('  - ModRM_RegOpc\n')
        fmtFile.write('  - ModRM_RM\n')
        fmtFile.write('  Assembly: OPC')
        if opEn == 'RM':
            if type2 == 'm':
                fmtFile.write(' (ModRM_RM),')
            elif type2 == 'r':
                fmtFile.write(' ModRM_RM,')
            fmtFile.write(' ModRM_RegOpc\n')
        elif opEn == 'MR':
            fmtFile.write(' ModRM_RegOpc,')
            if type1 == 'm':
                fmtFile.write(' (ModRM_RM)\n')
            else:
                fmtFile.write(' ModRM_RM\n')
        else:
            return  # TODO
    if mnem not in counters:
        counters[mnem] = 0
    insFile.write('- Name: "' + mnem + '_V' + repr(counters[mnem]) + '"\n')
    counters[mnem] += 1
    insFile.write('  Mnemonic: "' + mnem + '"\n')
    insFile.write('  Opcode: "' + opc + '"\n')
    insFile.write('  Description: "' + note + '"\n')
    insFile.write('  Format: "' + formatname + '"\n')
    insFile.write('  Operands:\n')
    if rex:
        insFile.write(
            '    REX_W :        [     \'1\',       \'REX_W\', \'?\' ]\n')
        insFile.write(
            '    REX_X :        [     \'0\',       \'REX_X\', \'?\' ]\n')
    insFile.write('    ModRM_Mod :    [     \'3\',   \'ModRM_Mod\', \'?\' ]\n')
    insFile.write('    ModRM_RegOpc : [  \'')
    if opEn == 'RM':
        if type1 == 'r':
            insFile.write('R_' + repr(size1))
        elif type1 == 'xmm':
            insFile.write('XMM')
        elif type1 == 'mm':
            insFile.write('MM')
        else:
            print('opc ' + repr(opc) + ' oext ' + repr(oext) + ' mnem ' + repr(
                mnem) + ' rexAble ' + repr(rexAble) + ' opEn ' + repr(
                    opEn) + ' type1 ' + repr(type1) + ' size1 ' + repr(
                        size1) + ' type2 ' + repr(type2) + ' size2 ' + repr(
                            size2))
            return
        if rex and size1 >= 64 and type1 != 'mm':
            insFile.write('_REX')
        insFile.write('\',\'ModRM_RegOpc\',')
        if dst1:
            insFile.write('\'IO\' ]\n')
        else:
            insFile.write(' \'I\' ]\n')
        insFile.write('    ModRM_RM :     [')
        if type2 == 'r':
            insFile.write('  \'R_' + repr(size2))
        elif type2 == 'm':
            insFile.write('\'ABR_64')
        elif type2 == 'xmm':
            insFile.write('\'XMM')
        elif type2 == 'mm':
            insFile.write('\'MM')
        else:
            print('opc ' + repr(opc) + ' oext ' + repr(oext) + ' mnem ' + repr(
                mnem) + ' rexAble ' + repr(rexAble) + ' opEn ' + repr(
                    opEn) + ' type1 ' + repr(type1) + ' size1 ' + repr(
                        size1) + ' type2 ' + repr(type2) + ' size2 ' + repr(
                            size2))
            return
        if rex and size2 >= 64 and type2 != 'mm':
            insFile.write('_REX')
        insFile.write('\',    \'ModRM_RM\',')
        if dst2:
            insFile.write('\'IO\' ]\n')
        else:
            insFile.write(' \'I\' ]\n')
        if type2 == 'm':
            insFile.write(
                '  MemoryOperands:\n    MEM1 :         [ [\'ModRM_RM\'], [' +
                repr(size2 / 8) + '], ' + repr(size2 / 8) + ',')
            if dst2:
                insFile.write('\'IO\' ]\n')
            else:
                insFile.write(' \'I\' ]\n')
    elif opEn == 'MR':
        if type2 == 'r':
            insFile.write('R_' + repr(size2))
        elif type2 == 'xmm':
            insFile.write('XMM')
        elif type2 == 'mm':
            insFile.write('MM')
        else:
            print('opc ' + repr(opc) + ' oext ' + repr(oext) + ' mnem ' + repr(
                mnem) + ' rexAble ' + repr(rexAble) + ' opEn ' + repr(
                    opEn) + ' type1 ' + repr(type1) + ' size1 ' + repr(
                        size1) + ' type2 ' + repr(type2) + ' size2 ' + repr(
                            size2))
            return
        if rex and size2 >= 64 and type2 != 'mm':
            insFile.write('_REX')
        insFile.write('\',\'ModRM_RegOpc\',')
        if dst2:
            insFile.write('\'IO\' ]\n')
        else:
            insFile.write(' \'I\' ]\n')
        insFile.write('    ModRM_RM :     [')
        if type1 == 'r':
            insFile.write('  \'R_' + repr(size1))
        elif type1 == 'm':
            insFile.write('\'ABR_64')
        elif type1 == 'xmm':
            insFile.write('\'XMM')
        elif type1 == 'mm':
            insFile.write('\'MM')
        else:
            print('opc ' + repr(opc) + ' oext ' + repr(oext) + ' mnem ' + repr(
                mnem) + ' rexAble ' + repr(rexAble) + ' opEn ' + repr(
                    opEn) + ' type1 ' + repr(type1) + ' size1 ' + repr(
                        size1) + ' type2 ' + repr(type2) + ' size2 ' + repr(
                            size2))
            return
        if rex and size1 >= 64 and type1 != 'mm':
            insFile.write('_REX')
        insFile.write('\',    \'ModRM_RM\',')
        if dst1:
            insFile.write('\'IO\' ]\n')
        else:
            insFile.write(' \'I\' ]\n')
        if type1 == 'm':
            insFile.write(
                '  MemoryOperands:\n    MEM1 :         [ [\'ModRM_RM\'], [' +
                repr(size1 / 8) + '], ' + repr(size1 / 8) + ',')
            if dst1:
                insFile.write('\'IO\' ]\n')
            else:
                insFile.write(' \'I\' ]\n')
    else:
        return  # TODO
    # sys.exit()


def write_instructions(row):
    twobyte = row[0]
    opc = row[1]
    if twobyte:
        opc = '0F' + opc
    oext = row[2]
    if oext != '':
        oextt = int(oext)
        if oextt < 0 or oextt > 7:
            skipped.append(row)
            return
    mnem = row[3]
    note = row[4]
    rexAble = row[5]
    numop = row[6]
    if numop != 2:
        skipped.append(row)
        return
    optypes = []
    opsizes = []
    opdst = []
    knowntype = set(['r', 'm', 'imm', 'xmm', 'mm', 'AL', 'AX', 'EAX', 'RAX',
                     'ST', '1'])
    knownsize = set([0, 8, 16, 32, 64, 128])
    for i in range(numop):
        optype = row[7 + i * 3]
        for atype in optype:
            if atype not in knowntype:
                skipped.append(row)
                return
        optypes.append(optype)
        opsize = row[7 + i * 3 + 1]
        for size in opsize:
            if size not in knownsize:
                skipped.append(row)
                return
        opsizes.append(opsize)
        opdst.append(row[7 + i * 3 + 2])
    if 'm' in optypes[0] and 'm' in optypes[1]:
        print('Abnormal instruction: opc ' + repr(opc) + ' oext ' + repr(
            oext) + ' mnem ' + repr(mnem) + ' types1 ' + repr(optypes[
                0]) + ' types2 ' + repr(optypes[1]))
        return
    if 'm' in optypes[0]:
        opEn = 'MR'
    elif 'm' in optypes[1]:
        opEn = 'RM'
    elif optypes[0] == ['r'] and optypes[1] == ['r']:
        # elif 'm' not in optypes[0] and 'm' not in optypes[1]:
        if mnem in opEns:
            opEn = opEns[mnem]
        else:
            print('Abnormal instruction: opc ' + repr(opc) + ' oext ' + repr(
                oext) + ' mnem ' + repr(mnem) + ' types1 ' + repr(optypes[
                    0]) + ' types2 ' + repr(optypes[1]))
            return
    else:  # TODO
        skipped.append(row)
        return
    opEns[mnem] = opEn
    if opsizes[0] == opsizes[1]:
        for type1 in optypes[0]:
            for size1 in opsizes[0]:
                for type2 in optypes[1]:
                    write_2op_instruction(opc, oext, mnem, note, rexAble, opEn,
                                          type1, size1, opdst[0], type2, size1,
                                          opdst[1])
    else:
        for type1 in optypes[0]:
            for size1 in opsizes[0]:
                for type2 in optypes[1]:
                    for size2 in opsizes[1]:
                        write_2op_instruction(opc, oext, mnem, note, rexAble,
                                              opEn, type1, size1, opdst[0],
                                              type2, size2, opdst[1])


def write_opc_record(record, twobyte):
    opc = record.get('value')
    if opc is None:
        print('Error: no opc\n' + ET.tostring(record))
        return 0
    rows = []
    for entry in record.findall('entry'):
        attr = entry.get('attr')
        if attr == 'invd':
            return 0
        if attr == 'null':
            return 0
        grp1 = entry.find('grp1')
        if grp1 is not None:
            if grp1.text == 'prefix':
                return 0
        opcdext = entry.find('opcd_ext')
        if opcdext is None:
            oext = ''
        else:
            oext = opcdext.text
        note = entry.find('note').find('brief')
        if note is None:
            print('Warning: no description ' + ET.tostring(entry))
            return 0
        notetext = note.text
        #
        # if isinstance(notetext, unicode):  # @UndefinedVariable
        # notetext = unicodedata.normalize('NFKD', notetext).encode('ascii',
        #                                                           'ignore')
        #
        for syntax in entry.findall('syntax'):
            mnem = syntax.find('mnem')
            if mnem is None:
                continue
            optypes = []
            opsizes = []
            opdst = []
            hasError = False
            rexAble = False
            for elem in syntax.iter():
                if elem.tag != 'dst' and elem.tag != 'src':
                    continue
                opdst.append(elem.tag == 'dst')
                optype = elem.find('a')
                opsize = elem.find('t')
                if optype is None or opsize is None:
                    if elem.text is None:
                        hasError = True
                        break
                    optypes.append(translate(elem.text))
                    opsizes.append([0])
                else:
                    optypes.append(translate(optype.text))
                    opsizes.append(translate(opsize.text))
                    if rexEligible(opsize.text):
                        rexAble = True
            if hasError:
                continue
            row = [
                twobyte, opc, oext, mnem.text, notetext, rexAble, len(optypes)
            ]
            for i in range(len(optypes)):
                row.append(optypes[i])
                row.append(opsizes[i])
                row.append(opdst[i])
            rows.append(row)
    for row in rows:
        write_instructions(row)
    return len(rows)


def write_headers():
    header = '# Copyright 2011-2021 IBM Corporation\n'
    header += '# All rights reserved\n'
    header += '# Generated on ' + str(datetime.datetime.now()) + '\n'
    header += '# Generated from ' + xmlFile + '\n' + '#\n'
    insFile.write(header)
    fmtFile.write(header)


inFile = open(xmlFile, 'r')
xmldata = inFile.read()
inFile.close()
root = ET.fromstring(xmldata)
counter = 0
skipped = []
unknowns = set([])
formats = set([])
opEns = dict([])
counters = dict([])
insFile = open(instrFile, 'wb')  # adding b avoids strange eol on windows
fmtFile = open(formtFile, 'wb')
write_headers()
for record in root.find('one-byte').findall('pri_opcd'):
    counter = counter + write_opc_record(record, False)
for record in root.find('two-byte').findall('pri_opcd'):
    counter = counter + write_opc_record(record, True)
insFile.close()
fmtFile.close()
print('Total number of syntex records:   ' + repr(counter))
print('Number of skipped syntex records: ' + repr(len(skipped)))
