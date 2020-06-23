# Copyright 2018 IBM Corporation
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
""":mod:`microprobe.passes.instruction` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import copy
import itertools
import multiprocessing as mp
import random
import pickle

# Third party modules
from six.moves import range
from six.moves import zip

# Own modules
import microprobe.code.ins
import microprobe.passes
import microprobe.utils.distrib
from microprobe import MICROPROBE_RC
from microprobe.code.address import Address, InstructionAddress
from microprobe.code.ins import instruction_set_def_properties
from microprobe.code.var import Variable
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeUncheckableEnvironmentWarning
from microprobe.target.isa.instruction import InstructionType
from microprobe.target.isa.register import Register
from microprobe.utils.asm import interpret_asm
from microprobe.utils.cmdline import print_info
from microprobe.utils.distrib import generate_weighted_profile, \
    weighted_choice
from microprobe.utils.logger import get_logger
from microprobe.utils.misc import RejectingDict, closest_divisor, \
    Progress, iter_flatten, getnextf

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    'SetInstructionTypePass',
    'ReplaceInstructionByTypePass',
    'SetInstructionTypeByProfilePass',
    'SetRandomInstructionTypePass',
    'SetInstructionTypeBySequencePass',
    'ReproduceSequencePass',
    'SetInstructionTypeByPropertyPass',
    'InsertInstructionSequencePass',
    'DIDTSimplePass',
    'SetInstructionTypeByAlternatingSequencesPass',
    'SetInstructionOperandsByOpcodePass',
    'SetInstructionTypeByElementPass',
    'AddAssemblyByIndexPass',
    'ReplaceLoadInstructionsPass',
]

# Functions


# Classes
class AddAssemblyByIndexPass(microprobe.passes.Pass):
    """AddAssemblyByIndexPass pass.

    """

    def __init__(self, assembly, allow_registers=None, index=-1):
        """

        :param assembly:
        :type assembly:
        """

        super(AddAssemblyByIndexPass, self).__init__()
        self._asm = assembly
        self._aregs = []
        if allow_registers is not None:
            self._aregs = allow_registers
        self._index = index

        self._description = "Append the '%s' instructions at index of the"\
            "building block." % ";".join(assembly)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        instructions_def = interpret_asm(
            self._asm, target, building_block.labels
        )

        instructions = []
        for definition in instructions_def:
            instruction = microprobe.code.ins.Instruction()
            instruction_set_def_properties(
                instruction,
                definition,
                building_block=building_block,
                target=target,
                allowed_registers=self._aregs
            )
            instructions.append(instruction)

        if self._index < 0:
            building_block.add_instructions(
                instructions,
                after=building_block.cfg.bbls[-1].instrs[-1]
            )
        elif self._index == 0:
            building_block.add_instructions(
                instructions,
                before=building_block.cfg.bbls[0].instrs[0]
            )
        else:
            cindex = 0
            ains = None
            instr = None
            for bbl in building_block.cfg.bbls:
                for instr in bbl.instrs:
                    cindex = cindex + 1

                if instr is None:
                    raise MicroprobeCodeGenerationError(
                        "Empty basic block found"
                    )

                if cindex == self._index:
                    ains = instr

                    building_block.add_instructions(instructions, after=ains)

                    return

            building_block.add_instructions(
                instructions,
                after=building_block.cfg.bbls[-1].instrs[-1]
            )


class SetInstructionTypePass(microprobe.passes.Pass):
    """SetInstructionTypePass pass.

    """

    def __init__(self, instr, allow_registers=None):
        """

        :param instr:

        """
        super(SetInstructionTypePass, self).__init__()
        self._instr = instr
        self._aregs = []
        if allow_registers is not None:
            self._aregs = allow_registers

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_arch_type(self._instr)
                for reg in self._aregs:
                    instr.add_allow_register(reg)

        return []


class ReplaceInstructionByTypePass(microprobe.passes.Pass):
    """ReplaceInstructionByTypePass pass.

    """

    def __init__(self, instr1, instr2, every):
        """

        :param instr1:
        :param instr2:
        :param every:

        """
        super(ReplaceInstructionByTypePass, self).__init__()

        if not isinstance(instr1, list):
            instr1 = [instr1]

        self._instr1 = instr1
        self._instr2 = instr2
        self._every = every
        self._description = "Replace '%s' by '%s' every '%d'" % (
            [instr.name for instr in instr1],
            instr2.name, every
        )

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        replaced = False

        if self._every == 0:
            return

        count = 0
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if instr.architecture_type in self._instr1:
                    count = count + 1

                    if (count % self._every) != 0:
                        continue

                    replaced = True
                    instr.set_arch_type(self._instr2)

                    # reserve implicit operands (if they are not already
                    # reserved) and add them as allowed
                    for operand_descriptor in instr.implicit_operands:
                        register = list(operand_descriptor.type.values())[0]
                        instr.add_allow_register(register)

                        if operand_descriptor.is_output and register not \
                                in building_block.context.reserved_registers \
                                and register not in target.control_registers:
                            building_block.context.add_reserved_registers(
                                [register]
                            )

                    context_fix_functions = instr.check_context(
                        building_block.context
                    )
                    for context_fix_function in context_fix_functions:
                        try:
                            context_fix_function(target, building_block)
                        except MicroprobeUncheckableEnvironmentWarning as wue:
                            building_block.add_warning(str(wue))

        # if not replaced:
        #    raise MicroprobeCodeGenerationError(
        #        "Unable to replace %s by %s every %d times" %
        #        ([instr.name for instr in self._instr1],
        #        self._instr2.name, self._every))


class SetInstructionTypeByElementPass(microprobe.passes.Pass):
    """SetInstructionTypeByElementPass pass.

    """

    def __init__(
            self,
            target,
            components,
            profile,
            block=None,
            maxlatency=None,
            minlatency=None,
            avelatency=None,
            any_comp=False
    ):

        if block is None:
            block = []

        super(SetInstructionTypeByElementPass, self).__init__()
        profile = _get_profile(
            target,
            components,
            profile,
            block,
            maxlatency=maxlatency,
            minlatency=minlatency,
            avelatency=avelatency,
            any_comp=any_comp
        )
        self._func = microprobe.utils.distrib.weighted_choice(profile)
        self._description = "Profile by component"

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_arch_type(self._func())

        return []


class SetInstructionTypeByProfilePass(microprobe.passes.Pass):
    """SetInstructionTypeByProfilePass pass.

    """

    def __init__(self, profile):
        """

        :param profile:

        """
        super(SetInstructionTypeByProfilePass, self).__init__()
        self._func = microprobe.utils.distrib.weighted_choice(profile)

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_arch_type(self._func())

        return []


class SetRandomInstructionTypePass(microprobe.passes.Pass):
    """SetRandomInstructionTypePass pass.

    """

    def __init__(self, instructions):
        """

        :param instructions:

        """
        super(SetRandomInstructionTypePass, self).__init__()
        self._instrs = instructions
        myrandom = random.Random()
        myrandom.seed(10)
        self._func = myrandom.choice

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        for idx, instr in enumerate(self._instrs):
            if not isinstance(instr, str):
                continue
            self._instrs[idx] = target.isa.instructions[instr]

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                instr.set_arch_type(self._func(list(self._instrs)))

                # reserve implicit operands (if they are not already
                # reserved) and add them as allowed
                for operand_descriptor in instr.implicit_operands:
                    register = list(operand_descriptor.type.values())[0]
                    instr.add_allow_register(register)

                    if operand_descriptor.is_output and register not \
                            in building_block.context.reserved_registers \
                            and register not in target.control_registers:
                        building_block.context.add_reserved_registers(
                            [register]
                        )

                context_fix_functions = instr.check_context(
                    building_block.context
                )
                for context_fix_function in context_fix_functions:
                    try:
                        context_fix_function(target, building_block)
                    except MicroprobeUncheckableEnvironmentWarning as wcheck:
                        building_block.add_warning(str(wcheck))

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """
        instrs = {}
        instrs_per = {}
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                if instr.architecture_type not in list(instrs.keys()):
                    instrs[instr.architecture_type] = 1
                else:
                    instrs[instr.architecture_type] += 1

        total = sum(instrs.values())
        for key, value in instrs.items():
            instrs_per[key] = (value) / total

        total_per = sum(instrs_per.values())
        assert abs(total_per - 1.0) < 0.0001, total_per

        average_value = total_per / len(list(instrs_per.values()))

        for key in sorted(instrs_per):

            value = instrs_per[key]
            if abs(value - average_value) > 0.05:

                LOG.debug("Deviation: %.5f > 0.05", abs(value - average_value))
                LOG.debug("Instruction: %s", key)
                LOG.debug("Count: %d", instrs[key])
                return False

        return True


class SetInstructionTypeBySequencePass(microprobe.passes.Pass):
    """SetInstructionTypeBySequencePass pass.

    """

    def __init__(self, instrs, prepend=None,
                 allow_registers=None):
        """

        :param instrs:

        """
        super(SetInstructionTypeBySequencePass, self).__init__()

        for instr in instrs:
            if not isinstance(instr, InstructionType):
                raise MicroprobeCodeGenerationError(
                    "Invalid sequence definition. '%s' is not an instruction"
                    " type " % instr
                )

        self._sequence = instrs
        self._func = getnextf(itertools.cycle(instrs))
        self._description = "Repeat the instruction sequence '%s'" % \
            ([instruction.name for instruction in self._sequence])

        if prepend is None:
            prepend = []

        self._prepend = prepend
        self._aregs = []
        if allow_registers is not None:
            self._aregs = allow_registers

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        count = 0

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                if count < len(self._prepend):
                    instruction = self._prepend[count]
                else:
                    instruction = self._func()

                count += 1

                LOG.debug("Set instruction type: %s", instruction)
                instr.set_arch_type(instruction)

                for reg in self._aregs:
                    instr.add_allow_register(reg)

                # reserve implicit operands (if they are not already
                # reserved) and add them as allowed
                for operand_descriptor in instr.implicit_operands:
                    register = list(operand_descriptor.type.values())[0]
                    instr.add_allow_register(register)

                    if (
                        operand_descriptor.is_output and register not in
                        building_block.context.reserved_registers and
                        register not in target.control_registers
                    ):

                        building_block.context.add_reserved_registers(
                            [register]
                        )

                context_fix_functions = instr.check_context(
                    building_block.context
                )

                for context_fix_function in context_fix_functions:

                    try:

                        context_fix_function(target, building_block)

                    except MicroprobeUncheckableEnvironmentWarning as wcheck:

                        building_block.add_warning(str(wcheck))

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        func = getnextf(itertools.cycle(self._sequence))
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                pass_ok = pass_ok and (instr.architecture_type == func())
        return pass_ok


class ReproduceSequencePass(microprobe.passes.Pass):
    """ReproduceSequencePass pass.

    """

    def __init__(self, seq):
        """

        :param seq:

        """
        super(ReproduceSequencePass, self).__init__()
        self._sequence = seq[:]
        self._description = "Reproduce instruction sequence"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param dummy_target:

        """

        if len(self._sequence) > MICROPROBE_RC['parallel_threshold']:
            if MICROPROBE_RC['verbose']:
                print_info("Enabling parallel processing")
            return self._parallel(building_block, target)

        sequence = iter(self._sequence)
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                definition = next(sequence)
                instruction_set_def_properties(
                    instr,
                    definition,
                    building_block=building_block,
                    target=target
                )

        return []

    def _parallel(self, building_block, target):

        def _iter_zip(list1, list2, extra=None):
            idx = 0
            try:
                while True:
                    item1 = next(list1)
                    item2 = next(list2)
                    if extra is None:
                        yield (item1, item2, idx)

                    else:
                        yield tuple([item1, item2] + extra + [idx])
                    idx = idx + 1
            except StopIteration:
                return

        props = iter(self._sequence)

        for bbl in building_block.cfg.bbls:
            instrs = iter(bbl.instrs)
            instrs_props = list(_iter_zip(instrs, props,
                                          extra=[building_block, target]))

            csize = max(len(bbl.instrs) // MICROPROBE_RC['cpus'], 1)

            instrs_propsl = (instrs_props[idx:idx + csize]
                             for idx in range(
                                 0, len(self._sequence), csize
            )
            )

            if MICROPROBE_RC['verbose']:
                print_info("Start mapping to %s threads ... " %
                           MICROPROBE_RC['cpus'])

            extra_args = {}
            extra_args['show_progress'] = True
            processes = []
            queues = []
            for chunk in instrs_propsl:
                queue = mp.Queue()
                extra_args['queue'] = queue
                proc = mp.Process(target=_set_props,
                                  args=(chunk,),
                                  kwargs=extra_args)
                processes.append(proc)
                queues.append(queue)
                proc.start()
                extra_args['show_progress'] = False

            new_instrs = []
            for queue in queues:
                new_instrs += queue.get()

            progress = Progress(
                len(bbl.instrs),
                msg="Setting instruction properties: "
            )

            instrs = iter(bbl.instrs)
            for instr, new_instr in zip(instrs, new_instrs):
                bbl.reset_instruction(instr, new_instr)
                progress()

            for queue in queues:
                queue.close()
                queue.join_thread()

            for process in processes:
                process.join()
                process.terminate()

        return []

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        pass_ok = True
        func = getnextf(itertools.cycle(self._sequence))
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                pass_ok = pass_ok and (instr.architecture_type == func())
        return pass_ok


class SetInstructionTypeByPropertyPass(SetInstructionTypeBySequencePass):
    """SetInstructionTypeByPropertyPass pass.

    """

    def __init__(
        self,
        instructions,
        attribute,
        targetvalue,
        maxvalue=None,
        minvalue=None
    ):
        """

        :param instructions:
        :param attribute:
        :param targetvalue:
        :param maxvalue:  (Default value = None)
        :param minvalue:  (Default value = None)

        """
        super(SetInstructionTypeByPropertyPass, self).__init__(instructions)
        self._targetvalue = targetvalue
        self._attribute = attribute
        self._profile = generate_weighted_profile(
            instructions,
            attribute,
            targetvalue,
            maxvalue=maxvalue,
            minvalue=minvalue
        )
        self._func = weighted_choice(self._profile)
        self._description = "Generate instruction profile with average" \
                            " attribute '%s' value of %d." % (attribute,
                                                              targetvalue)
        if maxvalue is not None:
            self._description += "Filter out values above %d." % maxvalue

        if minvalue is not None:
            self._description += "Filter out values below %d" % maxvalue

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        values = []
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                values.append(getattr(instr, self._attribute))

        finalvalue = sum(values) // len(values)

        diff = abs((finalvalue // self._targetvalue) - 1)
        if diff > 0.05:
            LOG.debug(
                "finalvalue %f != expected %f (diff %d%%)", finalvalue,
                self._targetvalue, diff * 100
            )
            return False

        return True


class InsertInstructionSequencePass(microprobe.passes.Pass):
    """InsertInstructionSequencePass pass.

    """

    def __init__(self, instrs, every=None, pad=0, operands=None):
        """

        :param instrs:
        :param every:  (Default value = None)
        :param pad:  (Default value = 0)
        :param operands:  (Default value = None)

        """
        super(InsertInstructionSequencePass, self).__init__()
        self._instrs = instrs
        self._every = every
        self._pad = pad
        self._operands = operands
        self._description = "Insert instruction: %s , every '%s', with " \
                            "pad '%s' and operands: '%s'" % (instrs, every,
                                                             pad, operands)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        for bbl in building_block.cfg.bbls:

            indexes = list(range(self._pad, bbl.size, self._every))
            instructions = bbl.instrs[:]

            for index in indexes:

                newins = []

                for instr in self._instrs:

                    nins = target.new_instruction(instr.name)

                    if self._operands is not None:
                        nins.set_operands(self._operands)

                    newins.append(nins)

                bbl.insert_instr(newins, after=instructions[index])


class DIDTSimplePass(microprobe.passes.Pass):
    """DIDTSimplePass pass.

    """

    def __init__(
        self, size, instrs1, ipc1, dep1, instrs2, ipc2, dep2, freqhz,
        system_freq_mhz
    ):
        """

        :param size:
        :param instrs1:
        :param ipc1:
        :param dep1:
        :param instrs2:
        :param ipc2:
        :param dep2:
        :param freqhz:
        :param system_freq_mhz:

        """

        super(DIDTSimplePass, self).__init__()

        LOG.debug("IPC: %s, %s ", ipc1, ipc2)
        LOG.debug("FREQ: %s, %s", freqhz, system_freq_mhz)

        cycletime = 1.0 / (system_freq_mhz * 1000000)
        period = 1.0 / (freqhz)
        cycles = (period / 2) / cycletime

        LOG.debug("TIMES: %s %s %s", cycletime, period, cycles)

        nins1 = cycles * ipc1
        nins2 = cycles * ipc2

        self._nins1 = int(nins1)
        self._nins2 = int(nins2)

        if self._nins1 < 1:
            self._nins1 = 1
            LOG.warning("Warning 1 a single instruction more than the period")

        if self._nins2 < 1:
            self._nins2 = 1
            LOG.warning("Warning 2 a single instruction more than the period")

        LOG.debug("INS %s %s", nins1, nins2)

        # seq1len = len(instrs1)
        # seq2len = len(instrs2)

        # repeat1 = (size/2)/seq1len
        # repeat2 = (size/2)/seq2len

        # Compute iterations in each sequence
        self._loop1 = int(nins1 / (size / 2))
        self._loop2 = int(nins2 / (size / 2))

        LOG.debug(
            " %f%% deviation in loop1 size ", (
                (
                    abs(
                        self._loop1 - (nins1 / (size / 2))
                    ) / (nins1 / (size / 2))
                ) * 100
            )
        )
        LOG.debug(
            " %f%% deviation in loop2 size ", (
                (
                    abs(
                        self._loop2 - (nins2 / (size / 2))
                    ) / (nins2 / (size / 2))
                ) * 100
            )
        )

        LOG.debug("LOOP %s %s", self._loop1, self._loop2)

        self._size = size / 2

        self._func1 = getnextf(itertools.cycle(instrs1))
        self._func2 = getnextf(itertools.cycle(instrs2))

        self._dep1 = dep1
        self._dep2 = dep2

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        rregs = building_block.context.reserved_registers

        LOG.debug(self._loop1, self._loop2)

        if not (self._loop1 < 2 and self._loop2 < 2):
            controlreg = target.get_address_reg(rregs)

            init_loop1 = target.set_register(controlreg, self._loop1)
            instr = microprobe.code.ins.Instruction()
            instr.set_arch_type(target.isa["MTSPR"])
            instr.set_operands([target.registers["CTR"], controlreg])
            init_loop1.append(instr)

            init_loop2 = target.set_register(controlreg, self._loop2)
            instr = microprobe.code.ins.Instruction()
            instr.set_arch_type(target.isa["MTSPR"])
            instr.set_operands([target.registers["CTR"], controlreg])
            init_loop2.append(instr)

            branch_loop1 = microprobe.code.ins.Instruction()
            branch_loop1.set_arch_type(target.isa["BC"])
            branch_loop1.set_operands([16, 0, "loop1"])

            branch_loop2 = microprobe.code.ins.Instruction()
            branch_loop2.set_arch_type(target.isa["BC"])
            branch_loop2.set_operands([16, 0, "loop2+24"])

            for instr in init_loop1 + init_loop2 + [branch_loop1] + \
                    [branch_loop2]:
                instr.add_allow_register(controlreg)
                instr.add_allow_register(target.registers["CTR"])

            building_block.add_init(init_loop1)
            building_block.add_fini(init_loop1)

            bbl1 = building_block.cfg.add_bbl(size=self._size)
            bbl2 = building_block.cfg.add_bbl(size=self._size)

            first = True
            for instr in bbl1.instrs:
                instr.set_arch_type(self._func1())
                instr.set_dependency_distance(self._dep1)
                if first:
                    first = False
                    instr.set_label("loop1")

            bbl1.insert_instr([branch_loop1], after=instr)

            first = True
            for instr in bbl2.instrs:
                instr.set_arch_type(self._func2())
                instr.set_dependency_distance(self._dep2)
                if first:
                    bbl2.insert_instr(init_loop2, before=instr)
                    first = False
                    init_loop2[0].set_label("loop2")

            bbl2.insert_instr([branch_loop2], after=instr)

            rregs.append(controlreg)

        else:
            size = self._nins1 + self._nins2
            while size < (self._size * 2):
                bbl = building_block.cfg.add_bbl(size=self._nins1)
                for instr in bbl.instrs:
                    instr.set_arch_type(self._func1())
                    instr.set_dependency_distance(self._dep1)

                bbl = building_block.cfg.add_bbl(size=self._nins2)
                for instr in bbl.instrs:
                    instr.set_arch_type(self._func2())
                    instr.set_dependency_distance(self._dep2)

                size = size + self._nins1 + self._nins2

            if size == self._nins1 + self._nins2:
                raise MicroprobeCodeGenerationError("Increase benchmark size")

        return rregs


class SetInstructionTypeByAlternatingSequencesPass(microprobe.passes.Pass):
    """DIDTPass pass.

    """

    def __init__(self, sequences, max_size=None):
        """

        :param sequences:
        :type sequences:
        :param max_size:
        :type max_size:
        """

        super(SetInstructionTypeByAlternatingSequencesPass, self).__init__()

        self._sequences = []
        self._max_size = max_size

        total_size = sum([elem[1] for elem in sequences])
        max_segment_size = max_size // (2 * len(sequences))

        if max_size is None:
            max_size = total_size * (len(sequences) + 1)

        for idx, sequence in enumerate(sequences):

            extra = 0
            iterations = 1

            modulo = len(sequence[0])
            length = min(sequence[1], max_segment_size)
            length = (length // modulo) * modulo

            if length == 0:
                length = modulo

            if (length * iterations) + extra != sequence[1]:

                iterations = sequence[1] // length

                extra = sequence[1] % length

            assert (length * iterations) + extra == sequence[1]

            self._sequences.append(
                (
                    getnextf(itertools.cycle(
                        sequence[
                            0
                        ]
                    )), length, iterations, extra
                )
            )

            LOG.debug(
                "Sequence: %d - %s, Length: %d, "
                "Iterations: %d, Extra: %d ", idx,
                ",".join([elem.name for elem in sequence[0]]), length,
                iterations, extra
            )

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        def fill_block(block, function):

            for instr in block.instrs:
                instr.set_arch_type(function())

                context_fix_functions = instr.check_context(
                    building_block.context
                )

                for context_fix_function in context_fix_functions:
                    try:
                        context_fix_function(target, building_block)
                    except MicroprobeUncheckableEnvironmentWarning as \
                            warning_check:
                        building_block.add_warning(str(warning_check))

        controlreg = target.get_register_for_address_arithmetic(
            building_block.context
        )

        for idx, sequence in enumerate(self._sequences):

            next_instruction, block_size, block_iterations, extra = sequence

            if block_iterations > 1:

                init_loop = target.set_register(
                    controlreg, block_iterations, building_block.context
                )

                if controlreg not in building_block.context.reserved_registers:
                    building_block.context.add_reserved_registers([controlreg])

                init_bbl = building_block.cfg.add_bbl(instructions=init_loop)

                for instr in init_bbl.instrs:
                    instr.add_allow_register(controlreg)

            block_bbl = building_block.cfg.add_bbl(size=block_size)
            fill_block(block_bbl, next_instruction)

            if block_iterations > 1:

                label = "sequence_%d" % idx
                block_bbl.instrs[0].set_label(label)
                add_cmp_branch = target.add_to_register(controlreg, -1)

                for instr in add_cmp_branch:
                    instr.add_allow_register(controlreg)

                add_cmp_branch += target.compare_and_branch(
                    controlreg,
                    0,
                    ">",
                    InstructionAddress(base_address=label),
                    building_block.context
                )

                block_bbl.insert_instr(
                    add_cmp_branch, after=block_bbl.instrs[-1]
                )

            if extra > 0:

                extra_bbl = building_block.cfg.add_bbl(size=(extra))
                fill_block(extra_bbl, next_instruction)

        return []


class SetInstructionOperandsByOpcodePass(microprobe.passes.Pass):
    """SetInstructionOperandsByOpcodePass pass.

    """

    def __init__(self, opcodes, operand_pos, value, force=False):
        """

        :param opcodes:
        :param operand_pos:
        :param value:

        """
        super(SetInstructionOperandsByOpcodePass, self).__init__()

        self._description = "Set operand %d of instructions with opcode " \
                            "'%s' to value: '%s'" % (operand_pos, opcodes,
                                                     value)
        if isinstance(opcodes, str):
            self._opcodes = [opcodes]
        else:
            self._opcodes = opcodes

        self._pos = operand_pos
        self._base_value = value
        self._force = force

        if not isinstance(value, list):

            def idem():
                """Return a constant."""
                return value

            self._value = idem
        else:
            self._value = getnextf(itertools.cycle(value))

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                if instr.name in self._opcodes:
                    if instr.operands()[
                            self._pos].value is None or self._force:
                        instr.operands()[self._pos].set_value(self._value())

                        if (instr.operands()[self._pos].is_output and
                                isinstance(
                                    instr.operands()[self._pos].value,
                                    Register
                                )):
                            instr.add_allow_register(
                                instr.operands()[self._pos].value
                            )

    def check(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        if isinstance(self._base_value, list):
            self._value = getnextf(itertools.cycle(self._base_value))

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                if instr.opcode in self._opcodes:
                    if instr.operands()[self._pos].value != self._value():
                        return False

        return True


class ReplaceLoadInstructionsPass(microprobe.passes.Pass):
    """ReplaceLoadInstructionsPass pass.

    """

    def __init__(self, instr, every):
        """

        :param instr:
        :type instr:
        :param every:
        :type every:
        """

        super(ReplaceLoadInstructionsPass, self).__init__()
        self._description = "Replace every load for a '%s' instruction every "\
            "'%d' number of loads" % (instr.name, every)
        self._instr = instr
        self._every = every

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """

        if self._every == 0:
            return []

        count = 0
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                is_load = False
                for moperand in instr.memory_operands():
                    if moperand.is_load:
                        is_load = True
                        break

                if is_load:
                    count = count + 1
                    if (count % self._every) == 0:
                        instr.set_arch_type(self._instr)


# TODO: This get_profile function is copied from the first prototype of the
# code, back in 2011. It need an importand re-engineering pass.
def _get_profile(
    target,
    components,
    profile,
    block,
    maxlatency=None,
    minlatency=None,
    avelatency=None,
    any_comp=False
):

    if avelatency is not None:
        if maxlatency is not None and avelatency > maxlatency:
            raise MicroprobeCodeGenerationError(
                "I can not fulfill the conditions"
            )
        if minlatency is not None and avelatency < minlatency:
            raise MicroprobeCodeGenerationError(
                "I can not fulfill the conditions"
            )

    isa_map = target.property_isa_map("execution_units")

    if any_comp:
        setm = set()
        for comp in components:
            setm = setm | isa_map[comp.name]
    else:
        setm = None
        for comp in components:
            if setm is None:
                setm = isa_map[comp.name]
            else:
                setm = setm & isa_map[comp.name]

    for comp in block:
        setm = setm - isa_map[comp.name]

    values = []
    for key, value in profile.items():
        if key not in setm:
            continue

        if maxlatency is not None:
            if key.latency > maxlatency and key.latency > 0:
                continue

        if minlatency is not None:
            if key.latency < minlatency and key.latency > 0:
                continue

        values.append((key, value))

    if len(values) == 0:

        for value in setm:
            if value.privileged or value.hypervisor or value.trap:
                continue

            if maxlatency is not None:
                if value.latency > maxlatency and value.latency > 0:
                    continue

            if minlatency is not None:
                if value.latency < minlatency and value.latency > 0:
                    continue

            values.append((value, 1))

    if len(values) < 1:
        raise MicroprobeCodeGenerationError(
            "No instruction found in the ISA stressing %s" % (
                [comp.name for comp in components]
            )
        )

    if avelatency is not None:

        def calc_avelatency(values):
            """Computer average latency by weight."""
            return sum(
                [
                    v.latency * weight for v, weight in values
                ]
            ) / sum(
                [
                    weight for v, weight in values
                ]
            )

        cavelatency = calc_avelatency(values)

        if cavelatency < avelatency:
            abovelist = [
                idx for idx, v in enumerate(values)
                if v[0].latency > avelatency
            ]
            if len(abovelist) > 0:
                while cavelatency < avelatency:
                    index = random.choice(abovelist)
                    abovelist.remove(index)
                    values[index] = (values[index][0], values[index][1] + 1)
                    cavelatency = calc_avelatency(values)
                    if len(abovelist) == 0:
                        abovelist = [
                            idx
                            for idx, v in enumerate(values)
                            if v[0].latency > avelatency
                        ]
            else:
                maxlat = max([v.latency for v, dummy_weight in values])
                values = [(v, w) for v, w in values if v.latency == maxlat]

        elif cavelatency > avelatency:
            belowlist = [
                idx for idx, v in enumerate(values)
                if v[0].latency < avelatency
            ]
            if len(belowlist) > 0:
                while cavelatency > avelatency:
                    index = random.choice(belowlist)
                    belowlist.remove(index)
                    values[index] = (values[index][0], values[index][1] + 1)
                    cavelatency = calc_avelatency(values)
                    if len(belowlist) == 0:
                        belowlist = [
                            idx
                            for idx, v in enumerate(values)
                            if v[0].latency < avelatency
                        ]
                        assert len(belowlist) > 0, "Something wrong"
            else:
                minlat = min([v.latency for v, dummy_weight in values])
                values = [(v, w) for v, w in values if v.latency == minlat]

    return dict(values)


def _set_props(largs, queue=None, show_progress=False):

    rlist = []

    if show_progress:
        progress = Progress(
            len(largs),
            msg="Setting instruction properties: "
        )

    for args in largs:
        instr, definition, building_block, target, displ = args
        instruction_set_def_properties(
            instr,
            definition,
            building_block=building_block,
            target=target,
            label_displ=displ
        )

        if show_progress:
            progress()

        rlist.append(instr)

    if queue is not None:
        queue.put(rlist)

    return rlist
