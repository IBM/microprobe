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
""":mod:`microprobe.passes.memory` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import collections
import itertools

# Third party modules
import six
from six.moves import range
from six.moves import zip

# Own modules
import microprobe.code.var
import microprobe.passes
import microprobe.utils.distrib
from microprobe.code.address import Address, InstructionAddress
from microprobe.exceptions import MicroprobeCodeGenerationError,\
        MicroprobeValueError
from microprobe.target.isa.operand import OperandConst, \
    OperandConstReg, OperandDescriptor, OperandReg
from microprobe.passes.address import UpdateInstructionAddressesPass
from microprobe.utils.distrib import regular_seq
from microprobe.utils.logger import get_logger, set_log_level
from microprobe.utils.misc import longest_common_substr, range_to_sequence, \
    getnextf

# Local modules


# Constants
LOG = get_logger(__name__)
__all__ = [
    'GenericMemoryModelPass',
    'GenericOldMemoryModelPass',
    'SetMemoryOperandByOpcodePass',
    'SingleMemoryStreamPass',
    'FixMemoryReferencesPass',
    'GenericMemoryStreamsPass',
    'InitializeMemoryDecorator']

# Functions


# Classes
class GenericMemoryModelPass(microprobe.passes.Pass):
    """GenericMemoryModelPass pass.

    """

    def __init__(self, model):
        """

        :param model:

        """
        super(GenericMemoryModelPass, self).__init__()
        self._model = model
        self._description = "Generic memory model pass. "\
                            "Using model: %s" % model

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        if not building_block.context.register_has_value(0):
            reg = target.get_register_for_address_arithmetic(
                building_block.context
            )
            building_block.add_init(
                target.set_register(
                    reg, 0, building_block.context
                )
            )

            building_block.context.set_register_value(reg, 0)
            building_block.context.add_reserved_registers([reg])

        self._model.initialize_model()

        tregs = {}
        vregs = {}
        base_displ = {}

        for bbl in building_block.cfg.bbls:
            last_instr = None
            for instr in bbl.instrs:

                if not instr.access_storage:
                    last_instr = instr
                    continue

                for memoperand in instr.memory_operands():

                    if memoperand.address is not None:
                        continue

                    if memoperand.is_agen:
                        continue

                    if (
                        memoperand.possible_addresses(building_block.context)
                        is not None
                    ):

                        LOG.critical(
                            "Constrained operands for instruction"
                            " %s . Not implemented", instr.mnemonic
                        )
                        raise NotImplementedError

                    address, length = self._model(
                        memoperand.possible_lengths(building_block.context)
                    )

                    LOG.debug("START %s --> %s ?", instr, address)

                    var = address.base_address

                    if var not in building_block.registered_global_vars():

                        building_block.register_var(
                            var, building_block.context
                        )

                        reg = target.get_register_for_address_arithmetic(
                            building_block.context
                        )

                        building_block.add_init(
                            target.set_register_to_address(
                                reg,
                                Address(base_address=var),
                                building_block.context
                            )
                        )

                        building_block.context.set_register_value(
                            reg, Address(base_address=var)
                        )

                        building_block.context.add_reserved_registers([reg])

                        vregs[var] = reg

                        LOG.debug("Registering Var: %s", var)
                        LOG.debug("Used reg: %s", reg)

                        treg = target.get_register_for_address_arithmetic(
                            building_block.context
                        )

                        tregs[var] = treg

                        building_block.context.add_reserved_registers([treg])

                        LOG.debug(
                            "Reserving '%s' for displacement "
                            "computations", treg
                        )

                        base_displ[var] = 0

                    alignment = memoperand.alignment()
                    if alignment is not None:

                        if address.displacement % alignment != 0:
                            newdisplacement = int(
                                address.displacement // alignment
                            ) * alignment
                            address = Address(
                                base_address=address.base_address,
                                displacement=newdisplacement
                            )

                    try:

                        LOG.debug("First trial, using default context")
                        memoperand.set_address(address, building_block.context)

                    except MicroprobeCodeGenerationError:

                        LOG.debug(
                            "Unable to generate the address. Fixing "
                            "Context to allow the generation"
                        )

                        regdisp = tregs[var]
                        regbase = vregs[var]

                        LOG.debug("Register base: %s", regbase.name)
                        LOG.debug("Register displacement: %s", regdisp.name)

                        new_ins_displ = target.set_register(
                            regdisp, address.displacement - base_displ[var],
                            building_block.context
                        )

                        new_ins_all = target.set_register_to_address(
                            regbase,
                            address,
                            building_block.context,
                            force_relative=True
                        )

                        if (
                            (len(new_ins_all) < len(new_ins_displ)) or (
                                (len(new_ins_all) == len(new_ins_displ)) and
                                address.displacement <= abs(
                                    base_displ[var] - address.displacement
                                )
                            )
                        ):

                            new_ins = new_ins_all
                            reg_value = address
                            reg = regbase
                            base_displ[var] = address.displacement

                        else:

                            new_ins = new_ins_displ
                            reg_value = address.displacement - base_displ[var]
                            reg = regdisp

                        oldcontext = building_block.context.copy()

                        building_block.context.set_register_value(
                            reg, reg_value
                        )

                        try:

                            LOG.debug("Second trial, after fixing the context")
                            memoperand.set_address(
                                address, building_block.context
                            )

                            building_block.add_instructions(
                                new_ins,
                                after=last_instr,
                                before=instr
                            )

                            for nins in new_ins:
                                nins.add_allow_register(reg)

                        except MicroprobeCodeGenerationError:
                            # Reset state and force switching, it should be
                            # always possible to generate any given address

                            LOG.debug(
                                "Unable to generate the address. Fixing "
                                "Context to allow the generation"
                            )

                            building_block.set_context(oldcontext)

                            new_ins = target.set_register_to_address(
                                regbase,
                                address,
                                building_block.context,
                                force_relative=True
                            )

                            base_displ[var] = address.displacement

                            building_block.context.set_register_value(
                                regbase, address
                            )

                            for nins in new_ins:
                                nins.add_allow_register(regbase)

                            LOG.debug("Third trial, after fixing the context")
                            memoperand.set_address(
                                address, building_block.context
                            )

                            building_block.add_instructions(
                                new_ins,
                                after=last_instr,
                                before=instr
                            )

                    if memoperand.variable_length:
                        memoperand.set_length(length, building_block.context)

                    LOG.debug("%s --> %s Done!", instr, address)
                    instr.add_comment("Address: %s" % address)

                    last_instr = instr

        actions = self._model.finalize_model()

        if len(actions) > 0:
            idx = 0
            for idx, action in enumerate(actions):
                var, increment, guard = action

                # building_block.context.unset_registers([vregs[var]])
                # building_block.context.unset_registers([tregs[var]])

                reg = target.get_register_for_address_arithmetic(
                    building_block.context
                )

                LOG.debug(
                    "Using register %s for counting the guard "
                    "iterations", reg.name
                )

                building_block.add_init(
                    target.set_register(
                        reg, 0, building_block.context
                    )
                )

                building_block.context.add_reserved_registers([reg])

                new_instrs = target.add_to_register(reg, 1)

                if idx > 0:
                    new_instrs[0].set_label("mem_guard_%d" % idx)

                building_block.add_fini(new_instrs)

                building_block.add_fini(
                    target.add_to_register(
                        vregs[var], increment - base_displ[var]
                    )
                )

                building_block.add_fini(
                    target.compare_and_branch(
                        reg, guard, "<", "mem_guard_%d" % (
                            idx + 1
                        ), building_block.context
                    )
                )

                # remove from context so that
                # it is initialized to the beginning
                building_block.context.unset_registers([vregs[var]])

                building_block.add_fini(
                    target.set_register_to_address(
                        vregs[var],
                        Address(base_address=var),
                        building_block.context
                    )
                )

                # and reset the counter
                building_block.add_fini(
                    target.set_register(
                        reg, 0, building_block.context
                    )
                )

                building_block.context.set_register_value(
                    vregs[var], Address(base_address=var)
                )

            new_instr = target.nop()

            new_instr.set_label("mem_guard_%d" % (idx + 1))
            building_block.add_fini([new_instr])

        # remove all index registers from context if they have been used
        for treg in tregs.values():

            if building_block.context.get_register_value(treg) is None:
                continue

            building_block.context.unset_registers([treg])

        for var, displacement in base_displ.items():
            if displacement == 0:
                continue

            # base register has been touched, remove from context so that
            # it is initialized to the beginning
            building_block.context.unset_registers([vregs[var]])

            if var in [action[0] for action in actions]:
                # Variable already guarded
                continue

            # force re-init, if base_register has been touch
            building_block.add_fini(
                target.set_register_to_address(
                    vregs[var],
                    Address(base_address=var),
                    building_block.context
                )
            )

            # building_block.context.set_register_value(
            #    vregs[var],
            #    Address(base_address=var)
            # )

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError


class GenericOldMemoryModelPass(microprobe.passes.Pass):
    """GenericOldMemoryModelPass pass.

    """

    def __init__(self, model, strict=True, loadsonly=False, storesonly=False):
        """

        :param model:
        :param strict:  (Default value = True)
        :param loadsonly:  (Default value = False)
        :param storesonly:  (Default value = False)

        """
        super(GenericOldMemoryModelPass, self).__init__()
        self._strict = strict
        self._model = sorted(model, key=lambda m: m[0])

        self._lo = loadsonly
        self._so = storesonly
        items = []
        sets_dict = {}

        all_ratio = 0
        mcomp_ant = None
        accum = 100

        for mcomp, ratio in self._model:
            items.append((mcomp, ratio))
            all_ratio += ratio

            if accum == 0:
                sets = []
            elif mcomp_ant is None:
                sets = mcomp.setsways()
                lsets = len(sets)
                sets = sets[0:int(lsets * ratio // accum)]
            else:
                sets = mcomp.setsways()
                sets_ant = [
                    elem & ((1 << mcomp_ant.set_ways_bits()) - 1)
                    for elem in sets
                ]
                zipping = list(zip(sets, sets_ant))

                fset = frozenset(sets_dict[mcomp_ant])
                sets = [s1 for s1, s2 in zipping if s2 not in fset]

                lsets = len(sets)
                sets = sets[0:int(lsets * ratio // accum)]

            sets_dict[mcomp] = sets
            accum = accum - ratio
            mcomp_ant = mcomp

        mcomp_ant = None

        for mcomp, ratio in self._model:

            slist = [elem << mcomp.offset_bits() for elem in sets_dict[mcomp]]

            # TODO: shuffle function too slow for pseudorandom

            if mcomp_ant is None:
                mcomp_ant = mcomp

            # TODO: strided parameter or random or pseudorandom (32k ranges)
            shuffle_type = None

            if shuffle_type == '32k':
                slist = microprobe.utils.distrib.shuffle(slist, 32768)
            elif shuffle_type == 'all':
                slist = microprobe.utils.distrib.shuffle(slist, -1)
            elif shuffle_type == 'mcomp_ant':
                slist = microprobe.utils.distrib.shuffle(slist, mcomp_ant.size)

            if len(slist) > 0:
                tlist = []
                tlist.append(slist[0])
                tlist.append(slist[-1])

            sets_dict[mcomp] = slist
            mcomp_ant = mcomp

        self._sets = sets_dict
        self._func = microprobe.utils.distrib.weighted_choice(dict(items))

        assert all_ratio == 100, "The memory access model is not complete"
        assert accum == 0, "Something wrong"

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        descriptors = {}

        rregs = building_block.context.reserved_registers

        mant = None
        for mcomp, ratio in self._model:

            var = microprobe.code.var.VariableArray(
                mcomp.name,
                "char", mcomp.size,
                align=256 * 1024 * 1024
            )

            building_block.register_var(var, building_block.context)

            if ratio > 0:
                reg_base = target.get_address_reg(rregs)
                rregs.append(reg_base)
                reg_idx = target.get_address_reg(rregs)
                rregs.append(reg_idx)
                calc_instrs = []
                last_instr = None
                count = 0
                reduced = False
                max_value = 0

                if mant is None:
                    module = len(self._sets[mcomp])
                else:
                    module = min(
                        int(
                            4 * (
                                len(mant.setsways()) - len(self._sets[mant])
                            )
                        ), len(self._sets[mcomp])
                    )

                descriptors[mcomp] = [
                    var, reg_base, 0, reg_idx, 0, calc_instrs, last_instr,
                    count, module, reduced, max_value
                ]

            mant = mcomp

        for var, reg_base, reg_base_val, reg_idx, reg_idx_val, calc_instrs, \
                last_instr, count, module, reduced, \
                max_value in six.itervalues(descriptors):

            building_block.add_init(target.load_var_address(reg_base, var))
            building_block.add_init(target.set_register(reg_idx, 0))

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if (
                    instr.mem() and not (instr.store() and self._lo) and
                    not (instr.load() and self._so)
                ):

                    mcomp = self._func()

                    var, reg_base, reg_base_val, reg_idx, reg_idx_val, \
                        calc_instrs, last_instr, count, module, reduced, \
                        max_value = descriptors[mcomp]

                    if reg_base not in rregs:
                        rregs.append(reg_base)

                    if reg_idx not in rregs:
                        rregs.append(reg_idx)

                    if module > 0:
                        value = self._sets[mcomp][count % (module)]
                    else:
                        value = 0

                    max_value = max(value, max_value)

                    count = count + 1

                    # iterate over the second 52.5% of the sets.
                    # This will reduce some hits in previous levels when the
                    # pattern is repeated
                    # but no complete.

                    # if module>0 and (count % module) == 0 and not reduced:
                    # print "REDUCING"
                    #    new_module = int(module * 0.525)
                    #    jump = module - new_module
                    #    module = new_module
                    #    reduced = True
                    #    self._sets[mcomp] = self._sets[mcomp][jump:]

                    values = target.generate_address(
                        value, instr, reg_base, reg_base_val, reg_idx,
                        reg_idx_val, calc_instrs
                    )
                    reg_base_val_new, reg_idx_val_new, tinstrs, \
                        new_instrs = values

                    for k, dummy in descriptors.items():
                        if k == mcomp:
                            # TODO: Do it more smart: now we constrain the
                            # usage
                            # of previous instructions as calc_instructions,
                            # only if the base register and the idx register
                            # are not touched (implying that the memory
                            # operation uses an immediate (and does not touch
                            # anything).
                            if (
                                reg_base_val == reg_base_val_new and
                                reg_idx_val == reg_idx_val_new
                            ):
                                descriptors[mcomp] = [
                                    var, reg_base, reg_base_val_new, reg_idx,
                                    reg_idx_val_new, calc_instrs, instr, count,
                                    module, reduced, max_value
                                ]
                            else:
                                descriptors[mcomp] = [
                                    var, reg_base, reg_base_val_new, reg_idx,
                                    reg_idx_val_new, [], instr, count, module,
                                    reduced, max_value
                                ]
                        else:
                            for tinstr in tinstrs:
                                descriptors[k][5] = []
                                descriptors[k][6] = instr

                    if len(tinstrs) > 0:
                        for tinstr in tinstrs:
                            tinstr.add_allow_register(reg_base)
                            tinstr.add_allow_register(reg_idx)

                    if len(new_instrs) > 0:

                        building_block.add_instructions(
                            new_instrs,
                            after=last_instr,
                            before=instr
                        )
                        for new_instr in new_instrs:
                            new_instr.add_allow_register(reg_base)
                            new_instr.add_allow_register(reg_idx)

                    # TODO: AUTOCALCULATE
                    # TODO: Fix this, the purpose is to touch a given address
                    # before using it afterwards only for the first level of
                    # the cache hierarchy

                    warm_l1_cache = True
                    if warm_l1_cache and instr.store() and mcomp.name == "L1D":
                        ninstr = target.generate_load()
                        values = target.generate_address(
                            value, ninstr, reg_base, 0, reg_idx, 0, []
                        )

                        # ninstr.set_operands_random()
                        new_instrs = values[3]
                        building_block.add_init(new_instrs)
                        building_block.add_init([ninstr])
                        building_block.add_init(
                            target.load_var_address(reg_base, var)
                        )
                        building_block.add_init(
                            target.set_register(
                                reg_idx, 0
                            )
                        )

                else:
                    for key, dummy in descriptors.items():
                        descriptors[key][5].append(instr)

        mcomp_ant = None
        blabel = None
        for mcomp, ratio in self._model:
            if mcomp_ant is None:
                mcomp_ant = mcomp

                if mcomp in descriptors:
                    var, reg_base, reg_base_val, reg_idx, reg_idx_val, \
                        calc_instrs, last_instr, count, module, reduced, \
                        max_value = descriptors[mcomp]

                    # Init everything: reg base to the start of the array var,
                    # register idx to zero and register of the constant to
                    # zero.

                    new_instrs = target.load_var_address(reg_base, var)
                    new_instrs = new_instrs + target.set_register(reg_idx, 0)
                    for new_instr in new_instrs:
                        new_instr.add_allow_register(reg_base)
                        new_instr.add_allow_register(reg_idx)
                    building_block.add_fini(new_instrs)

                continue

            if mcomp in descriptors:
                var, reg_base, reg_base_val, reg_idx, reg_idx_val, \
                    calc_instrs, last_instr, count, module, reduced, \
                    max_value = descriptors[mcomp]
            else:
                mcomp_ant = mcomp
                continue

            size = len(self._sets[mcomp])
            rsize = len(mcomp_ant.setsways()) - len(self._sets[mcomp_ant])

            incsize = (max_value // mcomp_ant.size)
            if max_value % mcomp_ant.size:
                incsize += 1
            incsize = mcomp_ant.size * incsize

            # if count >= rsize:
            #    incsize = incsize*2
            guard = mcomp.size // incsize

            if self._strict:
                if count == 0 and ratio > 0:
                    raise NotImplementedError(
                        "Not access generated to %s, "
                        "increase the size" % mcomp
                    )
                if count > 0 and ratio == 0:
                    raise NotImplementedError(
                        "Access generated to %s which is"
                        " not modeled!" % mcomp
                    )

                if (guard * count) < (2 * rsize):
                    LOG.critical("Guard: %s", guard)
                    LOG.critical("count: %s", count)
                    LOG.critical("rsize: %s", rsize)
                    LOG.critical("mcomp: %s", mcomp)
                    raise NotImplementedError(
                        "This case is not implemented "
                        "yet. Consider increasing the "
                        "benchmark size (%d > %d)" % (guard * count, 2 * rsize)
                    )

            # Always set the index register to zero
            new_instrs = target.set_register(reg_idx, 0)
            for new_instr in new_instrs:
                new_instr.add_allow_register(reg_base)
                new_instr.add_allow_register(reg_idx)
            building_block.add_fini(new_instrs)

            if blabel is not None:
                new_instrs[0].set_label(blabel)
                blabel = None

            if count > size or count > (2 * rsize):
                # we touch everything, se we can reset every time
                # or we touch at least two times the available sets in the
                # previous level, meaning that we are accessing the current
                # level of the cache hierarchy
                new_instrs = target.load_var_address(reg_base, var)
                new_instrs = new_instrs + target.set_register(reg_idx, 0)
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)
                    new_instr.add_allow_register(reg_idx)
                building_block.add_fini(new_instrs)

            else:
                # we do not touch everything but we have enough room in the
                # array for ensuring the access to the required level of the
                # memory hierarchy

                # if count < rsize:
                # print count, rsize

                # show warning if it is not the last level of the memory
                # hierarchy which usually is very difficult to touch all

                if self._strict:
                    LOG.warning(
                        "Warning: Memory model accuracy affected because "
                        "the total number of references to %s is low. Check "
                        "the final memory behavior of the generated benchmark."
                        " To increase accuracy, you can increase the number "
                        "of references by incrementing the weight of this "
                        "component or the benchmark size.", mcomp.name
                    )

                # register the counter control constant (reserving a register)
                # and set its value to zero
                reg_constant = target.get_address_reg(rregs)
                rregs.append(reg_constant)
                new_instrs = target.set_register(reg_constant, 0)
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_constant)
                target.add_init(new_instrs)

                # add one to the counter
                dummy, new_instrs = target.add_value_reg(reg_constant, 1)
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_constant)
                building_block.add_fini(new_instrs)

                # set the label of the first instruction (in case the previous
                # memory component)
                # skips some code, it need a target
                # if blabel is not None:
                #    new_instrs[0].set_label(blabel)
                #    blabel = None

                # print "MCOMP", mcomp,  mcomp.size, guard, mcomp.size/guard,
                #                                count, rsize, mcomp_ant
                # print "REG", reg_base_val

                # add the required size to the register base of the memory
                # component

                # If (mcomp.size/guard) - reg_base_val == 0:

                # if reg_base_val >= (mcomp.size/guard):
                #     print mcomp, mcomp.size
                #     print "Guard", guard
                #     print "Base val", reg_base_val
                #     print reg_base_val, ">=", (mcomp.size/guard)
                #     print mcomp.size/mcomp_ant.size
                #     guard = gua    rd - 2
                #     print "REDUCED GUARD"
                # else:
                #     print mcomp, mcomp.size
                #     print "Guard", guard
                #     print "Base val", reg_base_val
                #     print "VAL", (mcomp.size/guard)*(guard-1)

                # increment the base register by
                dummy_rubbish, new_instrs = target.add_value_reg(
                    reg_base, (mcomp.size // guard) - reg_base_val
                )
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)
                    # print new_instr.assembly()
                building_block.add_fini(new_instrs)

                # Add the conditional branch
                new_instrs = target.conditional_branch(
                    reg_constant, "<", guard, "%sguard" % mcomp.name
                )
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_constant)
                    # print new_instr.assembly()
                building_block.add_fini(new_instrs)

                # Set the label for in case the next component needs it
                blabel = "%sguard" % mcomp.name

                # Init everything: reg base to the start of the array var,
                # register idx to zero and register of the constant to zero.
                new_instrs = target.load_var_address(reg_base, var)
                new_instrs = new_instrs + target.set_register(reg_constant, 0)
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)
                    new_instr.add_allow_register(reg_idx)
                    # print new_instr.assembly()
                building_block.add_fini(new_instrs)

            mcomp_ant = mcomp

        # Add a nop with a label, for the last mcomp that needs to jump
        # somewhere if it wants to skip the reset code.
        if blabel is not None:
            new_instr = target.nop()
            new_instr.set_label(blabel)
            # print new_instr.assembly()
            building_block.add_fini([new_instr])
            blabel = None

        return rregs


class SingleMemoryStreamPass(microprobe.passes.Pass):
    """SingleMemoryStreamPass pass.

    """

    _ids = itertools.count(0)

    def __init__(self, size, stride, length=None, align=None,
                 warmstores=False, value="random"):
        """

        :param size:
        :param stride:
        :param length:  (Default value = None)
        :param align: (Default value = None)

        """

        super(SingleMemoryStreamPass, self).__init__()

        self._size = size
        self._stride = stride
        self._length = length
        self._align = align
        self._warmstores = warmstores

        if value == "random":
            value = None

        self._var = microprobe.code.var.VariableArray(
            "ST_%d_%d_%d" % (self._size, self._stride, next(self._ids)),
            "char", (self._size + 1) * max(self._stride, 1),
            align=self._align, value=value
        )

        addresses = []
        for idx in range(0, self._size):
            addresses.append(
                Address(
                    base_address=self._var,
                    displacement=idx * self._stride
                )
            )

        self._addresses = addresses
        self._description = "Access to '%s' different memory locations in a" \
                            " round-robin fashion. Stride between locations:" \
                            " '%s' bytes. Length of the memory accesses: '%s'"\
                            " bytes" % (self._size, self._stride, self._length)

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param target:

        """

        if not building_block.context.register_has_value(0):

            reg = target.get_register_for_address_arithmetic(
                building_block.context
            )

            building_block.add_init(
                target.set_register(
                    reg, 0, building_block.context
                )
            )

            building_block.context.set_register_value(reg, 0)
            building_block.context.add_reserved_registers([reg])

        idx = 0
        not_initialized = True
        warmed = []

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                if not instr.access_storage:
                    continue

                LOG.debug("Memory instruction: %s",
                          instr)

                for memoperand in instr.memory_operands():

                    if memoperand.address is not None:
                        continue

                    if memoperand.is_agen:
                        continue

                    if memoperand.is_branch_target:
                        continue

                    # initialize the variable the first time used
                    if not_initialized:

                        building_block.register_var(
                            self._var, building_block.context
                        )

                        reg = target.get_register_for_address_arithmetic(
                            building_block.context
                        )

                        building_block.add_init(
                            target.set_register_to_address(
                                reg, self._addresses[
                                    idx
                                ], building_block.context
                            )
                        )

                        building_block.context.set_register_value(
                            reg, self._addresses[idx]
                        )

                        building_block.context.add_reserved_registers([reg])
                        not_initialized = False

                    if (
                        memoperand.possible_addresses(building_block.context)
                        is not None
                    ):

                        paddresses = memoperand.possible_addresses(
                            building_block.context
                        )
                        taddress = paddresses[idx % len(paddresses)]

                        LOG.warning(
                            "Memory operand constrained, generating"
                            " address: %s , instead of: %s", taddress,
                            self._addresses[idx]
                        )

                    else:
                        taddress = self._addresses[idx]

                    alignment = memoperand.alignment()

                    if alignment is not None:
                        if taddress.displacement % alignment != 0:
                            newdisplacement = int(
                                taddress.displacement // alignment
                            ) * alignment
                            taddress = Address(
                                base_address=taddress.base_address,
                                displacement=newdisplacement
                            )

                    # Set address of the memory operand
                    try:

                        LOG.debug("Target address: %s", taddress)
                        memoperand.set_address(
                            taddress, building_block.context
                        )

                    except MicroprobeCodeGenerationError:

                        reg = target.get_register_for_address_arithmetic(
                            building_block.context
                        )

                        building_block.add_init(
                            target.set_register_to_address(
                                reg, taddress, building_block.context
                            )
                        )

                        # oldcontext = building_block.context.copy()

                        building_block.context.set_register_value(
                            reg, taddress
                        )

                        building_block.context.add_reserved_registers([reg])

                        try:

                            LOG.debug("Target address 2: %s", taddress)
                            memoperand.set_address(
                                taddress, building_block.context
                            )

                        except MicroprobeCodeGenerationError as exc:
                            raise exc

                    instr.add_comment("Address: %s" % taddress)

                    # Set length of the memory operand --> default maximum
                    if memoperand.variable_length:
                        length = self._length

                        if length is None:

                            length = max(
                                memoperand.possible_lengths(
                                    building_block.context
                                )
                            )

                        LOG.debug("Length: %s", length)
                        memoperand.set_length(length, building_block.context)

                    assert memoperand.length is not None

                    if (self._warmstores and memoperand.is_store and
                            taddress not in warmed):
                        # Warm stores
                        mycontext = target.wrapper.context()
                        ninstr = target.set_register_to_address(
                            target.scratch_registers[0],
                            taddress,
                            mycontext)
                        mycontext.set_register_value(
                            target.scratch_registers[0],
                            taddress)
                        ninstr += target.load(
                            target.scratch_registers[0],
                            taddress,
                            mycontext
                        )
                        building_block.add_init(ninstr)
                        warmed.append(taddress)

                    idx = (idx + 1) % len(self._addresses)

                if instr.access_storage_with_update:
                    for memoperand in instr.memory_operands():
                        for operand in memoperand.operands:
                            if operand.descriptor.type.address_base:
                                building_block.context.set_register_value(
                                    operand.value, memoperand.address
                                )
                                instr.add_allow_register(operand.value)

    def check(self, building_block, target):
        """

        :param building_block:
        :param target:

        """
        raise NotImplementedError


class FixMemoryReferencesPass(microprobe.passes.Pass):
    """FixMemoryReferencesPass pass.

    """

    _ref_with_updates_map = {}

    def __init__(self, reset_registers=False):
        """

        """
        super(FixMemoryReferencesPass, self).__init__()

        self._description = "Fix the memory references avoid segmenation" \
            "faults during execution"
        self._reset_regs = reset_registers

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param dummy_target:

        """

        fixlist = {}
        set_regs = []

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                LOG.debug("Fixing %s", instr)
                LOG.debug("Asm: %s", instr.assembly())
                set_regs += [
                    elem
                    for elem in instr.sets()
                    if elem not in set_regs and elem in
                    target.address_registers
                ]

                if not instr.access_storage:
                    LOG.debug("Skip %s", instr)
                    continue

                if instr.access_storage_with_update:
                    LOG.debug("Fixing access storage with update")
                    self._fix_with_update(instr, target)

                for memoperand in instr.memory_operands():

                    LOG.debug("Memory operand: %s", memoperand)

                    if memoperand.is_agen:
                        continue

                    max_value = 0
                    base_operand_value = None
                    index_operand_value = None

                    for operand in memoperand.operands:

                        LOG.debug("Operand: %s", operand)

                        if operand.type.address_relative:
                            LOG.debug("Skip relative")
                            continue

                        if operand.value is not None:

                            LOG.debug("Value is: %s", operand.value)

                            if operand.type.immediate:
                                descriptor = OperandDescriptor(
                                    OperandConst(
                                        operand.type.name,
                                        operand.type.description,
                                        operand.value,
                                        aim=operand.type.address_immediate,
                                        arel=operand.type.address_relative
                                    ),
                                    operand.is_input,
                                    operand.is_output
                                )

                                max_value = abs(operand.value)

                            else:

                                descriptor = OperandDescriptor(
                                    OperandConstReg(
                                        operand.type.name,
                                        operand.type.description,
                                        operand.value,
                                        operand.type.address_base,
                                        operand.type.address_index,
                                        operand.type.float, operand.type.vector
                                    ), operand.is_input, operand.is_output
                                )

                                if operand.type.address_base:
                                    base_operand_value = operand.value

                                if operand.type.address_index:
                                    index_operand_value = operand.value

                            if not self._reset_regs:
                                LOG.debug("Set descriptor")
                                operand.set_descriptor(descriptor)

                    LOG.debug("Max value: %d", max_value)
                    LOG.debug("Base operand: %s", base_operand_value)
                    LOG.debug("Index operand: %s", index_operand_value)

                    if (
                        base_operand_value is None and
                        index_operand_value is None
                    ):
                        LOG.debug("All none. Skip")
                        continue

                    if base_operand_value is not None:
                        key = (base_operand_value, index_operand_value)
                    else:
                        key = (index_operand_value, None)

                    LOG.debug("KEY: %s - %s", key[0], key[1])

                    # A. Switch if the base register has been used as index and
                    # the index has not been used as base
                    # B. Switch if the index operand has been used as base and
                    # the base operand not has been used as base
                    # C. Otherwise choose the key direction that minimizes the
                    # required modifications afterwards
                    if (
                        key[1] is not None and key[0] in [
                            elem[1]
                            for elem in fixlist.keys() if elem[1] is not None
                        ] and key[1] not in [
                            elem[0] for elem in fixlist.keys()
                        ]
                    ):
                        LOG.debug(
                            "Switch: base used as index, "
                            "index not used as base")
                        key = (key[1], key[0])
                        base_operand_value, index_operand_value = \
                            index_operand_value, base_operand_value

                    elif (
                        key[1] is not None and
                        key[1] in [elem[0] for elem in fixlist.keys()] and
                        key[0] not in [elem[0] for elem in fixlist.keys()]
                    ):
                        LOG.debug(
                            "Swtich: index used as base, "
                            "and base not used as base")
                        key = (key[1], key[0])
                        base_operand_value, index_operand_value = \
                            index_operand_value, base_operand_value
                    elif (
                        key[1] is not None and key in fixlist and
                        (key[1], key[0]) in fixlist
                    ):
                        LOG.debug("Both already")
                        if len(fixlist[key][2]) < \
                                len(fixlist[(key[1], key[0])][2]):
                            LOG.debug("Switch to minimize")
                            key = (key[1], key[0])
                            base_operand_value, index_operand_value = \
                                index_operand_value, base_operand_value

                    max_length = max(
                        memoperand.possible_lengths(
                            building_block.context
                        )
                    )

                    LOG.debug("KEY: %s - %s", key[0], key[1])
                    LOG.debug("Base: %s", base_operand_value)
                    LOG.debug("Index: %s", index_operand_value)
                    LOG.debug("Max value: %d", max_value)
                    LOG.debug("Max length: %d", max_length)

                    if max_value == 0 and max_length == 0:
                        raise MicroprobeCodeGenerationError(
                            "Unable to fix memory reference"
                        )

                    if key in fixlist:
                        LOG.debug("Key already in fix list")
                        fixlist[key] = (
                            fixlist[key][0], fixlist[key][1],
                            fixlist[key][2] + [memoperand],
                            max(fixlist[key][3], max_value),
                            max(fixlist[key][4], max_length)
                        )
                    else:
                        LOG.debug("New key added to the fix list")
                        fixlist[key] = (
                            base_operand_value, index_operand_value,
                            [memoperand], max_value, max_length
                        )

        fix_number = 0
        fix_base_registers = []
        fix_index_registers = []
        switch_registers = []

        max_length_dict = {}
        max_value_dict = {}
        for key, value in fixlist.items():
            base_operand, max_value, max_length = (
                value[0], value[3], value[4]
            )

            if base_operand in max_length_dict:
                max_length_dict[base_operand] = max(
                    max_length, max_length_dict[base_operand]
                )
            else:
                max_length_dict[base_operand] = max_length

            if base_operand in max_value_dict:
                max_value_dict[base_operand] = max(
                    max_value, max_value_dict[base_operand]
                )
            else:
                max_value_dict[base_operand] = max_value

        for value in fixlist.values():

            base_operand_value, index_operand_value, \
                memoperands, max_value, max_length = value

            max_value = max_value_dict[base_operand_value]
            max_length = max_length_dict[base_operand_value]

            LOG.debug("Fix: %s", fix_number)
            LOG.debug("Base operand: %s", base_operand_value)
            LOG.debug("Index_operand: %s", index_operand_value)
            LOG.debug("Memory operands:")
            for memoperand in memoperands:
                LOG.debug("--> %s", memoperand)
            LOG.debug("Maximum value: %s", max_value)
            LOG.debug("Maximum length: %s", max_length)

            if (
                base_operand_value is not None and
                base_operand_value not in fix_base_registers
            ):

                if base_operand_value in fix_index_registers:

                    if base_operand_value not in switch_registers:
                        switch_registers.append(base_operand_value)

                else:

                    variable = microprobe.code.var.VariableArray(
                        "MEMACCESS_FIX_%s" % fix_number,
                        "char", (max_value + max_length) * 2,
                        align=max_length
                    )

                    building_block.register_var(
                        variable, building_block.context
                    )

                    building_block.add_init(
                        target.set_register_to_address(
                            base_operand_value, variable.address + max_value +
                            max_length, building_block.context
                        )
                    )

                    building_block.context.set_register_value(
                        base_operand_value,
                        variable.address + max_value + max_length
                    )

                    fix_base_registers.append(base_operand_value)

                    fix_number = fix_number + 1

                    if base_operand_value not in \
                            building_block.context.reserved_registers:

                        building_block.context.add_reserved_registers(
                            [base_operand_value]
                        )

            if (
                index_operand_value is not None and
                index_operand_value not in fix_index_registers
            ):

                if index_operand_value in fix_base_registers:

                    if index_operand_value not in switch_registers:
                        switch_registers.append(index_operand_value)

                else:

                    building_block.add_init(
                        target.set_register(
                            index_operand_value, 0, building_block.context
                        )
                    )

                    building_block.context.set_register_value(
                        index_operand_value, 0
                    )

                    fix_index_registers.append(index_operand_value)

                    if index_operand_value not in \
                            building_block.context.reserved_registers:

                        building_block.context.add_reserved_registers(
                            [index_operand_value]
                        )

        if not self._reset_regs:
            return

        free_regs = [
            elem
            for elem in target.address_registers
            if elem not in set_regs and elem not in fix_base_registers
        ]

        if len(fix_index_registers) == 0:
            if len(free_regs) > 0:
                reg = free_regs[0]
                free_regs = free_regs[1:]
            else:
                pregs = [
                    elem
                    for elem in target.address_registers
                    if elem not in fix_base_registers
                ]
                if len(pregs) == 0:
                    raise MicroprobeCodeGenerationError(
                        "Not enough free registers"
                    )
                reg = pregs[0]

            building_block.add_init(
                target.set_register(
                    reg, 0, building_block.context
                )
            )

            building_block.context.set_register_value(reg, 0)

            fix_index_registers.append(reg)

            if reg not in \
                    building_block.context.reserved_registers:

                building_block.context.add_reserved_registers([reg])

        assert set(fix_index_registers).isdisjoint(set(fix_base_registers))

        fix_registers = set(fix_index_registers + fix_base_registers)
        fix_index_registers = sorted(fix_index_registers)
        fix_base_registers = sorted(fix_base_registers)

        for bbl in building_block.cfg.bbls:

            for instr in bbl.instrs:

                set_registers = set(instr.sets())

                if not set_registers.isdisjoint(fix_registers):

                    registers = set_registers.intersection(fix_registers)
                    for operand in instr.operands():
                        if operand.value in registers and operand.is_output:
                            operand.unset_value()

                for operand in instr.operands():

                    if operand.type.immediate or operand.value is None:
                        continue
                    elif (
                        operand.value in switch_registers and
                        operand.type.address_base
                    ):
                        valid_values = fix_base_registers
                    elif (
                        operand.value in switch_registers and
                        operand.type.address_index
                    ):
                        valid_values = fix_index_registers
                    else:
                        continue

                    assert len(valid_values) > 0

                    operand.unset_value()

                    valid_values = list(
                        set(valid_values).intersection(
                            set(operand.type.values())
                        )
                    )

                    assert len(valid_values) > 0

                    descriptor = OperandDescriptor(
                        OperandReg(
                            operand.type.name, operand.type.description,
                            valid_values, operand.type.address_base,
                            operand.type.address_index, operand.type.float,
                            operand.type.vector
                        ), operand.is_input, operand.is_output
                    )
                    operand.set_descriptor(descriptor)

                if instr.access_storage:

                    base_operand = None
                    index_operand = None
                    sorted_base_operand_values = None
                    sorted_index_operand_values = None
                    needs_fix = False
                    fix_only_base = False

                    for operand in instr.operands():
                        if operand.type.immediate:
                            continue
                        if operand.type.address_relative:
                            continue
                        if operand.type.address_base:
                            base_operand = operand
                            sorted_base_operand_values = \
                                sorted(base_operand.type.values())
                        if operand.type.address_index:
                            index_operand = operand
                            sorted_index_operand_values = \
                                sorted(index_operand.type.values())

                    if base_operand is None and index_operand is None:
                        continue

                    elif base_operand is not None and index_operand is None:

                        if base_operand.value is None:
                            if sorted_base_operand_values != \
                                    fix_base_registers:
                                needs_fix = True
                                fix_only_base = True

                        elif base_operand.value not in fix_base_registers:
                            raise NotImplementedError(
                                "Base operand not none and not in base "
                                " registers. "
                            )

                    elif (
                        base_operand is not None and index_operand is not None
                    ):

                        if (
                            base_operand.value is None and
                            index_operand.value is None
                        ):

                            if not (
                                (
                                    sorted_base_operand_values ==
                                    fix_base_registers and
                                    sorted_index_operand_values ==
                                    fix_index_registers
                                ) or (
                                    sorted_base_operand_values ==
                                    fix_index_registers and
                                    sorted_index_operand_values ==
                                    fix_base_registers
                                )
                            ):

                                needs_fix = True

                        elif base_operand.value is None:
                            # yapf: disable
                            if not (
                                (
                                    index_operand.value in
                                    fix_index_registers and
                                    sorted_base_operand_values ==
                                    fix_base_registers
                                ) or (
                                    index_operand.value in
                                    fix_base_registers and
                                    sorted_base_operand_values ==
                                    fix_index_registers
                                )
                            ):
                                # yapf: enable
                                needs_fix = True

                        elif index_operand.value is None:
                            # yapf: disable
                            if not (
                                (
                                    base_operand.value in
                                    fix_base_registers and
                                    sorted_index_operand_values ==
                                    fix_index_registers
                                ) or (
                                    base_operand.value in
                                    fix_index_registers and
                                    sorted_index_operand_values ==
                                    fix_base_registers
                                )
                            ):
                                # yapf: enable
                                needs_fix = True

                        else:
                            # yapf: disable
                            if not (
                                (
                                    base_operand.value in
                                    fix_base_registers and
                                    index_operand.value in fix_index_registers
                                ) or (
                                    base_operand.value in
                                    fix_index_registers and
                                    index_operand.value in fix_base_registers
                                )
                            ):
                                # yapf: enable
                                needs_fix = True

                        if needs_fix:

                            assert len(fix_base_registers) > 0

                            base_operand.unset_value()

                            valid_values = list(
                                set(fix_base_registers).intersection(
                                    set(base_operand.type.values())
                                )
                            )

                            assert len(valid_values) > 0

                            descriptor = OperandDescriptor(
                                OperandReg(
                                    base_operand.type.name,
                                    base_operand.type.description,
                                    valid_values,
                                    base_operand.type.address_base,
                                    base_operand.type.address_index,
                                    base_operand.type.float,
                                    base_operand.type.vector
                                ), base_operand.is_input,
                                base_operand.is_output
                            )
                            base_operand.set_descriptor(descriptor)

                        if needs_fix and not fix_only_base:

                            assert len(fix_index_registers) > 0

                            index_operand.unset_value()

                            valid_values = list(
                                set(fix_index_registers).intersection(
                                    set(index_operand.type.values())
                                )
                            )

                            assert len(valid_values) > 0

                            descriptor = OperandDescriptor(
                                OperandReg(
                                    index_operand.type.name,
                                    index_operand.type.description,
                                    valid_values,
                                    index_operand.type.address_base,
                                    index_operand.type.address_index,
                                    index_operand.type.float,
                                    index_operand.type.vector
                                ), index_operand.is_input,
                                index_operand.is_output
                            )
                            index_operand.set_descriptor(descriptor)

                    elif base_operand is None and index_operand is not None:
                        raise NotImplementedError(
                            "Unknown index operand without base operand.\n"
                            " Instruction: %s \n"
                            " Assembly: %s" % (instr, instr.assembly())
                        )

    @classmethod
    def _fix_with_update(cls, instr, target):

        if instr.architecture_type in cls._ref_with_updates_map:
            new_arch_type = cls._ref_with_updates_map[instr.architecture_type]
        else:
            new_arch_type = cls._similar_type_without_update(instr, target)
            cls._ref_with_updates_map[instr.architecture_type] = new_arch_type

        assert new_arch_type != instr.architecture_type
        assert new_arch_type.access_storage_with_update is False

        LOG.debug("Orig arch type: %s", instr.architecture_type)
        operand_values = [op.value for op in instr.operands()]
        instr.set_arch_type(new_arch_type)
        instr.set_operands(operand_values)
        LOG.debug("New arch type: %s", instr.architecture_type)

    @staticmethod
    def _similar_type_without_update(instr, target):

        orig_arch_type = instr.architecture_type
        arch_types = [
            arch_type
            for arch_type in target.instructions.values()
            if arch_type.access_storage and
            not arch_type.access_storage_with_update
        ]

        arch_types = [
            arch_type
            for arch_type in arch_types
            if arch_type != orig_arch_type and len(arch_type.operands) == len(
                orig_arch_type.operands
            ) and len(
                arch_type.implicit_operands
            ) == len(
                orig_arch_type.implicit_operands
            ) and len(arch_type.memory_operand_descriptors) == len(
                orig_arch_type.memory_operand_descriptors
            )
        ]

        LOG.debug("Similar architecture types found:")
        for arch_type in arch_types:
            LOG.debug(arch_type)

        def _check_memory_operand(arch_type):
            for op1, op2 in zip(
                orig_arch_type.memory_operand_descriptors,
                arch_type.memory_operand_descriptors
            ):
                for elem in [
                    'is_load', 'is_store', 'is_agen', 'is_prefetch',
                    'is_branch_target', 'bit_rate'
                ]:

                    if getattr(op1, elem) != getattr(op2, elem):
                        return False
            return True

        def _check_properties(arch_type):
            prop_orig = orig_arch_type.properties
            prop_new = arch_type.properties

            del prop_orig['access_storage_with_update']
            del prop_new['access_storage_with_update']

            return prop_orig == prop_new

        arch_types = [
            arch_type
            for arch_type in arch_types
            if _check_memory_operand(arch_type) and _check_properties(
                arch_type
            )
        ]

        LOG.debug(
            "Similar architecture types found after filtering"
            " the properties and the memory operands:"
        )
        for arch_type in arch_types:
            LOG.debug(arch_type)

        if len(arch_types) == 0:
            raise MicroprobeCodeGenerationError(
                "Unable to fix instruction type '%s'." %
                instr.architecture_type
            )

        if len(arch_types) > 1:
            LOG.debug("Multiple instruction types found")
            LOG.debug("Take the most closest one (by name)")

            def sort_key(elem):
                return len(longest_common_substr(
                    instr.architecture_type.mnemonic, elem.mnemonic))

            arch_types = sorted(arch_types, key=sort_key, reverse=True)

        return arch_types[0]


class GenericMemoryStreamsPass(microprobe.passes.Pass):
    """GenericMemoryStreamsPass pass.

    """

    def __init__(
        self,
        model,
        strict=True,
        loadsonly=False,
        storesonly=False,
        switch_stores=False,
        shift_streams=0,
        warmstores=False
    ):
        """

        :param model:
        :type model:
        :param strict:
        :type strict:
        :param loadsonly:
        :type loadsonly:
        :param storesonly:
        :type storesonly:
        :param switch_stores:
        :type switch_stores:
        """

        super(GenericMemoryStreamsPass, self).__init__()

        self._strict = strict
        self._model = model

        self._lo = loadsonly
        self._so = storesonly
        self._switch = switch_stores
        self._warmstores = warmstores
        items = []
        sets_dict = {}

        all_ratio = 0
        accum = 100

        shift = 0

        if len(self._model) == 0:
            raise MicroprobeCodeGenerationError(
                "No streams specified for the memory model pass"
            )

        for elem in self._model:
            if len(elem) == 5:
                elem.append(0)

        for sid, size, ratio, stride, streams, shuffle in self._model:

            items.append((sid, ratio))
            all_ratio += ratio
            accum = accum - ratio

            if stride == 0:
                values = [0]
            else:
                values = [(value + shift) for value in range(0, size, stride)]
                values = microprobe.utils.distrib.shuffle(values, shuffle)

            sets_dict[sid] = values
            shift += shift_streams

            if streams <= 0:
                raise MicroprobeCodeGenerationError(
                    "Number of streams should be 1 "
                    "or higher on stream id: %s" % sid
                )

        self._sets = sets_dict
        self._func = regular_seq(dict(items))

        self._description = "Create generic streams: %s" % self._model

    def __call__(self, building_block, target):
        """

        :param building_block:
        :param dummy_target:

        """

        descriptors = {}
        descriptors2 = {}

        for sid, size, ratio, dummy_stride, streams, shuffle in self._model:

            var = microprobe.code.var.VariableArray(
                "stream%d" % sid, "char", size, align=4 * 1024
            )

            building_block.register_var(var, building_block.context)

            if ratio > 0:
                reg_basel = []
                reg_idxl = []
                calc_instrsl = []
                for stream in range(0, streams):
                    reg_base = target.get_register_for_address_arithmetic(
                        building_block.context
                    )
                    building_block.context.add_reserved_registers([reg_base])
                    reg_basel.append(reg_base)
                    reg_idx = target.get_register_for_address_arithmetic(
                        building_block.context
                    )
                    building_block.context.add_reserved_registers([reg_idx])
                    reg_idxl.append(reg_idx)
                    calc_instrsl.append([])

                last_instr = None
                count = 0
                reduced = False
                max_value = 0

                module = len(self._sets[sid])

                descriptors[sid] = [
                    var, reg_basel, [0] * streams, reg_idxl, [0] * streams,
                    calc_instrsl, last_instr, count, module, reduced,
                    max_value, 0
                ]
                descriptors2[sid] = [0]

        for var, reg_basel, reg_base_vall, reg_idxl, reg_idx_vall, \
                calc_instrsl, last_instr, count, module, reduced, \
                max_value, sind in six.itervalues(descriptors):

            for sind in range(0, len(reg_base_vall)):
                building_block.add_init(
                    target.set_register_to_address(
                        reg_basel[sind],
                        Address(base_address=var),
                        building_block.context
                    )
                )

                building_block.context.set_register_value(
                    reg_basel[sind],
                    Address(
                        base_address=var))
                # building_block.context.add_reserved_registers([reg_idxl[sind]])

                building_block.add_init(
                    target.set_register(
                        reg_idxl[sind], 0, building_block.context
                    )
                )

                instr = target.set_register(
                        reg_idxl[sind], 0, building_block.context
                    )[0]

                building_block.context.set_register_value(reg_idxl[sind], 0)
                # building_block.context.add_reserved_registers([reg_idxl[sind]])

        zeros = None
        ones = None
        extra_switch = []
        warmed = []
        prev_instr = None

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                is_load = False
                is_store = False
                is_agen = False
                is_branch = False

                for moperand in instr.memory_operands():
                    if moperand.is_load:
                        is_load = True
                    if moperand.is_store:
                        is_store = True
                    if moperand.is_agen:
                        is_agen = True
                    if moperand.is_branch_target:
                        is_branch = True

                if is_agen:
                    continue

                if is_branch:
                    continue

                if instr.access_storage and not (
                    is_store and self._lo
                ) and not (
                    is_load and self._so
                ):

                    mcomp = self._func()
                    var, reg_basel, reg_base_vall, reg_idxl, reg_idx_vall,\
                        calc_instrsl, last_instr, count, module, reduced,\
                        max_value, sind = descriptors[mcomp]

                    reg_base = reg_basel[sind]
                    reg_base_val = reg_base_vall[sind]
                    reg_idx = reg_idxl[sind]
                    reg_idx_val = reg_idx_vall[sind]
                    calc_instrs = calc_instrsl[sind]

                    if reg_base not in \
                            building_block.context.reserved_registers:
                        building_block.context.add_reserved_registers(
                            [reg_base]
                        )

                    if reg_idx not in \
                            building_block.context.reserved_registers:
                        building_block.context.add_reserved_registers(
                            [reg_idx]
                        )

                    if module > 0:
                        value = self._sets[mcomp][count % (module)]
                    else:
                        value = 0

                    max_value = max(value, max_value)

                    memoperand = instr.memory_operands()[0]
                    address = Address(
                        base_address=var,
                        displacement=value
                    )

                    instr.add_comment("Address: %s" % address)
                    try:
                        memoperand.set_address(address, building_block.context)
                        reg_base_val_new = reg_base_val
                        reg_idx_val_new = reg_idx_val
                        tinstrs = []
                        new_instrs = []
                        if mcomp > 0:
                            prev_instr = instr
                    except MicroprobeCodeGenerationError:

                        diff = address.displacement - \
                            reg_base_val - reg_idx_val

                        tinstrs = []
                        new_instrs = []

                        # sometimes we don't have index operands,
                        # so we should update the base value
                        has_index = len([operand for operand in
                                         instr.operands() if
                                         operand.type.address_index]) > 0

                        if has_index:
                            update_reg = reg_idx
                        else:
                            update_reg = reg_base

                        add_instructions = target.add_to_register(
                            update_reg, diff
                        )

                        if len(add_instructions) > 0:
                            for elem in calc_instrs:
                                ains = add_instructions[0]
                                if ains.name != elem.name:
                                    continue

                                values = [
                                    oper.value for oper in ains.operands()
                                ]
                                elem.set_operands(values)
                                elem.add_comment(
                                    "Reused to compute address: %s" % address
                                )

                                tinstrs.append(elem)
                                prev_instr = elem

                                add_instructions = add_instructions[1:]
                                if len(add_instructions) == 0:
                                    break

                        if len(add_instructions) > 0:
                            bbl.insert_instr(
                                add_instructions, before=instr,
                                after=prev_instr
                            )
                            new_instrs = add_instructions
                            for elem in add_instructions:
                                elem.add_comment(
                                    "Added to compute address: %s" % address
                                )

                        building_block.context.set_register_value(
                            update_reg,
                            building_block.context.get_register_value(
                                update_reg) +
                            diff
                        )

                        memoperand.set_address(
                            address,
                            building_block.context)

                        if has_index:
                            reg_base_val_new = reg_base_val
                            reg_idx_val_new = reg_idx_val + diff
                        else:
                            reg_base_val_new = reg_base_val + diff
                            reg_idx_val_new = reg_idx_val

                    count = count + 1

                    if (self._warmstores and memoperand.is_store and
                            address not in warmed):
                        # Warm stores
                        mycontext = target.wrapper.context()
                        ninstr = target.set_register_to_address(
                            target.scratch_registers[0],
                            address,
                            mycontext)
                        mycontext.set_register_value(
                            target.scratch_registers[0],
                            address)
                        ninstr += target.load(
                            target.scratch_registers[0],
                            address,
                            mycontext
                        )
                        building_block.add_init(ninstr)
                        warmed.append(address)

                    # values = target.generate_address(
                    #   value, instr, reg_base, reg_base_val, reg_idx,
                    #    reg_idx_val, calc_instrs
                    # )

                    # reg_base_val_new, reg_idx_val_new,\
                    #    tinstrs, new_instrs = values

                    for key, value in descriptors.items():
                        if key == mcomp:

                            reg_base_vall[sind] = reg_base_val_new
                            reg_idx_vall[sind] = reg_idx_val_new

                            if (
                                reg_base_val == reg_base_val_new and
                                reg_idx_val == reg_idx_val_new
                            ):

                                calc_instrsl[sind] = []
                                sind = (sind + 1) % len(reg_base_vall)
                                descriptors[mcomp] = [
                                    var, reg_basel, reg_base_vall, reg_idxl,
                                    reg_idx_vall, calc_instrsl, instr, count,
                                    module, reduced, max_value, sind
                                ]
                            else:
                                calc_instrsl[sind] = []
                                sind = (sind + 1) % len(reg_base_vall)
                                descriptors[mcomp] = [
                                    var, reg_basel, reg_base_vall, reg_idxl,
                                    reg_idx_vall, calc_instrsl, instr, count,
                                    module, reduced, max_value, sind
                                ]

                        # Remove touched instructions from all the streams
                        # of all memory components (if we touched a
                        # instruction)
                        for stream in range(0, len(descriptors[key][1])):
                            calc_instrs_new = []

                            for calcins in descriptors[key][5][stream]:

                                if len(tinstrs) == 0:
                                    calc_instrs_new.append(calcins)
                                    continue

                                if hex(id(calcins)) in [
                                    hex(id(ttt)) for ttt in tinstrs
                                ]:
                                    continue

                                calc_instrs_new.append(calcins)

                            descriptors[key][5][stream] = calc_instrs_new

                    if len(tinstrs) > 0:
                        for tinstr in tinstrs:
                            tinstr.add_allow_register(reg_base)
                            tinstr.add_allow_register(reg_idx)

                    if len(new_instrs) > 0:
                        for tinstr in new_instrs:
                            tinstr.add_allow_register(reg_base)
                            tinstr.add_allow_register(reg_idx)

                    if self._switch and memoperand.is_store:
                        dcount = descriptors2[mcomp][0]

                        if zeros is None:
                            zeros = {}

                        if ones is None:
                            ones = {}

                        valid_values = set(
                            instr.operands()[0].type.values()
                        ).difference(
                            set(building_block.context.reserved_registers)
                        )

                        try:
                            valid_value = list(valid_values)[-1]
                        except IndexError:
                            raise MicroprobeCodeGenerationError(
                                "Unable to implement memory switch. "
                                "Not enough free registers available"
                            )

                        valid_type = valid_value.type

                        if valid_type not in zeros:
                            building_block.context.add_reserved_registers(
                                [valid_value]
                            )
                            value = int("5" * (valid_type.size // 4), 16)
                            building_block.add_init(
                                target.set_register(
                                    valid_value, value, building_block.context
                                )
                            )
                            zeros[valid_value.type] = valid_value
                            valid_zero = valid_value

                            if valid_value.type.name == "FPR":
                                extra_reg = target.registers[
                                    "FPR%d" % (
                                        int(
                                            valid_value.assembly()
                                        ) + 1
                                    )
                                ]
                                building_block.add_init(target.set_register(
                                    extra_reg, value, building_block.context))
                                building_block.context.add_reserved_registers(
                                    [extra_reg]
                                )
                                extra_reg2 = target.registers[
                                    "VSR%d" % (
                                        int(
                                            valid_value.assembly()
                                        )
                                    )
                                ]
                                building_block.context.add_reserved_registers(
                                    [extra_reg2]
                                )

                        else:
                            valid_zero = zeros[valid_type]

                        valid_values = set(
                            instr.operands()[0].type.values()
                        ).difference(
                            set(building_block.context.reserved_registers)
                        )
                        valid_value = list(valid_values)[-1]
                        valid_type = valid_value.type

                        if valid_type not in ones:
                            building_block.context.add_reserved_registers(
                                [valid_value]
                            )
                            value = int("a" * (valid_type.size // 4), 16)
                            building_block.add_init(
                                target.set_register(
                                    valid_value, value, building_block.context
                                )
                            )
                            ones[valid_value.type] = valid_value
                            valid_one = valid_value

                            if valid_value.type.name == "FPR":
                                extra_reg = target.registers[
                                    "FPR%d" % (
                                        int(
                                            valid_value.assembly()
                                        ) + 1
                                    )
                                ]
                                building_block.add_init(target.set_register(
                                    extra_reg, value, building_block.context))
                                building_block.context.add_reserved_registers(
                                    [extra_reg]
                                )
                                extra_reg2 = target.registers[
                                    "VSR%d" % (
                                        int(
                                            valid_value.assembly()
                                        )
                                    )
                                ]
                                building_block.context.add_reserved_registers(
                                    [extra_reg2]
                                )

                        else:
                            valid_one = ones[valid_type]

                        if (dcount % 2) == 0:
                            instr.operands()[0].set_value(valid_zero)
                            instr.add_allow_register(valid_zero)

                        else:
                            instr.operands()[0].set_value(valid_one)
                            instr.add_allow_register(valid_one)

                        for mkreg in instr.sets():
                            if not instr.allows(mkreg):
                                instr.add_allow_register(valid_one)

                            if mkreg not in \
                                    building_block.context.reserved_registers:
                                building_block.context.add_reserved_registers(
                                    [mkreg]
                                )

                        extra_switch.extend(
                            instr.operands()[0].uses()
                        )

                        extra_switch.extend(
                            instr.operands()[0].sets()
                        )

                        descriptors2[mcomp][0] = dcount + 1

                else:

                    # TODO: This is not target generic, fix
                    if instr.name == "ADDI_V0":
                        for key, value in descriptors.items():
                            for stream in range(0, len(descriptors[key][1])):
                                descriptors[key][5][stream].append(instr)

        if zeros is not None and ones is not None:
            for register in set(
                    list(
                        zeros.values()) +
                    list(
                        ones.values()) +
                    extra_switch):
                new_instrs = target.negate_register(
                    register,
                    building_block.context)
                building_block.add_fini(new_instrs)

                if register not in building_block.context.reserved_registers:
                    building_block.context.add_reserved_registers([register])

        blabel = None
        blabelins = None
        emptycontext = target.wrapper.context()

        for sid, size, ratio, stride, streams, shuffle in self._model:
            var, reg_basel, reg_base_vall, reg_idxl, reg_idx_vall,\
                calc_instrs, last_instr, count, module, reduced,\
                max_value, sind = descriptors[sid]

            if max_value == 0:
                continue

            if max_value * 2 >= size:
                # We go through the stream more than two
                # times. Reseting to beginning

                for sind in range(0, len(reg_base_vall)):
                    reg_base = reg_basel[sind]
                    reg_base_val = reg_base_vall[sind]
                    reg_idx = reg_idxl[sind]
                    reg_idx_val = reg_idx_vall[sind]

                    # new_instrs = target.load_var_address(reg_base, var)

                    new_instrs = target.set_register_to_address(
                        reg_base,
                        Address(
                            base_address=var),
                        emptycontext)

                    if blabel is not None:
                        if new_instrs[0].label is not None:
                            label = new_instrs[0].label
                            new_operand = InstructionAddress(
                                base_address=label
                            )
                            old_operand = InstructionAddress(
                                base_address=blabel
                            )
                            for operand in blabelins.operands():
                                if operand.value == old_operand:
                                    operand.set_value(new_operand)
                                    break
                        else:
                            new_instrs[0].set_label(blabel)

                        blabel = None
                        blabelins = None

                    assert len(new_instrs) > 0
                    new_instrs = new_instrs + \
                        target.set_register(reg_idx, 0, emptycontext)
                    for new_instr in new_instrs:
                        new_instr.add_allow_register(reg_base)
                        new_instr.add_allow_register(reg_idx)
                    building_block.add_fini(new_instrs)
                continue

            # Always set the index register to zero
            # which is the initial state
            for sind in range(0, len(reg_base_vall)):
                reg_base = reg_basel[sind]
                reg_base_val = reg_base_vall[sind]
                reg_idx = reg_idxl[sind]
                reg_idx_val = reg_idx_vall[sind]

                new_instrs = target.set_register(reg_idx, 0, emptycontext)
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)
                    new_instr.add_allow_register(reg_idx)
                building_block.add_fini(new_instrs)

            if blabel is not None:
                new_instrs[0].set_label(blabel)
                blabel = None
                blabelins = None

            # Get a register to count the number of iterations
            reg_constant = target.get_register_for_address_arithmetic(
                building_block.context
            )
            # Reserve it
            building_block.context.add_reserved_registers([reg_constant])

            # Set it to zero during initialization
            new_instrs = target.set_register(
                reg_constant,
                0,
                building_block.context)
            for new_instr in new_instrs:
                new_instr.add_allow_register(reg_constant)

            building_block.add_init(new_instrs)

            # Add one to the counter
            new_instrs = target.add_to_register(reg_constant, 1)
            for new_instr in new_instrs:
                new_instr.add_allow_register(reg_constant)
            building_block.add_fini(new_instrs)

            # Update base register
            for sind in range(0, len(reg_base_vall)):
                reg_base = reg_basel[sind]
                reg_base_val = reg_base_vall[sind]
                reg_idx = reg_idxl[sind]
                reg_idx_val = reg_idx_vall[sind]

                new_instrs = target.add_to_register(
                    reg_base, max_value-reg_base_val+stride
                )
                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)

                building_block.add_fini(new_instrs)

            # Add the conditional branch
            guard = (size // (max_value + stride))

            # Set the label for in case the next component needs it
            blabel = "stream%sguard" % sid

            new_instrs = target.compare_and_branch(
                reg_constant, guard, "<", blabel, building_block.context
            )
            blabelins = new_instrs[-1]

            building_block.add_fini(new_instrs)

            # Init everything: reg base to the start of the array var,
            # register idx to zero and register of the constant to zero.

            for sind in range(0, len(reg_base_vall)):
                reg_base = reg_basel[sind]
                reg_base_val = reg_base_vall[sind]
                reg_idx = reg_idxl[sind]
                reg_idx_val = reg_idx_vall[sind]

                new_instrs = target.set_register_to_address(
                    reg_base,
                    Address(
                        base_address=var),
                    emptycontext)

                assert len(new_instrs) > 0

                new_instrs = new_instrs + \
                    target.set_register(reg_constant, 0, emptycontext)

                for new_instr in new_instrs:
                    new_instr.add_allow_register(reg_base)
                    new_instr.add_allow_register(reg_idx)
                building_block.add_fini(new_instrs)

        # Add a nop with a label, for the last mcomp that needs to jump
        # somewhere if it wants to skip the reset code.
        if blabel is not None:
            new_instr = target.nop()
            new_instr.set_label(blabel)
            building_block.add_fini([new_instr])
            blabel = None
            blabelins = None


class SetMemoryOperandByOpcodePass(microprobe.passes.Pass):
    """SetMemoryOperandByOpcodePass pass.

    """

    def __init__(self, opcode, operand_pos, value):
        """

        :param opcode:
        :param operand_pos:
        :param value:

        """
        super(SetMemoryOperandByOpcodePass, self).__init__()
        self._description = "Set memory operand %d of instructions with " \
                            "opcode " \
                            "'%s' to value: '%s'" % (operand_pos, opcode,
                                                     value)
        self._opcode = opcode
        self._pos = operand_pos
        self._base_value = value

        if not isinstance(value, list):

            def idem():
                """Return a constant."""
                return value

            valuef = idem

        else:

            valuef = getnextf(itertools.cycle(value))

        self._value = valuef

    def __call__(self, building_block, dummy_target):
        """

        :param building_block:
        :param dummy_target:

        """
        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:
                if instr.name == self._opcode:
                    value = self._value()
                    if instr.memory_operands()[self._pos].is_branch_target:
                        if not isinstance(value, InstructionAddress):
                            if instr.label != "":
                                value = InstructionAddress(
                                    base_address=instr.label,
                                    displacement=value
                                )
                            else:
                                value = InstructionAddress(
                                    base_address="ins_id_%s" % id(instr),
                                    displacement=value
                                )
                                instr.set_label("ins_id_%s" % id(instr))

                        assert isinstance(value, InstructionAddress)
                    else:
                        if not isinstance(value, Address):
                            value = Address(
                                base_address="data",
                                displacement=value
                            )

                        assert isinstance(value, Address)

                    instr.memory_operands()[
                        self._pos
                    ].set_address(
                        value, building_block.context
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
                if instr.opcode == self._opcode:
                    if instr.memory_operands()[
                        self._pos
                    ].value != self._value():
                        return False

        return True


class InitializeMemoryDecorator(microprobe.passes.Pass):
    """InitializeMemoryDecoratorPass pass.

    """

    _error_class = collections.namedtuple("LateErrorClass", ['next'])

    def __init__(self, default=None):

        self._default = default
        self._description = "Initialize memory decorator. Default: %s" \
            % self._default

    def __call__(self, building_block, dummy_target):

        default = None

        for bbl in building_block.cfg.bbls:
            for instr in bbl.instrs:

                is_agen = False

                for moperand in instr.memory_operands():
                    if moperand.is_agen:
                        is_agen = True

                if is_agen:
                    continue

                if not instr.access_storage and instr.mnemonic != "raw":
                    continue

                if "MA" in instr.decorators:
                    value = instr.decorators['MA']['value']
                    value = self._normalize_value(
                        instr, value[:],
                        building_block
                    )
                    instr.decorators["MA"]["value"] = value
                else:
                    if default is None:
                        default = self._normalize_value(instr,
                                                        self._default,
                                                        building_block)
                    instr.add_decorator("MA", default)

    def _normalize_value(self, instr, value, building_block):

        if value is None:

            def function():
                raise MicroprobeCodeGenerationError(
                    "No memory access decorator specified for instruction '%s'"
                    " at %s" % (instr.assembly(), instr.address)
                )

            return self._error_class(function)

        elif not isinstance(value, list):
            value = [value]

        data_segment = 0
        if building_block.context.data_segment is not None:
            data_segment = building_block.context.data_segment

        value_list = []
        for elem in value:

            if elem is None:
                continue

            if isinstance(elem, six.integer_types):
                value_list.append(
                    Address(
                        base_address="data",
                        displacement=elem -
                        data_segment))
            elif isinstance(elem, Address):
                value_list.append(elem)
            elif isinstance(elem, str):

                int_elem = [int(selem, 0) for selem in elem.split("-")]

                for elem2 in range_to_sequence(*int_elem):
                    value_list.append(
                        Address(
                            base_address="data",
                            displacement=elem2 -
                            data_segment))
            else:
                raise MicroprobeCodeGenerationError(
                    "Unable to interpret decorator MA decorator"
                    " with value '%s' in instruction '%s' at %s" %
                    (value, instr.assembly(), instr.address))

        value = itertools.cycle(value_list)
        return value
