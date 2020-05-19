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
""":mod:`~.code` generation package

A package for driving the code generation process within microprobe.
The sub-packages of this package are:

- :mod:`~.wrapper`: Code generation wrapper package.

and the modules in this package are the following:

- :mod:`~.address`: Address object module.
- :mod:`~.bbl`: Building block object module.
- :mod:`~.benchmark`: Benchmark object module.
- :mod:`~.cfg`: Control flow graph object module.
- :mod:`~.context`: Context object module.
- :mod:`~.ins`: Instruction object module.
- :mod:`~.var`: Variable objects module.

Visit their respective documentation for further details.

This package defines the benchmark synthesizer (:class:`~.Synthesizer`),
which is the main object driving the code generation process in the
microprobe framework. This object provides a simple interface to define
the set of passes (:class:`~.Pass`) to apply to generate a benchmark
(:class:`~.Benchmark`).
"""

# Futures
from __future__ import absolute_import

# Built-in modules
import copy
import datetime
import os
import warnings
from time import time

# Third party modules
import six

# Own modules
import microprobe.code.wrapper
import microprobe.target
import microprobe.utils as cmd
from microprobe import MICROPROBE_RC
from microprobe.code.address import InstructionAddress
from microprobe.code.benchmark import benchmark_factory
from microprobe.code.context import Context
from microprobe.code.ins import Instruction
from microprobe.exceptions import MicroprobeCodeGenerationError, \
    MicroprobeError, MicroprobeValueError
from microprobe.utils.imp import get_all_subclasses, load_source
from microprobe.utils.logger import DEBUG, get_logger, set_log_level
from microprobe.utils.misc import OrderedDict, findfiles, Progress, \
    open_generic_fd

# Local modules


# Constants

#: Package logger (:class:`~.logging.Logger`).
LOG = get_logger(__name__)

_INIT = True
__all__ = ['get_wrapper', 'Synthesizer']


# Functions
def get_wrapper(name):
    """Return a wrapper object with name *name*.

    Look for the registered :class:`~.Wrapper` objects and return and instance
    of the one with name equal *name*.

    :param name: Wrapper name
    :type name: :class:`~.str`
    :return: A wrapper instance
    :rtype: :class:`~.Wrapper`
    """

    global _INIT  # pylint: disable=global-statement
    if _INIT:
        _INIT = False
        _import_default_wrappers()

    if MICROPROBE_RC['debugwrapper']:
        name = "DebugBinaryDouble"

    for elem in get_all_subclasses(microprobe.code.wrapper.Wrapper):
        if elem.__name__ == name:
            return elem

    raise MicroprobeValueError(
        "Unknown wrapper '%s'. Available wrappers are: %s. " % (
            name, [
                elem.__name__
                for elem in get_all_subclasses(
                    microprobe.code.wrapper.Wrapper
                )
            ]
        )
    )


def _import_default_wrappers():
    modules = []
    LOG.debug('Wrapper paths: %s', MICROPROBE_RC['wrapper_paths'])
    for path in MICROPROBE_RC['wrapper_paths']:
        for module in findfiles([path], r"wrappers/.+\.py$", full=True):
            module = os.path.realpath(module)
            if module not in modules:
                modules.append(module)

    lmodules = -1
    while lmodules != len(modules):
        lmodules = len(modules)
        for module_file in modules[:]:

            name = (os.path.basename(module_file).replace(".py", ""))

            if name == "__init__":
                continue

            if name in microprobe.code.wrapper.__dict__:
                raise MicroprobeError(
                    "Wrapper module name '%s' in '%s' already loaded. " %
                    (name, module_file)
                )

            try:
                module = load_source(name, module_file)
            except MicroprobeValueError:
                continue

            microprobe.code.wrapper.__dict__[name] = module
            modules.remove(module_file)

            current_wrappers = \
                [elem.__name__ for elem in
                 get_all_subclasses(microprobe.code.wrapper.Wrapper)
                 ]

            if len(current_wrappers) != len(set(current_wrappers)):
                for elem in set(current_wrappers):
                    current_wrappers.remove(elem)
                overwrapper = list(set(current_wrappers))[0]
                raise MicroprobeError(
                    "Module name '%s' in '%s' overrides an existing wrapper "
                    "with name '%s'" % (name, module_file, overwrapper)
                )


# Classes
class Synthesizer(object):
    """Benchmark synthesizer.

    The Synthesizer objects are in charge of creating :class:`~.Benchmark`
    objects based on a set of passes that have been previously defined.

    The typical workflow will be as follow. User instantiates the synthesizer,
    specifying also the :class:`~.Target` and the :class:`~.Wrapper`, which are
    required to know the target properties as well as how the code should be
    translated to the final representation. Then a set of :class:`~.Pass` are
    registered using the :meth:`add_pass` method. This passes will be applied
    in the provided order on a empty :class:`~.Benchmark` object when the
    :meth:`~.synthesize` method is called. Finally, the generated benchmark
    can be saved to disk by using the :meth:`~.save` method. A snippet of
    code of this process would be like:

    .. code:: python

        synthesizer =  Synthesizer(...)  # Instantiate object
        synthesizer.add_pass(...)        # Add transformation passes
        ...
        synthesizer.add_pass(...)
        synthesizer.synthesize(...)      # Apply the passes and generate a
                                         # benchmark
        synthesizer.save(...)            # Save the benchmark

    The default structure of the benchmarks being synthesized is as follows:

    #. ``extra_raw['FILE_HEADER']`` contents
    #. ``wrapper.headers()`` contents
    #. **<global variable declarations>**
    #. ``wrapper.start_main()`` contents
    #. ``extra_raw['CODE_HEADER']`` contents
    #. **<global variable initializations>**
    #. ``wrapper.post_var()`` contents
    #. **<benchmark initialization code>**
    #. ``wrapper.start_loop()`` contents
    #. **<benchmark building blocks>**
    #. **<benchmark finalization code>**
    #. ``wrapper.end_loop()`` contents
    #. ``extra_raw['CODE_FOOTER']`` contents
    #. ``wrapper.end_main()`` contents
    #. ``wrapper.footer()`` contents
    #. ``extra_raw['FILE_FOOTER']`` contents

    where:

    - ``extra_raw`` contents are provided at initialization (see below)
    - wrapper object methods provide the decoupling between output format and
      the benchmark synthesizer
    - **variables** and **building block** contents are populated by the passes
      being applied

    .. note::

        - This default code layout can be changed by sub-classing this class.

        - The :meth:`~.synthesize` method and the :meth:`~.save` method can be
          called multiple times to generate and save multiple benchmarks in
          case that some of the passes have some random behavior. Otherwise,
          it does not make sense ;).
    """

    def __init__(self, target, wrapper, **kwargs):
        """Create a Synthesizer object.

        :param target: Benchmark target
        :type target: :class:`~.Target`
        :param wrapper: Wrapper object defining the output format
        :type wrapper: :class:`~.Wrapper`
        :param value: Default immediate value used for non-initialized
                      immediates (Default: random)
        :type value: :class:`~.int`
        :param no_scratch: Disable automatic declaration of scratch variables
                           required for code generation support
                           (Default: False)
        :type no_scratch: :class:`~.bool`
        :param extra_raw: List of extra raw strings to be embedded in the final
                          output
        :type extra_raw: :class:`~.list` of elements containing a ``name`` and
                         a ``value`` attributes (Default: [])
        :return: A Synthesizer instance
        :rtype: :class:`~.Synthesizer`
        """
        self._target = target

        # Extra arguments
        self._no_scratch = kwargs.get("no_scratch", False)
        self._raw = kwargs.get("extra_raw", {})
        self._immediate = kwargs.get("value", "random")
        self._threads = kwargs.get("threads", 1)

        self._passes = {}
        for idx in range(1, self._threads + 1):
            self._passes[idx] = []

        self._current_thread = 1

        if isinstance(wrapper, list):
            if len(wrapper) != self._threads:
                raise MicroprobeCodeGenerationError(
                    "Number of wrappers provided (%d) is different from "
                    "number of threads (%d) specified in the Synthesizer" %
                    (len(wrapper), self._threads)
                )
            self._wrappers = wrapper
        else:
            self._wrappers = [wrapper]
            for dummy in range(1, self._threads):
                new_wrapper = copy.deepcopy(wrapper)
                self._wrappers.append(new_wrapper)

        for wrapper in self._wrappers:
            wrapper.set_target(target)

    @property
    def target(self):
        """Target attribute (:class:`~.Target`)."""
        return self._target

    @property
    def wrapper(self):
        """Wrapper attribute (:class:`~.Wrapper`)."""
        return self._wrappers[self._current_thread - 1]

    def add_pass(self, synth_pass, thread_idx=None):
        """Add a pass to the benchmark synthesizer.

        :param synth_pass: New pass to add.
        :type synth_pass: :class:`~.Pass`
        """

        if thread_idx is None:
            self._passes[self._current_thread].append(synth_pass)
        else:
            if not 1 <= thread_idx <= self._threads + 1:
                raise MicroprobeCodeGenerationError(
                    "Unknown thread id: %d (min: 1, max: %d)"
                    % (thread_idx, self._threads + 1)
                )
            self._passes[thread_idx].append(synth_pass)

    def save(self, name, bench=None):
        """Save a benchmark to disk.

        Save a synthesized benchmark to disk. If bench is not specified a
        benchmark is automatically synthesized using the :meth:`~.synthesize`
        method.

        :param name: Filename to save
        :type name: :class:`~.str`
        :param bench: Benchmark to save (Default value = None)
        :type bench: :class:`~.Benchmark`
        """
        if bench is None:
            bench = self.synthesize()

        starttime = time()
        program_str = self._wrap(bench)
        endtime = time()
        LOG.info(
            "Pass wrap: %s", (
                datetime.timedelta(
                    seconds=endtime - starttime
                )
            )
        )

        outputname = self._wrappers[0].outputname(name)
        fdx = open_generic_fd(outputname, 'wb')

        for elem in program_str:
            if isinstance(elem, six.string_types) and six.PY3:
                elem = elem.encode()
            fdx.write(elem)
        fdx.close()

    def synthesize(self):
        """Synthesize a benchmark.

        Synthesize a benchmark based on the set of passes that have been
        added using the :meth:`add_pass` method.

        :return: A new synthesized benchmark
        :rtype: :class:`~.Benchmark`
        """
        LOG.info("Start synthesizing benchmark")

        # Create benchmark object
        bench = benchmark_factory(threads=self._threads)

        for thread_id in range(1, self._threads + 1):

            LOG.info("Start synthesizing benchmark thread %d" % thread_id)

            self.set_current_thread(thread_id)
            self._target.set_wrapper(self._wrappers[thread_id - 1])
            bench.set_current_thread(thread_id)

            # Set default context -- environment context
            bench.set_context(self.wrapper.context())
            # bench.set_context(Context())

            for var in self.wrapper.required_global_vars():
                bench.register_var(var, bench.context)

            if not self._no_scratch:
                bench.register_var(self._target.scratch_var, bench.context)

            # Basic context
            reserved_registers = self._target.reserved_registers
            reserved_registers += self.wrapper.reserved_registers(
                reserved_registers, self._target
            )

            bench.context.add_reserved_registers(reserved_registers)

            if MICROPROBE_RC['debugpasses']:
                previous_level = LOG.getEffectiveLevel()
                set_log_level(DEBUG)

            passes = self._passes[thread_id]

            starttime = time()
            for idx, step in enumerate(passes):

                LOG.info("Applying pass %03d: %s", idx,
                         step.__class__.__name__)

                if MICROPROBE_RC['verbose']:
                    cmd.cmdline.print_info("Applying pass %03d: %s" %
                                           (idx, step.__class__.__name__))

                step(bench, self.target)
                bench.add_pass_info(step.info())
                endtime = time()
                LOG.debug(
                    "Applying pass %03d: %s : Execution time: %s",
                    idx,
                    step.__class__.__name__,
                    datetime.timedelta(seconds=endtime - starttime)
                )
                starttime = endtime

            starttime = time()
            for idx, step in enumerate(passes):

                LOG.info("Checking pass %03d: %s", idx,
                         step.__class__.__name__)
                try:
                    pass_ok = step.check(bench, self.target)
                except NotImplementedError:
                    LOG.warning(
                        "Checking pass %03d: %s. NOT IMPLEMENTED", idx,
                        step.__class__.__name__
                    )
                    pass_ok = False

                endtime = time()

                if not pass_ok:
                    LOG.warning(
                        "Checking pass %03d: %s. Test result: FAIL", idx,
                        step.__class__.__name__
                    )

                    bench.add_warning(
                        "Pass %03d: %s did not pass the check test" %
                        (idx, step.__class__.__name__)
                    )
                else:
                    LOG.debug(
                        "Checking pass %03d: %s. Test result: OK", idx,
                        step.__class__.__name__
                    )

                LOG.debug(
                    "Checking pass %03d: %s : Execution time: %s",
                    idx,
                    step.__class__.__name__,
                    datetime.timedelta(seconds=endtime - starttime)
                )

                starttime = endtime

            if MICROPROBE_RC['debugpasses']:
                set_log_level(previous_level)

        return bench

    def _wrap_thread(self, bench, thread_id):
        """Wrap a thread in benchmark.

        This function wraps a thread using the synthesizer wrapper. The
        wrapping process is the process of converting the internal
        representation of the benchmark to the actual string that is written
        to a file, adding the necessary prologue and epilogue bytes of
        data.

        :param bench: Benchmark to wrap.
        :type bench: :class:`~.Benchmark`
        :param thread_id: Thread to wrap
        :type thread_id : :class:`~.int`
        :return: A string representation of the benchmark
        :rtype: :class:`~.str`
        """

        bench.set_current_thread(thread_id)
        self.set_current_thread(thread_id)

        thread_str = []
        thread_str.append(self.wrapper.start_main())

        if 'CODE_HEADER' in self._raw:
            thread_str.append("\n" + self._raw['CODE_HEADER'] + "\n")

        for var in bench.registered_global_vars():
            if var.value is None:
                thread_str.append(
                    self.wrapper.init_global_var(
                        var, self._immediate
                    )
                )

        thread_str.append(self.wrapper.post_var())

        # TODO: This is hardcoded and assumes a loop always. Needs to be more
        # generic: pass a building block to a wrapper and it automatically
        # returns the required string

        for instr in bench.init:
            thread_str.append(self.wrapper.wrap_ins(instr))

        code_str = []
        first = True
        instr = None
        for bbl in bench.cfg.bbls:
            for instr in bbl.instrs:
                if first is True:
                    first = False
                    if bench.init:
                        code_str.append(
                            self.wrapper.start_loop(
                                instr, bench.init[0]
                            )
                        )
                    else:
                        code_str.append(self.wrapper.start_loop(instr, instr))
                code_str.append(self.wrapper.wrap_ins(instr))

        if instr is None:
            raise MicroprobeCodeGenerationError(
                "No instructions found in benchmark"
            )

        thread_str.extend(code_str)

        for instr in bench.fini:
            thread_str.append(self.wrapper.wrap_ins(instr))

        last_instr = instr
        thread_str.append(self.wrapper.end_loop(last_instr))

        if 'CODE_FOOTER' in self._raw:
            thread_str.append("\n" + self._raw['CODE_FOOTER'] + "\n")

        thread_str.append(self.wrapper.end_main())

        return thread_str

    def _wrap(self, bench):
        """Wrap a benchmark.

        This function wraps a benchmark using the synthesizer wrapper. The
        wrapping process is the process of converting the internal
        representation of the benchmark to the actual string that is written
        to a file, adding the necessary prologue and epilogue bytes of
        data.

        :param bench: Benchmark to wrap.
        :type bench: :class:`~.Benchmark`
        :return: A string representation of the benchmark
        :rtype: :class:`~.str`
        """

        for wrapper in self._wrappers:
            wrapper.set_benchmark(bench)

        self.set_current_thread(1)

        bench_str = []

        if 'FILE_HEADER' in self._raw:
            bench_str.append(self._raw['FILE_HEADER'] + "\n")

        bench_str.append(self.wrapper.headers())

        for thread_id in range(1, self._threads + 1):
            self.set_current_thread(thread_id)
            bench.set_current_thread(thread_id)
            for var in sorted(
                    bench.registered_global_vars(),
                    key=lambda x: x.address
            ):
                bench_str.append(self.wrapper.declare_global_var(var))

        for thread_id in range(1, self._threads + 1):
            bench_str.extend(self._wrap_thread(bench, thread_id))

        self.set_current_thread(1)
        bench_str.append(self.wrapper.footer())

        if 'FILE_FOOTER' in self._raw:
            bench_str.append("\n" + self._raw['FILE_FOOTER'] + "\n")

        bench_str = [elem for elem in bench_str if elem != ""]
        return bench_str

    def set_current_thread(self, idx):
        """ """
        self._current_thread = idx
        if not 1 <= idx <= self._threads + 1:
            raise MicroprobeCodeGenerationError(
                "Unknown thread id: %d (min: 1, max: %d)" % (idx,
                                                             self._threads + 1)
            )


class TraceSynthesizer(Synthesizer):
    """Trace synthesizer.

    The Trace Synthesizer objects are in charge of creating
    :class:`~.Benchmark` objects based on a set of passes that have been
    previously defined. They operate in a similar fashion as
    :class:`~.Synthesizer` objects but differ on how the benchmark
    object is dumped. In this case a dynamic execution trace is dumped (i.e.
    an execution trace). Required dynamic information should be provided
    by the registered passes.

    The default structure of the benchmarks being synthesized is as follows:

    #. ``wrapper.headers()`` contents
    #. Dynamic execution trace from:
      -  **<benchmark initialization code>**
      -  **<benchmark building blocks>**
      -  **<benchmark finalization code>**
    """

    def __init__(self, target, wrapper, **kwargs):
        super(TraceSynthesizer, self).__init__(target, wrapper,
                                               **kwargs)

        self._show_trace = kwargs.get("show_trace", False)
        self._maxins = kwargs.get("maxins", 10000)

    def _wrap(self, bench):
        """Wrap a benchmark.

        This function wraps a benchmark using the synthesizer wrapper. The
        wrapping process is the process of converting the internal
        representation of the benchmark to the actual string that is written
        to a file, adding the necessary prologue and epilogue bytes of
        data.

        :param bench: Benchmark to wrap.
        :type bench: :class:`~.Benchmark`
        :return: A string representation of the benchmark
        :rtype: :class:`~.str`
        """
        self.wrapper.set_benchmark(bench)

        bench_str = []
        bench_str.append(self.wrapper.headers())

        instructions = []
        instructions_dict = {}
        instructions_next_dict = {}

        for instr in bench.init:
            instructions.append(instr)

        for bbl in bench.cfg.bbls:
            for instr in bbl.instrs:
                instructions.append(instr)

        for instr in bench.fini:
            instructions.append(instr)

        for instr in instructions:
            instructions_dict[instr.address] = instr
            if (instr.branch or instr.syscall or instr.trap):
                instructions_next_dict[instr.address] = \
                    instr.decorators['NI']['value']
            else:
                instructions_next_dict[instr.address] = \
                    instr.address + instr.architecture_type.format.length

        instr = instructions[0]
        count = 0

        cmd.cmdline.print_info(
            "Maximum trace size: %s instructions " %
            self._maxins)

        progress = Progress(self._maxins, msg="Instructions generated:")

        while True:

            count = count + 1

            if count > self._maxins:
                cmd.cmdline.print_info(
                    "Max number of instructions (%d) reached. "
                    "Stoping trace generation." % self._maxins)
                break

            try:
                instr_address = instructions_next_dict[instr.address]
                if not isinstance(instr_address, InstructionAddress):
                    instr_address = next(instr_address)

                next_instr = instructions_dict[instr_address]

            except KeyError:
                cmd.cmdline.print_info(
                    "Jump to an unknown instruction in address "
                    "%s found. Stoping trace generation." %
                    instr_address)
                break

            progress()
            wrap_ins = self.wrapper.wrap_ins(instr,
                                             next_instr=next_instr,
                                             show=self._show_trace)

            bench_str.append(
                wrap_ins
            )

            instr = next_instr

        bench_str = [elem for elem in bench_str if elem != ""]
        return bench_str
