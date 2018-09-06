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
""":mod:`microprobe.driver.genetic` module

"""

# Futures
from __future__ import absolute_import, division, print_function

# Built-in modules
import datetime
import math
import os
import random
import subprocess
import tempfile
import time as runtime

# Third party modules
import six
from six.moves import range

# Own modules
from microprobe.exceptions import MicroprobeError
from microprobe.utils.logger import get_logger

if six.PY2:
    # pylint: disable=E0401
    import pyevolve.G1DList  # @UnresolvedImport
    import pyevolve.GAllele  # @UnresolvedImport
    import pyevolve.GSimpleGA  # @UnresolvedImport
    import pyevolve.Initializators  # @UnresolvedImport
    import pyevolve.Mutators  # @UnresolvedImport
    # pylint: enable=E0401

# Constants
LOG = get_logger(__name__)
__all__ = ["GenericDriver", "ExecCmdDriver"]

# Functions


# Classes
class GenericDriver(object):
    """Class to represent a Generic DSE Driver."""

    def __init__(self,
                 eval_func,
                 target_score,
                 generations,
                 population,
                 params,
                 allele=False,
                 dummy_slots=False,
                 logfile=None, ):
        """

        :param eval_func:
        :param target_score:
        :param generations:
        :param population:
        :param params:
        :param allele:  (Default value = False)
        :param dummy_slots:  (Default value = False)

        """
        LOG.debug("Population size: %d", population)
        LOG.debug("Target score: %f", target_score)
        LOG.debug("Generations: %d", generations)

        if not six.PY2:
            raise NotImplementedError("Driver support only for Python2")

        self._allele = allele

        if allele:

            set_of_alleles = pyevolve.GAllele.GAlleles()

            length = 0
            self._params = []
            for param_values in params:
                pmin, pmax, pstep = param_values
                start = length

                for dummy_elem in range(0, int((pmax - pmin) // pstep)):
                    allele_range = pyevolve.GAllele.GAlleleRange(0, 1)
                    length += 1
                    set_of_alleles.add(allele_range)

                end = length
                self._params.append((pmin, pmax, pstep, start, end))

                genome = pyevolve.G1DList.G1DList(length)
                genome.setParams(allele=set_of_alleles)

                genome.mutator.set(pyevolve.Mutators.G1DListMutatorAllele)
                genome.initializator.set(
                    pyevolve.Initializators.G1DListInitializatorAllele)
                genome.crossover.set(
                    pyevolve.Crossovers.G1DListCrossoverSinglePoint)

        else:
            genome = pyevolve.G1DList.G1DList(len(params))
            mmin = min([m[0] for m in params])
            mmax = max([M[1] for M in params])
            genome.setParams(rangemin=mmin)
            genome.setParams(rangemax=mmax)
            genome.setParams(gauss_mu=(mmax - mmin) // 2)
            genome.setParams(gauss_mu=1)
            genome.setParams(gauss_sigma=1)
            genome.mutator.set(pyevolve.Mutators.G1DListMutatorRealGaussian)
            genome.initializator.set(
                pyevolve.Initializators.G1DListInitializatorReal)
            genome.crossover.set(self.max_min_cross_over)

        genome.evaluator.set(eval_func)

        genome.setParams(bestrawscore=target_score)
        genome.setParams(roundDecimal=2)

        ga_obj = pyevolve.GSimpleGA.GSimpleGA(genome)
        ga_obj.setGenerations(generations)
        ga_obj.setElitism(False)
        ga_obj.setMutationRate(0.5)
        ga_obj.terminationCriteria.set(pyevolve.GSimpleGA.RawScoreCriteria)
        ga_obj.setPopulationSize(population)
        ga_obj.setMinimax(pyevolve.Consts.minimaxType["maximize"])

        self._ga = ga_obj
        self._results = None
        if logfile is not None:
            if os.path.isfile(logfile):
                raise MicroprobeError("Log file '%s' already exist" % logfile)
            self._logfile_fd = open(logfile, 'w')

            header = "TIME, GENERATION,INDIVIDUAL,%s,SCORE" % ','.join(
                ['PARAM%03d' % elem for elem in range(0, len(params))])

            self._logfile_fd.write(header + "\n")
            pyevolve.logEnable()

            def _logging_callback(ga_engine):

                generation = ga_engine.getCurrentGeneration()
                line = "%f" % runtime.time()
                line += ",%03d" % generation
                line += ","

                for idx, elem in enumerate(ga_engine.getPopulation()):
                    pline = line + str(idx) + ","
                    pline += ",".join(
                        [str(param) for param in elem.genomeList]
                    )
                    pline += "," + str(elem.score)
                    self._logfile_fd.write(pline + "\n")

                return False

            self._ga.stepCallback.set(_logging_callback)

    def rejoinparams(self, chromosome):
        """

        :param chromosome:

        """

        if self._allele:
            params = []
            for pmin, dummy_pmax, pstep, start, end in self._params:
                params.append((sum(chromosome[start:end]) * pstep) + pmin)
            return params
        else:
            return chromosome

    def run(self, freq_stats):
        """

        :param freq_stats:

        """
        self._ga.evolve(freq_stats=freq_stats)
        self._results = self._ga.bestIndividual()

    def solution(self):
        """ """
        return self.rejoinparams(self._results.genomeList)

    def score(self):
        """ """
        return self._results.score

    @classmethod
    def max_min_cross_over(cls, dummy_genome, **args):
        """ Max min cross_over.

        :param dummy_genome: arguments
        :param args: arguments

        """
        sister = None
        brother = None
        g_mom = args["mom"]
        g_dad = args["dad"]

        if args["count"] >= 1:
            sister = g_mom.clone()
            sister.resetStats()

            for idx, dummy_elem in enumerate(sister):
                rand = random.randint(-1, 1)
                rand = rand * 0.33
                sister[idx] = ((g_dad[idx] + g_mom[idx]) // 2) + rand

        if args["count"] == 2:
            brother = g_dad.clone()
            brother.resetStats()

            for idx, dummy_elem in enumerate(brother):
                rand = random.randint(-1, 1)
                rand = rand * 0.33
                sister[idx] = ((g_dad[idx] + g_mom[idx]) // 2) + rand

        return (sister, brother)


class ExecCmdDriver(GenericDriver):
    """Class to represent a Command Line DSE Driver"""

    def __init__(self,
                 bench_factory,
                 target_score,
                 generations,
                 population,
                 cmd,
                 params,
                 logfile=None):
        """

        :param bench_factory:
        :param target_score:
        :param generations:
        :param population:
        :param cmd:
        :param params:

        """

        def eval_func_factory(function, cmd):
            """

            :param function:
            :param cmd:

            """

            def eval_func(chromosome):
                """

                :param chromosome:

                """

                result = []

                sol_eval = 1
                for iteration in range(0, sol_eval):

                    print("Iteration %s" % iteration)
                    file_fd, name = tempfile.mkstemp()
                    dirname = os.path.dirname(name)
                    fname = os.path.basename(name)
                    os.close(file_fd)

                    starttime = runtime.time()
                    print("Start generating...")
                    function(name, *self.rejoinparams(chromosome.genomeList))
                    print("End generating")
                    midtime = runtime.time()
                    print("Start evaluation...")
                    process = subprocess.Popen("%s %s" % (cmd, name),
                                               shell=True,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT)
                    line = process.stdout.readline(
                    )  # pylint: disable=E1101
                    print("End evaluation")
                    endtime = runtime.time()

                    print("Generated: %s" %
                          (datetime.timedelta(seconds=midtime - starttime)))
                    print("Evaluated: %s" %
                          (datetime.timedelta(seconds=endtime - midtime)))
                    print("Total: %s" %
                          (datetime.timedelta(seconds=endtime - starttime)))

                    try:
                        print("Line: '%s'" % line)
                        result.append(float(line))
                    except Exception:

                        print(Exception)
                        print("TODO: Fix exception handling")
                        exit(-1)

                        print("Got wrong line: %s" % line)
                        print("call:", cmd, name)
                        result.append(0)

                    for elem in os.listdir(dirname):
                        if elem.startswith(fname):
                            os.remove("%s/%s" % (dirname, elem))

                result = [math.sqrt(x) for x in result]
                # print chromosome
                # result = sum(chromosome.genomeList)

                result = sum(result) // sol_eval
                # print "Score: %f"%result, self.rejoinparams(
                # chromosome.genomeList)

                return result

            return eval_func

        eval_func = eval_func_factory(bench_factory, cmd)

        super(ExecCmdDriver, self).__init__(eval_func,
                                            target_score,
                                            generations,
                                            population,
                                            params,
                                            allele=False,
                                            logfile=logfile)
