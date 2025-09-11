# Makefile for Sphinx documentation
#

# You can set these variables from the command line.
#SPHINXOPTS    = -a -E -n
SPHINXOPTS    = -n
SPHINXBUILD   = python `which sphinx-build`
PAPER         =
BUILDDIR      = build
ifeq ($(MAXJOBS),)
MAXJOBS := 1
endif

# Internal variables.
PAPEROPT_a4     = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS   = -q -d $(BUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) source

.PHONY: help clean html dirhtml singlehtml pickle json htmlhelp qthelp devhelp epub latex latexpdf text man changes linkcheck doctest cleantests cleanrst submodules_rm submodules_add updatetests subtests

all: html

autoapi:
	sphinx-apidoc -o ./source/_rsts/ -f -d 4 ../

cleanrst: cleantests
	rm -fr ./source/microprobe.*.rst

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html       to make standalone HTML files"
	@echo "  dirhtml    to make HTML files named index.html in directories"
	@echo "  singlehtml to make a single large HTML file"
	@echo "  pickle     to make pickle files"
	@echo "  json       to make JSON files"
	@echo "  htmlhelp   to make HTML files and a HTML help project"
	@echo "  qthelp     to make HTML files and a qthelp project"
	@echo "  devhelp    to make HTML files and a Devhelp project"
	@echo "  epub       to make an epub"
	@echo "  latex      to make LaTeX files, you can set PAPER=a4 or PAPER=letter"
	@echo "  latexpdf   to make LaTeX files and run them through pdflatex"
	@echo "  text       to make text files"
	@echo "  man        to make manual pages"
	@echo "  changes    to make an overview of all changed/added/deprecated items"
	@echo "  linkcheck  to check all external links for integrity"
	@echo "  doctest    to run all doctests embedded in the documentation (if enabled)"

clean: cleanrst
	-rm -rf $(BUILDDIR)/*
	-find . -name \.*.cache
	-find . -name \.*.lock
	$(MAKE) -j ${MAXJOBS} submodules_rm
	$(MAKE) -j ${MAXJOBS} submodules_rm

html: clean
	$(MAKE) -j ${MAXJOBS} submodules_rm
	$(MAKE) -j ${MAXJOBS} submodules_rm
	$(MAKE) -j ${MAXJOBS} submodules_add
	$(MAKE) -j ${MAXJOBS} updatetests
	RELEASE="$$(git rev-parse --abbrev-ref HEAD) $$(git rev-parse --short HEAD)" $(SPHINXBUILD) -j ${MAXJOBS} -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html -w error.log
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."
	$(MAKE) -j ${MAXJOBS} submodules_rm
	$(MAKE) -j ${MAXJOBS} submodules_rm

submodules_add:
	sh -c 'set -x; for elem in ../targets/*/doc/*.rst ; do if [ -f ./source/$$(basename $$elem) ]; then if [ ! -f ./source/$$(basename $$elem.orig) ] ; then cp ./source/$$(basename $$elem) ./source/$$(basename $$elem).orig; fi; cat $$elem >> ./source/$$(basename $$elem) ; fi; done;'
	sh -c 'set -x; for elem in ../targets/*/doc/*.rst ; do if [ ! -f ./source/$$(basename $$elem) ]; then cp -f $$elem ./source/ ; fi; done;'


submodules_rm:
	sh -c 'set -x; for elem in $$(ls ../targets/*/doc/*.rst | xargs -n1 basename | sort | uniq) ; do if [ -f ./source/$$elem ]; then if [ ! -f ./source/$$elem.orig ]; then if [ $$(git status ./source/$$elem | grep -c "Untracked") -eq 1 ]; then rm ./source/$$elem ; fi; else mv -f ./source/$$elem.orig  ./source/$$elem; fi ; fi; done;'

updatetests: test1 test4 test5 test6 subtests

cleantests:
	rm -fr ./source/examples_outputs
	mkdir -p ./source/examples_outputs/
	@echo Tests cleared

test1: ./source/examples_outputs/example_mp_objdump2mpt.mpt

./source/examples_outputs/example_mp_objdump2mpt.mpt: ./source/examples/example_mp_objdump2mpt.dump ../targets/generic/tools/mp_objdump2mpt.py
	rm -f ./source/examples_outputs/example_mp_objdump2mpt.mpt
	mkdir -p ./source/examples_outputs/
	mp_objdump2mpt.py -P ../targets/ -T riscv_v22-riscv_generic-riscv64_linux_gcc -O ./source/examples_outputs/example_mp_objdump2mpt.mpt -i ./source/examples/example_mp_objdump2mpt.dump -s microprobe.text --elf-abi

#test2: ./source/examples_outputs/example_mp_objdump2dma.dma
#
#./source/examples_outputs/example_mp_objdump2dma.dma: ./source/examples/example_mp_objdump2mpt.dump ../targets/generic/tools/mp_objdump2dma.py
#	rm -f ./source/examples_outputs/example_mp_objdump2dma.dma
#	mkdir -p ./source/examples_outputs/
#	mp_objdump2dma.py -O ./source/examples_outputs/example_mp_objdump2dma.dma -i ./source/examples/example_mp_objdump2mpt.dump

test4: ./source/examples_outputs/example_mp_mpt2test_out.c

./source/examples_outputs/example_mp_mpt2test_out.c: ../targets/riscv/tests/tools/mpt2test_test003.mpt ../targets/generic/tools/mp_mpt2test.py
	rm -f ./source/examples_outputs/example_mp_mpt2test*.c
	mkdir -p ./source/examples_outputs/
	mp_mpt2test.py -P ../targets/ -T riscv_v22-riscv_generic-riscv64_linux_gcc -t ../targets/riscv/tests/tools/mpt2test_test003.mpt -O ./source/examples_outputs/example_mp_mpt2test_out.c --endless

test5: ./source/examples_outputs/example_mp_c2mpt.mpt

./source/examples_outputs/example_mp_c2mpt.mpt: ../targets/riscv/tests/tools/c2mpt_test003.c ../targets/generic/tools/mp_c2mpt.py
	rm -f ./source/examples_outputs/example_mp_c2mpt.mpt
	mkdir -p ./source/examples_outputs/
	mp_c2mpt.py -T riscv_v22-riscv_generic-riscv64_linux_gcc -P ../targets -i ../targets/riscv/tests/tools/c2mpt_test003.c -O ./source/examples_outputs/example_mp_c2mpt.mpt --target-c-compiler riscv64-linux-gnu-gcc --target-objdump riscv64-linux-gnu-objdump --target-c-compiler-flags="-O3 -march=rv64gc"

test6: ./source/examples_outputs/example_mpt2trace.output

./source/examples_outputs/example_mpt2trace.output: ../targets/power/tests/tools/mpt2trace_test001.mpt  ../targets/power/tools/mp_mpt2trace.py
	rm -f ./source/examples_outputs/example_mpt2trace.*
	mkdir -p ./source/examples_outputs/
	mp_mpt2trace.py -T power_v310-power10-ppc64le_linux_gcc -P ../targets/ -t ../targets/power/tests/tools/mpt2trace_test001.mpt -O ./source/examples_outputs/example_mpt2trace.qt --default-memory-access-pattern 0x200000-0x200100-8 --show-trace 2> ./source/examples_outputs/example_mpt2trace.output
	sed -i -n '/0x/p' ./source/examples_outputs/example_mpt2trace.output

subtests:
	sh -c 'set -x; if [ $$(ls ../targets/*/doc/Makefile 2> /dev/null | wc -l) -gt 0 ] ; then for fmake in $$(ls ../targets/*/doc/Makefile | xargs -n1 dirname | sort | uniq) ; do $(MAKE) -j ${MAXJOBS} -C $$fmake tests; done; fi;'

htmlstrict: clean
	$(MAKE) -j ${MAXJOBS} updatetests
	$(SPHINXBUILD) -W -j ${MAXJOBS} -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	if [ ! -d $(BUILDDIR)/html/_images ] ; echo "No _images created" ; false ; fi;
	if [ ! -d $(BUILDDIR)/html/_modules ] ; echo "No _modules created" ; false ; fi;
	if [ ! -d $(BUILDDIR)/html/_sources ] ; echo "No _sources created" ; false ; fi;
	if [ ! -d $(BUILDDIR)/html/_static ] ; echo "No _static created" ; false ; fi;
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

sf: cleanrst
	$(SPHINXBUILD) -W -j 8 -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

sfw: cleanrst
	$(SPHINXBUILD) -W -j 8 -b html $(ALLSPHINXOPTS) $(BUILDDIR)/html
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

dirhtml:
	$(SPHINXBUILD) -W -b dirhtml $(ALLSPHINXOPTS) $(BUILDDIR)/dirhtml
	@echo
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/dirhtml."

singlehtml:
	$(SPHINXBUILD) -W -b singlehtml $(ALLSPHINXOPTS) $(BUILDDIR)/singlehtml
	@echo
	@echo "Build finished. The HTML page is in $(BUILDDIR)/singlehtml."

pickle:
	$(SPHINXBUILD) -W -b pickle $(ALLSPHINXOPTS) $(BUILDDIR)/pickle
	@echo
	@echo "Build finished; now you can process the pickle files."

json:
	$(SPHINXBUILD) -W -b json $(ALLSPHINXOPTS) $(BUILDDIR)/json
	@echo
	@echo "Build finished; now you can process the JSON files."

htmlhelp:
	$(SPHINXBUILD) -W -b htmlhelp $(ALLSPHINXOPTS) $(BUILDDIR)/htmlhelp
	@echo
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      ".hhp project file in $(BUILDDIR)/htmlhelp."

qthelp:
	$(SPHINXBUILD) -W -b qthelp $(ALLSPHINXOPTS) $(BUILDDIR)/qthelp
	@echo
	@echo "Build finished; now you can run "qcollectiongenerator" with the" \
	      ".qhcp project file in $(BUILDDIR)/qthelp, like this:"
	@echo "# qcollectiongenerator $(BUILDDIR)/qthelp/Microprobedoc.qhcp"
	@echo "To view the help file:"
	@echo "# assistant -collectionFile $(BUILDDIR)/qthelp/Microprobedoc.qhc"

devhelp:
	$(SPHINXBUILD) -W -b devhelp $(ALLSPHINXOPTS) $(BUILDDIR)/devhelp
	@echo
	@echo "Build finished."
	@echo "To view the help file:"
	@echo "# mkdir -p $$HOME/.local/share/devhelp/Microprobe"
	@echo "# ln -s $(BUILDDIR)/devhelp $$HOME/.local/share/devhelp/Microprobe"
	@echo "# devhelp"

epub:
	$(SPHINXBUILD) -W -b epub $(ALLSPHINXOPTS) $(BUILDDIR)/epub
	@echo
	@echo "Build finished. The epub file is in $(BUILDDIR)/epub."

latex:
	$(SPHINXBUILD) -W -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo
	@echo "Build finished; the LaTeX files are in $(BUILDDIR)/latex."
	@echo "Run \`make' in that directory to run these through (pdf)latex" \
	      "(use \`make latexpdf' here to do that automatically)."

latexpdf:
	$(SPHINXBUILD) -W -b latex $(ALLSPHINXOPTS) $(BUILDDIR)/latex
	@echo "Running LaTeX files through pdflatex..."
	make -C $(BUILDDIR)/latex all-pdf
	@echo "pdflatex finished; the PDF files are in $(BUILDDIR)/latex."

text:
	$(SPHINXBUILD) -W -b text $(ALLSPHINXOPTS) $(BUILDDIR)/text
	@echo
	@echo "Build finished. The text files are in $(BUILDDIR)/text."

man:
	$(SPHINXBUILD) -W -b man $(ALLSPHINXOPTS) $(BUILDDIR)/man
	@echo
	@echo "Build finished. The manual pages are in $(BUILDDIR)/man."

changes:
	$(SPHINXBUILD) -W -b changes $(ALLSPHINXOPTS) $(BUILDDIR)/changes
	@echo
	@echo "The overview file is in $(BUILDDIR)/changes."

linkcheck:
	$(SPHINXBUILD) -W -b linkcheck $(ALLSPHINXOPTS) $(BUILDDIR)/linkcheck
	@echo
	@echo "Link check complete; look for any errors in the above output " \
	      "or in $(BUILDDIR)/linkcheck/output.txt."

doctest:
	$(SPHINXBUILD) -W -b doctest $(ALLSPHINXOPTS) $(BUILDDIR)/doctest
	@echo "Testing of doctests in the sources finished, look at the " \
	      "results in $(BUILDDIR)/doctest/output.txt."
