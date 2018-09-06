======================
Continuous integration
======================

Currently, we have implemented a Continuous Integration methodology
in a Jenkins or Travis instance. It executes the following scripts in the
following order:

#. Scripts to check the correctness of the code convenstions and
   the documentation generation:

   #. ``./dev_tools/ci/code_conventions_001_pycodestyle.sh``
   #. ``./dev_tools/ci/code_conventions_002_pylint.sh``
   #. ``./dev_tools/ci/code_conventions_003_documentation.sh``

#. Scripts to tests the functionality of Microprobe:

   #. ``./dev_tools/ci/test_001_end2end_tools.sh``
   #. ``./dev_tools/ci/test_002_end2end_examples.sh``
   #. ``./dev_tools/ci/test_003_end2end_targets.sh``
   #. ``./dev_tools/ci/test_004_unittest.sh``

#. Scripts to test the build of the pip distribution:

   #. ``./dev_tools/ci/build_001_distribution.sh``

#. Scripts to test the built pip distribution is correct:

   #. ``./dev_tools/ci/test_deploy_001_install.sh``

#. Scripts to deploy the new built distribution on public
   repositories (PyPI & GitHub).

   #. ``./dev_tools/ci/deploy_001.sh``

Check the aforementioned scripts plus the ``Jenkinsfile``/
or ``.travis.yml`` file to understand all the details of the
process implemented. You can execute all these scripts locally
(except the last one --the deployment--) to validate the
correctness of your code before creating a patch or a pull
requests in GitHub. We provide a script to do so::

   > ./dev_tools/ci/check_ci.sh

