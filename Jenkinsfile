#!/usr/bin/env groovy

def handleCheckout = {
  retry(3) {
    if (params.BUILD_TYPE == 'stable' && env.GIT_BRANCH == 'origin/devel')
    {
      sh 'echo Merging devel into master'
      checkout scm
      git branch: 'master'
      sh 'git merge origin/devel'
    }
    else
    {
      sh 'echo Using default checkout policy'
      checkout scm
    }
    sh 'if [ -x "$MP_SETUP_SCRIPT" ]; then $MP_SETUP_SCRIPT; fi;'
  }
}

pipeline {

  agent any

  environment {
    BUILD_TYPE = "${params.BUILD_TYPE}"
  }

  stages {
    stage('Code Conventions') { 
      steps{
        parallel( 
          "Pycodestyle" : { 
            node('linux') {
              timeout(time: 10, unit: 'MINUTES') {
                script { handleCheckout() }
                sh 'PYTHON_VERSION=2 $WORKSPACE/dev_tools/ci/code_conventions_001_pycodestyle.sh' 
                stash name: "pycodestyle2", includes: "pycodestyle2.out"
                sh '$WORKSPACE/dev_tools/ci/code_conventions_001_pycodestyle.sh -c' 
                sh 'PYTHON_VERSION=3 $WORKSPACE/dev_tools/ci/code_conventions_001_pycodestyle.sh' 
                stash name: "pycodestyle3", includes: "pycodestyle3.out"
                sh '$WORKSPACE/dev_tools/ci/code_conventions_001_pycodestyle.sh -c' 
              }
            }
          },
          "Pylint": { 
            node('linux') {
              timeout(time: 10, unit: 'MINUTES') {
                script { handleCheckout() }
                sh 'PYTHON_VERSION=2 $WORKSPACE/dev_tools/ci/code_conventions_002_pylint.sh' 
                stash name: "pylint2", includes: "pylint2.out"
                sh '$WORKSPACE/dev_tools/ci/code_conventions_002_pylint.sh -c' 
                sh 'PYTHON_VERSION=3 $WORKSPACE/dev_tools/ci/code_conventions_002_pylint.sh' 
                stash name: "pylint3", includes: "pylint3.out"
                sh '$WORKSPACE/dev_tools/ci/code_conventions_002_pylint.sh -c' 
              }
            }
          },
          "Documentation": { 
            node('linux') {
              timeout(time: 10, unit: 'MINUTES') {
                script { handleCheckout() }
                sh '$WORKSPACE/dev_tools/ci/code_conventions_003_documentation.sh' 
                stash name: "doc", includes: "doc.out"
                stash name: "html", includes: "doc/build/html/*"
                sh '$WORKSPACE/dev_tools/ci/code_conventions_003_documentation.sh -c' 
              }
            }
          }
        )
      } 
      post {
        always {
          unstash "pycodestyle2"
          unstash "pycodestyle3"
          unstash "pylint2"
          unstash "pylint3"
          unstash "doc"
          script { 
            if (params.BUILD_TYPE != 'stable') {
              ViolationsToGitHub([
                       commentOnlyChangedContent: true,
                       createCommentWithAllSingleFileComments: true,
                       gitHubUrl: '',
                       minSeverity: 'ERROR',
                       pullRequestId: env.CHANGE_ID,
                       repositoryName: env.JOB_NAME.split("/")[1],
                       repositoryOwner: '',
                       violationConfigs: [
                          [parser: 'FLAKE8', pattern: '.*/pycodestyle*\\.out$', reporter: 'dev_tools/ci/code_conventions_001_pycodestyle.sh'], 
                          [parser: 'PYLINT', pattern: '.*/pylint*\\.out$', reporter: 'dev_tools/ci/code_conventions_002_pylint.sh']
                          ]
                       ])
            }
          }
          warnings defaultEncoding: '', 
                   canRunOnFailed: true, 
                   excludePattern: '', 
                   failedNewAll: '3', 
                   failedNewHigh: '1', 
                   failedNewLow: '3', 
                   failedNewNormal: '2', 
                   failedTotalAll: '3', 
                   failedTotalHigh: '1', 
                   failedTotalLow: '3', 
                   failedTotalNormal: '2', 
                   healthy: '0', 
                   includePattern: '', 
                   messagesPattern: '', 
                   parserConfigurations: [[parserName: 'Pep8', pattern: 'pycodestyle*.out']],
                   unHealthy: '1', 
                   unstableNewAll: '0', 
                   unstableNewHigh: '0', 
                   unstableNewLow: '0', 
                   unstableNewNormal: '0', 
                   unstableTotalAll: '0', 
                   unstableTotalHigh: '0', 
                   unstableTotalLow: '0', 
                   unstableTotalNormal: '0', 
                   useStableBuildAsReference: true
          warnings defaultEncoding: '', 
                   canRunOnFailed: true, 
                   excludePattern: '', 
                   failedNewAll: '4000', 
                   failedNewHigh: '4000', 
                   failedNewLow: '4000', 
                   failedNewNormal: '4000', 
                   failedTotalAll: '4000', 
                   failedTotalHigh: '4000', 
                   failedTotalLow: '4000', 
                   failedTotalNormal: '4000', 
                   healthy: '0', 
                   includePattern: '', 
                   messagesPattern: '', 
                   parserConfigurations: [[parserName: 'PyLint', pattern: 'pylint*.out']], 
                   unHealthy: '4000', 
                   unstableNewAll: '4000', 
                   unstableNewHigh: '4000', 
                   unstableNewLow: '4000', 
                   unstableNewNormal: '4000', 
                   unstableTotalAll: '4000', 
                   unstableTotalHigh: '4000', 
                   unstableTotalLow: '4000', 
                   unstableTotalNormal: '4000', 
                   useStableBuildAsReference: true
          warnings defaultEncoding: '', 
                   canRunOnFailed: true, 
                   excludePattern: '', 
                   failedNewAll: '50', 
                   failedNewHigh: '50', 
                   failedNewLow: '50', 
                   failedNewNormal: '50', 
                   failedTotalAll: '50', 
                   failedTotalHigh: '50', 
                   failedTotalLow: '50', 
                   failedTotalNormal: '50', 
                   healthy: '0', 
                   includePattern: '', 
                   messagesPattern: '', 
                   parserConfigurations: [[parserName: 'Sphinx-build', pattern: 'doc.out']], 
                   unHealthy: '5', 
                   unstableNewAll: '50', 
                   unstableNewHigh: '50', 
                   unstableNewLow: '50', 
                   unstableNewNormal: '50', 
                   unstableTotalAll: '50', 
                   unstableTotalHigh: '50', 
                   unstableTotalLow: '50', 
                   unstableTotalNormal: '50', 
                   useStableBuildAsReference: true
          milestone label: "Code Conventions", ordinal: 1
        }
      }
    }  

    stage('Fast Functional Tests') { 
      when {
        expression { 
          (params.BUILD_TYPE != 'stable'
          &&
          (currentBuild.result == null || currentBuild.result == 'SUCCESS'))
        }
      }
      steps{
        parallel( 
          "Testing Tools" : { 
            node('linux') {
              timeout(time: 60, unit: 'MINUTES') {
                script { handleCheckout() }
                sh '''
                  rm -f test_tools*.xml
                  PYTHON_VERSION=2 $WORKSPACE/dev_tools/ci/test_001_end2end_tools.sh
                  PYTHON_VERSION=3 $WORKSPACE/dev_tools/ci/test_001_end2end_tools.sh
                  '''
                stash name: "tools", includes: "tests_tools*.xml"
                // stash name: "ctools", includes: "cover_tools.xml"
                sh '$WORKSPACE/dev_tools/ci/test_001_end2end_tools.sh -c'
              }
            }
          }, 
          "Testing Examples" : { 
            node('linux') {
              timeout(time: 60, unit: 'MINUTES') {
                script { handleCheckout() }
                sh '''
                  rm -f test_examples*.xml
                  PYTHON_VERSION=2 $WORKSPACE/dev_tools/ci/test_002_end2end_examples.sh
                  PYTHON_VERSION=3 $WORKSPACE/dev_tools/ci/test_002_end2end_examples.sh
                  '''
                stash name: "examples", includes: "tests_examples*.xml"
                // stash name: "cexamples", includes: "cover_examples.xml"
                sh '$WORKSPACE/dev_tools/ci/test_002_end2end_examples.sh -c'
              }
            }
          }, 
          "Testing Targets" : { 
            node('linux') {
              timeout(time: 60, unit: 'MINUTES') {
                script { handleCheckout() }
                sh '''
                  rm -f test_targets*.xml
                  PYTHON_VERSION=2 $WORKSPACE/dev_tools/ci/test_003_end2end_targets.sh
                  PYTHON_VERSION=3 $WORKSPACE/dev_tools/ci/test_003_end2end_targets.sh
                  '''
                stash name: "targets", includes: "tests_targets*.xml"
                // stash name: "ctargets", includes: "cover_targets.xml"
                sh '$WORKSPACE/dev_tools/ci/test_003_end2end_targets.sh -c'
              }
            }
          }, 
          "Unit Tests": { 
            node('linux') {
              timeout(time: 60, unit: 'MINUTES') {
                script { handleCheckout() }
                sh '$WORKSPACE/dev_tools/ci/test_004_unittest.sh' 
                // stash name: "unittests", includes: "test_targets.xml"
                // stash name: "cunittests", includes: "cover_targets.xml"
                sh '$WORKSPACE/dev_tools/ci/test_004_unittest.sh -c' 
              }
            }
          }
        )
      }
      post {
        always {
          unstash "tools"
          unstash "examples"
          unstash "targets"
          // unstash "ctools"
          // unstash "cexamples"
          // unstash "ctargets"
          junit allowEmptyResults: true, testResults: 'tests_*.xml'
          // step([$class: 'CoberturaPublisher', 
          //      coberturaReportFile: 'cover_*.xml', 
          //      failNoReports: false, 
          //      failUnhealthy: false, 
          //      failUnstable: false, 
          //      maxNumberOfBuilds: 0, 
          //      onlyStable: false, 
          //      sourceEncoding: 'ASCII', 
          //      zoomCoverageChart: false
          //    ])
          milestone label: "Fast Functional Tests", ordinal: 2
        }
      }
    }

    stage('Long Functional Tests') { 

      when {
        expression { 
          ((params.BUILD_TYPE == 'stable' && env.GIT_BRANCH == 'origin/devel')
          &&
          (currentBuild.result == null || currentBuild.result == 'SUCCESS'))
        }
      }
      steps{
        script {
          handleCheckout()
          def workspace = pwd()
          def tests = load workspace + '/dev_tools/ci/Jenkinsfile.func'
          def archs = ["RISCV"]
          archstring = sh returnStdout: true, script: 'cat $WORKSPACE/targets/*/dev_tools/ci/JenkinsTargets'
          archstring = archstring.replace(" ","").replace("\n", ",")
          archs.addAll(archstring.split(","))
          tests.runtests(archs) 
        }
      }
      post {
        always {
					script {
            def workspace = pwd()
            def archs = ["RISCV"]
						archstring = sh returnStdout: true, script: 'cat $WORKSPACE/targets/*/dev_tools/ci/JenkinsTargets'
						archstring = archstring.replace(" ","").replace("\n", ",")
						archs.addAll(archstring.split(","))
						for (arch in archs){
							unstash "tools"+arch
							unstash "examples"+arch
							unstash "targets"+arch 
							// unstash "ctools"+arch
							// unstash "cexamples"+arch
							// unstash "ctargets"+arch 
						}
					}
          junit allowEmptyResults: true, testResults: 'tests_*.xml'
          // step([$class: 'CoberturaPublisher', 
          //      coberturaReportFile: 'cover_*.xml', 
          //      failNoReports: false, 
          //      failUnhealthy: false, 
          //      failUnstable: false, 
          //      maxNumberOfBuilds: 0, 
          //      onlyStable: false, 
          //      sourceEncoding: 'ASCII', 
          //      zoomCoverageChart: false
          //    ])
          milestone label: "Long Functional Tests", ordinal: 3
        }
      }
    }

    stage('Build Release') {
      when {
        expression { 
          (currentBuild.result == null || currentBuild.result == 'SUCCESS')
        }
      }
      steps{
        node('linux') {
          timeout(time: 10, unit: 'MINUTES') {
            script { handleCheckout() }
            unstash "html"
            sh '$WORKSPACE/dev_tools/ci/build_001_distribution.sh'
            stash name: "distribution", includes: "distribution/*/*/*"
          }
        }
      }
      post {
        always {
          milestone label: "Build Release", ordinal: 4
        }
      }
    }

    stage('Test Release Deploy') {
      when {
        expression { 
          (currentBuild.result == null || currentBuild.result == 'SUCCESS')
        }
      }
      steps{
        parallel( 
          "Testing Python2.7 Environment" : {
            node('python27') {
              timeout(time: 10, unit: 'MINUTES') {
                script { handleCheckout() }
                unstash "distribution"
                sh '$WORKSPACE/dev_tools/ci/test_deploy_001_install.sh 2.7'
              }
            }
          },
          "Testing Python3 Environment" : {
            node('python3') {
              timeout(time: 10, unit: 'MINUTES') {
                script { handleCheckout() }
                unstash "distribution"
                sh '$WORKSPACE/dev_tools/ci/test_deploy_001_install.sh 3'
              }
            }
          }
        )
      }
      post {
        always {
          milestone label: "Test Release Deploy", ordinal: 5
        }
      }
    }

    stage('Deploy Release') {
      when {
        expression {
          (((params.BUILD_TYPE == 'stable' && env.GIT_BRANCH == 'origin/devel') || env.BRANCH_NAME == 'devel')  && (currentBuild.result == null || currentBuild.result == 'SUCCESS'))
        }
      }
      steps{
        node('linux') {
          timeout(time: 10, unit: 'MINUTES') {
            script { handleCheckout() }
            unstash "html"
            sh '$WORKSPACE/dev_tools/ci/deploy_001.sh'
          }
        }
      }
      post {
        always {
          milestone label: "Deploy Release", ordinal: 6
        }
      }
    }

    stage('Merge to Master') {
      when {
        expression {
          (env.GIT_BRANCH == 'origin/devel' && params.BUILD_TYPE == 'stable' && (currentBuild.result == null || currentBuild.result == 'SUCCESS'))
        }
      }
      steps{
        node('linux') {
          timeout(time: 10, unit: 'MINUTES') {
            script { handleCheckout() }
            sh 'git push --set-upstream origin master'
            sh '$WORKSPACE/dev_tools/ci/update_pages.sh'
          }
        }
      }
      post {
        always {
          milestone label: "Merge to Master", ordinal: 7
        }
      }
    }
  }
}

// vim: ts=2 sw=2 et
