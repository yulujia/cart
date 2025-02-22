#!/usr/bin/groovy
/* Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for any purpose (including commercial purposes)
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions, and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions, and the following disclaimer in the
 *    documentation and/or materials provided with the distribution.
 *
 * 3. In addition, redistributions of modified forms of the source or binary
 *    code must carry prominent notices stating that the original code was
 *    changed and the date of the change.
 *
 *  4. All publications or advertising materials mentioning features or use of
 *     this software are asked, but not required, to acknowledge that it was
 *     developed by Intel Corporation and credit the contributors.
 *
 * 5. Neither the name of Intel Corporation, nor the name of any Contributor
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// To use a test branch (i.e. PR) until it lands to master
// I.e. for testing library changes
//@Library(value="pipeline-lib@your_branch") _

def arch="-Linux"
def sanitized_JOB_NAME = JOB_NAME.toLowerCase().replaceAll('/', '-').replaceAll('%2f', '-')

pipeline {
    agent { label 'lightweight' }

    triggers {
        cron(env.BRANCH_NAME == 'master' ? '0 0 * * *' : '')
    }

    environment {
        GITHUB_USER = credentials('daos-jenkins-review-posting')
        BAHTTPS_PROXY = "${env.HTTP_PROXY ? '--build-arg HTTP_PROXY="' + env.HTTP_PROXY + '" --build-arg http_proxy="' + env.HTTP_PROXY + '"' : ''}"
        BAHTTP_PROXY = "${env.HTTP_PROXY ? '--build-arg HTTPS_PROXY="' + env.HTTPS_PROXY + '" --build-arg https_proxy="' + env.HTTPS_PROXY + '"' : ''}"
        UID=sh(script: "id -u", returnStdout: true)
        BUILDARGS = "--build-arg NOBUILD=1 --build-arg UID=$env.UID $env.BAHTTP_PROXY $env.BAHTTPS_PROXY"
    }

    options {
        // preserve stashes so that jobs can be started at the test stage
        preserveStashes(buildCount: 5)
    }

    stages {
        stage('Cancel Previous Builds') {
            when { changeRequest() }
            steps {
                cancelPreviousBuilds()
            }
        }
        stage('Pre-build') {
            parallel {
                stage('checkpatch') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile.centos.7'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-centos7 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        checkPatch user: GITHUB_USER_USR,
                                   password: GITHUB_USER_PSW,
                                   ignored_files: "src/control/vendor/*"
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'pylint.log', allowEmptyArchive: true
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        /* temporarily moved into stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'pre-build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'pre-build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'pre-build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
            }
        }
        stage('Build') {
            /* Don't use failFast here as whilst it avoids using extra resources
             * and gives faster results for PRs it's also on for master where we
	     * do want complete results in the case of partial failure
	     */
            //failFast true
            parallel {
                stage('Build RPM on CentOS 7') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile-mockbuild.centos.7'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs '--build-arg UID=$(id -u) --build-arg JENKINS_URL=' +
                                                env.JENKINS_URL
                            args  '--group-add mock --cap-add=SYS_ADMIN --privileged=true'
                        }
                    }
                    steps {
                         githubNotify credentialsId: 'daos-jenkins-commit-status',
                                      description: env.STAGE_NAME,
                                      context: "build" + "/" + env.STAGE_NAME,
                                      status: "PENDING"
                        checkoutScm withSubmodules: true
                        sh label: env.STAGE_NAME,
                           script: '''rm -rf artifacts/centos7/
                                      mkdir -p artifacts/centos7/
                                      if make srpm; then
                                          if make mockbuild; then
                                              (cd /var/lib/mock/epel-7-x86_64/result/ &&
                                               cp -r . $OLDPWD/artifacts/centos7/)
                                              createrepo artifacts/centos7/
                                          else
                                              rc=\${PIPESTATUS[0]}
                                              (cd /var/lib/mock/epel-7-x86_64/result/ &&
                                               cp -r . $OLDPWD/artifacts/centos7/)
                                              cp -af _topdir/SRPMS artifacts/centos7/
                                              exit \$rc
                                          fi
                                      else
                                          exit \${PIPESTATUS[0]}
                                      fi'''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'artifacts/centos7/**'
                        }
                        success {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "SUCCESS"
                        }
                        unstable {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "UNSTABLE"
                        }
                        failure {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "FAILURE"
                        }
                    }
                }
                stage('Build RPM on SLES 12.3') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile-rpmbuild.sles.12.3'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs '--build-arg UID=$(id -u) ' +
                                                '--build-arg JENKINS_URL=' +
                                                env.JENKINS_URL +
                                                 " --build-arg CACHEBUST=${currentBuild.startTimeInMillis}"
                        }
                    }
                    steps {
                         githubNotify credentialsId: 'daos-jenkins-commit-status',
                                      description: env.STAGE_NAME,
                                      context: "build" + "/" + env.STAGE_NAME,
                                      status: "PENDING"
                        checkoutScm withSubmodules: true
                        sh label: env.STAGE_NAME,
                           script: '''rm -rf artifacts/sles12.3/
                              mkdir -p artifacts/sles12.3/
                              rm -rf _topdir/SRPMS
                              if make srpm; then
                                  rm -rf _topdir/RPMS
                                  if make rpms; then
                                      ln _topdir/{RPMS/*,SRPMS}/*  artifacts/sles12.3/
                                      createrepo artifacts/sles12.3/
                                  else
                                      exit \${PIPESTATUS[0]}
                                  fi
                              else
                                  exit \${PIPESTATUS[0]}
                              fi'''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'artifacts/sles12.3/**'
                        }
                        success {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "SUCCESS"
                        }
                        unstable {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "UNSTABLE"
                        }
                        failure {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "FAILURE"
                        }
                    }
                }
                stage('Build RPM on Leap 42.3') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile-rpmbuild.leap.42.3'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs '--build-arg UID=$(id -u) ' +
                                                '--build-arg JENKINS_URL=' +
                                                env.JENKINS_URL +
                                                " --build-arg CACHEBUST=${currentBuild.startTimeInMillis}"
                        }
                    }
                    steps {
                         githubNotify credentialsId: 'daos-jenkins-commit-status',
                                      description: env.STAGE_NAME,
                                      context: "build" + "/" + env.STAGE_NAME,
                                      status: "PENDING"
                        checkoutScm withSubmodules: true
                        sh label: env.STAGE_NAME,
                           script: '''rm -rf artifacts/leap42.3/
                              mkdir -p artifacts/leap42.3/
                              rm -rf _topdir/SRPMS
                              if make srpm; then
                                  rm -rf _topdir/RPMS
                                  if make rpms; then
                                      ln _topdir/{RPMS/*,SRPMS}/*  artifacts/leap42.3/
                                      createrepo artifacts/leap42.3/
                                  else
                                      exit \${PIPESTATUS[0]}
                                  fi
                              else
                                  exit \${PIPESTATUS[0]}
                              fi'''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'artifacts/leap42.3/**'
                        }
                        success {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "SUCCESS"
                        }
                        unstable {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "UNSTABLE"
                        }
                        failure {
                            stepResult name: env.STAGE_NAME, context: "build",
                                       result: "FAILURE"
                        }
                    }
                }
                stage('Build master CentOS 7') {
                    when { branch 'master' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.centos.7'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-centos7 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild(clean: "_build.external${arch}",
                                   scons_args: '--build-config=utils/build-master.config')
                        // this really belongs in the test stage CORCI-530
                        sh '''scons utest --utest-mode=memcheck
                              mv build/Linux/src/utest{,_valgrind}
                              scons utest'''
                        stash name: 'CentOS-master-install', includes: 'install/**'
                        stash name: 'CentOS-master-build-vars', includes: ".build_vars${arch}.*"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-master-centos7",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            archiveArtifacts artifacts: '''build/Linux/src/utest_valgrind/utest.log,
                                                           build/Linux/src/utest_valgrind/test_output,
                                                           build/Linux/src/utest/utest.log,
                                                           build/Linux/src/utest/test_output'''
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-master"
                            archiveArtifacts artifacts: 'config.log-master'
                        }
                        failure {
                            sh "mv config${arch}.log config.log-master"
                            archiveArtifacts artifacts: 'config.log-master'
                        }
                    }
                }
                stage('Build on CentOS 7') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile.centos.7'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-centos7 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}"
                        // this really belongs in the test stage CORCI-530
                        sh '''scons utest --utest-mode=memcheck
                              mv build/Linux/src/utest{,_valgrind}
                              scons utest'''
                        stash name: 'CentOS-install', includes: 'install/**'
                        stash name: 'CentOS-build-vars', includes: ".build_vars${arch}.*"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-centos7",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            archiveArtifacts artifacts: '''build/Linux/src/utest_valgrind/utest.log,
                                                           build/Linux/src/utest_valgrind/test_output,
                                                           build/Linux/src/utest/utest.log,
                                                           build/Linux/src/utest/test_output'''
                        /* when JENKINS-39203 is resolved, can probably use stepResult
                           here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                        */
                        }
                        /* temporarily moved into stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        */
                        unstable {
                            sh "mv config${arch}.log config.log-centos7-gcc"
                            archiveArtifacts artifacts: 'config.log-centos7-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-centos7-gcc"
                            archiveArtifacts artifacts: 'config.log-centos7-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on CentOS 7 with Clang') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile.centos.7'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-centos7 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}", COMPILER: "clang"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-centos7-clang",
                                             tools: [ clang(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-centos7-clang"
                            archiveArtifacts artifacts: 'config.log-centos7-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-centos7-clang"
                            archiveArtifacts artifacts: 'config.log-centos7-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on Ubuntu 18.04') {
                    when { beforeAgent true
                           branch 'master' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.ubuntu.18.04'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-ubuntu18.04 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-ubuntu18",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                        */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-ubuntu18.04-gcc"
                            archiveArtifacts artifacts: 'config.log-ubuntu18.04-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-ubuntu18.04-gcc"
                            archiveArtifacts artifacts: 'config.log-ubuntu18.04-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on Ubuntu 18.04 with Clang') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile.ubuntu.18.04'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-ubuntu18.04 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}", COMPILER: "clang"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-ubuntu18-clang",
                                             tools: [ clang(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                        */
                        }
                        success {
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-ubuntu18.04-clang"
                            archiveArtifacts artifacts: 'config.log-ubuntu18.04-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-ubuntu18.04-clang"
                            archiveArtifacts artifacts: 'config.log-ubuntu18.04-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on SLES 12.3') {
                    when { beforeAgent true
                           environment name: 'SLES12_3_DOCKER', value: 'true' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.sles.12.3'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-sles12.3 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}"
                    }
                    post {
                        always {
                            node('lightweight') {
                                /* Stack dumping for sles12sp3/leap42.3:
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-sles12.3",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                                */
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-sles12sp3-gcc"
                            archiveArtifacts artifacts: 'config.log-sles12sp3-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-sles12sp3-gcc"
                            archiveArtifacts artifacts: 'config.log-sles12sp3-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on LEAP 42.3') {
                    when { beforeAgent true
                           environment name: 'LEAP42_3_DOCKER', value: 'true' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.leap.42.3'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-leap42.3 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}"
                    }
                    post {
                        always {
                            node('lightweight') {
                                /* Stack dumping for sles12sp3/leap42.3:
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: false,
                                             id: "analysis-leap42.3",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                                */
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-leap42sp3-gcc"
                            archiveArtifacts artifacts: 'config.log-leap42sp3-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-leap42sp3-gcc"
                            archiveArtifacts artifacts: 'config.log-leap42sp3-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on Leap 15') {
                    when { beforeAgent true
                           branch 'master' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.leap.15'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-leap15 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-leap15",
                                             tools: [ gcc4(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-leap15-gcc"
                            archiveArtifacts artifacts: 'config.log-leap15-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-leap15-gcc"
                            archiveArtifacts artifacts: 'config.log-leap15-gcc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on Leap 15 with Clang') {
                    when { beforeAgent true
                           branch 'master' }
                    agent {
                        dockerfile {
                            filename 'Dockerfile.leap.15'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-leap15 " + '$BUILDARGS'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}", COMPILER: "clang"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-leap15-clang",
                                             tools: [ clang(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-leap15-clang"
                            archiveArtifacts artifacts: 'config.log-leap15-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-leap15-clang"
                            archiveArtifacts artifacts: 'config.log-leap15-clang'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
                stage('Build on Leap 15 with Intel-C') {
                    agent {
                        dockerfile {
                            filename 'Dockerfile.leap.15'
                            dir 'utils/docker'
                            label 'docker_runner'
                            additionalBuildArgs "-t ${sanitized_JOB_NAME}-leap15 " + '$BUILDARGS'
                            args '-v /opt/intel:/opt/intel'
                        }
                    }
                    steps {
                        sconsBuild clean: "_build.external${arch}", COMPILER: "icc"
                    }
                    post {
                        always {
                            node('lightweight') {
                                recordIssues enabledForFailure: true,
                                             aggregatingResults: true,
                                             id: "analysis-leap15-intelc",
                                             tools: [ intel(), cppCheck() ],
                                             filters: [excludeFile('.*\\/_build\\.external-Linux\\/.*'),
                                                       excludeFile('_build\\.external-Linux\\/.*')]
                            }
                            /* when JENKINS-39203 is resolved, can probably use stepResult
                               here and remove the remaining post conditions
                               stepResult name: env.STAGE_NAME,
                                          context: 'build/' + env.STAGE_NAME,
                                          result: ${currentBuild.currentResult}
                            */
                        }
                        success {
                        /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                            */
                            sh "rm -rf _build.external${arch}"
                        }
                        unstable {
                            sh "mv config${arch}.log config.log-leap15-intelc"
                            archiveArtifacts artifacts: 'config.log-leap15-intelc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                            */
                        }
                        failure {
                            sh "mv config${arch}.log config.log-leap15-intelc"
                            archiveArtifacts artifacts: 'config.log-leap15-intelc'
                            /* temporarily moved into stepResult due to JENKINS-39203
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'build/' + env.STAGE_NAME,
                                         status: 'ERROR'
                            */
                        }
                    }
                }
            }
        }
        stage('Test') {
            parallel {
                stage('Single-node') {
                    agent {
                        label 'ci_vm1'
                    }
                    steps {
                        provisionNodes NODELIST: env.NODELIST,
                                       node_count: 1,
                                       snapshot: true
                        runTest stashes: [ 'CentOS-install', 'CentOS-build-vars' ],
                                script: '''export PDSH_SSH_ARGS_APPEND="-i ci_key"
                                           export CART_TEST_MODE=native
                                           bash -x ./multi-node-test.sh 1 ''' +
                                           env.NODELIST + ''' one_node''',
                                junit_files: "install/Linux/TESTING/avocado/job-results/CART_1node/*/*.xml"
                    }
                    post {
                        always {
                            sh '''rm -rf install/Linux/TESTING/avocado/job-results/CART_1node/*/html/
                                  if [ -n "$STAGE_NAME" ]; then
                                      rm -rf "$STAGE_NAME/"
                                      mkdir "$STAGE_NAME/"
                                      mv install/Linux/TESTING/avocado/job-results/CART_1node/* \
                                         "$STAGE_NAME/" || true
                                      mv install/Linux/TESTING/testLogs-1_node \
                                         "$STAGE_NAME/" || true
                                  else
                                      echo "The STAGE_NAME environment variable is missing!"
                                      false
                                  fi'''
                            junit env.STAGE_NAME + '/*/results.xml'
                            archiveArtifacts artifacts: env.STAGE_NAME + '/**'
                        }
                        /* temporarily moved into runTest->stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
                stage('Single-node-valgrind') {
                    agent {
                        label 'ci_vm1'
                    }
                    steps {
                        provisionNodes NODELIST: env.NODELIST,
                                       node_count: 1,
                                       snapshot: true
                        runTest stashes: [ 'CentOS-install', 'CentOS-build-vars' ],
                                script: '''export PDSH_SSH_ARGS_APPEND="-i ci_key"
                                           export CART_TEST_MODE=memcheck
                                           bash -x ./multi-node-test.sh 1 ''' +
                                           env.NODELIST + ''' one_node''',
                                junit_files: "install/Linux/TESTING/avocado/job-results/CART_1vgdnode/*/*.xml"
                    }
                    post {
                        always {
                            sh '''rm -rf install/Linux/TESTING/avocado/job-results/CART_1vgdnode/*/html/
                                  if [ -n "$STAGE_NAME" ]; then
                                      rm -rf "$STAGE_NAME/"
                                      mkdir "$STAGE_NAME/"
                                      mv install/Linux/TESTING/avocado/job-results/CART_1vgdnode/* \
                                         "$STAGE_NAME/" || true
                                      mv install/Linux/TESTING/testLogs-1vgd_node \
                                         "$STAGE_NAME/" || true
                                  else
                                      echo "The STAGE_NAME environment variable is missing!"
                                      false
                                  fi'''
                            publishValgrind (
                                failBuildOnInvalidReports: true,
                                failBuildOnMissingReports: true,
                                failThresholdDefinitelyLost: '0',
                                failThresholdInvalidReadWrite: '0',
                                failThresholdTotal: '0',
                                pattern: '**/*.memcheck',
                                publishResultsForAbortedBuilds: false,
                                publishResultsForFailedBuilds: false,
                                sourceSubstitutionPaths: '',
                                unstableThresholdDefinitelyLost: '',
                                unstableThresholdInvalidReadWrite: '',
                                unstableThresholdTotal: ''
                                )
                            junit env.STAGE_NAME + '/*/results.xml'
                            archiveArtifacts artifacts: env.STAGE_NAME + '/**'
                        }
                        /* temporarily moved into runTest->stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
                stage('Two-node') {
                    agent {
                        label 'ci_vm2'
                    }
                    steps {
                        provisionNodes NODELIST: env.NODELIST,
                                       node_count: 2,
                                       snapshot: true
                        runTest stashes: [ 'CentOS-install', 'CentOS-build-vars' ],
                                script: '''export PDSH_SSH_ARGS_APPEND="-i ci_key"
                                           export CART_TEST_MODE=none
                                           bash -x ./multi-node-test.sh 2 ''' +
                                           env.NODELIST + ''' two_node''',
                                junit_files: "install/Linux/TESTING/avocado/job-results/CART_2node/*/*.xml"
                    }
                    post {
                        always {
                            sh '''rm -rf install/Linux/TESTING/avocado/job-results/CART_2node/*/html/
                                  if [ -n "$STAGE_NAME" ]; then
                                      rm -rf "$STAGE_NAME/"
                                      mkdir "$STAGE_NAME/"
                                      mv install/Linux/TESTING/avocado/job-results/CART_2node/* \
                                         "$STAGE_NAME/" || true
                                      mv install/Linux/TESTING/testLogs-2_node \
                                         "$STAGE_NAME/" || true
                                  else
                                      echo "The STAGE_NAME environment variable is missing!"
                                      false
                                  fi'''
                            junit env.STAGE_NAME + '/*/results.xml'
                            archiveArtifacts artifacts: env.STAGE_NAME + '/**'
                        }
                        /* temporarily moved into runTest->stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
                stage('Three-node') {
                    agent {
                        label 'ci_vm3'
                    }
                    steps {
                        provisionNodes NODELIST: env.NODELIST,
                                       node_count: 3,
                                       snapshot: true
                        runTest stashes: [ 'CentOS-install', 'CentOS-build-vars' ],
                                script: '''export PDSH_SSH_ARGS_APPEND="-i ci_key"
                                           export CART_TEST_MODE=none
                                           bash -x ./multi-node-test.sh 3 ''' +
                                           env.NODELIST + ''' three_node''',
                                junit_files: "install/Linux/TESTING/avocado/job-results/CART_3node/*/*.xml"
                    }
                    post {
                        always {
                            sh '''rm -rf install/Linux/TESTING/avocado/job-results/CART_3node/*/html/
                                  if [ -n "$STAGE_NAME" ]; then
                                      rm -rf "$STAGE_NAME/"
                                      mkdir "$STAGE_NAME/"
                                      mv install/Linux/TESTING/avocado/job-results/CART_3node/* \
                                         "$STAGE_NAME/" || true
                                      mv install/Linux/TESTING/testLogs-3_node \
                                         "$STAGE_NAME/" || true
                                  else
                                      echo "The STAGE_NAME environment variable is missing!"
                                      false
                                  fi'''
                            junit env.STAGE_NAME + '/*/results.xml'
                            archiveArtifacts artifacts: env.STAGE_NAME + '/**'
                        }
                        /* temporarily moved into runTest->stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
                stage('Five-node') {
                    agent {
                        label 'ci_vm5'
                    }
                    steps {
                        provisionNodes NODELIST: env.NODELIST,
                                       node_count: 5,
                                       snapshot: true
                        runTest stashes: [ 'CentOS-install', 'CentOS-build-vars' ],
                                script: '''export PDSH_SSH_ARGS_APPEND="-i ci_key"
                                           export CART_TEST_MODE=none
                                           bash -x ./multi-node-test.sh 5 ''' +
                                           env.NODELIST + ''' five_node''',
                                junit_files: "install/Linux/TESTING/avocado/job-results/CART_5node/*/*.xml"
                    }
                    post {
                        always {
                            sh '''rm -rf install/Linux/TESTING/avocado/job-results/CART_5node/*/html/
                                  if [ -n "$STAGE_NAME" ]; then
                                      rm -rf "$STAGE_NAME/"
                                      mkdir "$STAGE_NAME/"
                                      mv install/Linux/TESTING/avocado/job-results/CART_5node/* \
                                         "$STAGE_NAME/" || true
                                      mv install/Linux/TESTING/testLogs-5_node \
                                         "$STAGE_NAME/" || true
                                  else
                                      echo "The STAGE_NAME environment variable is missing!"
                                      false
                                  fi'''
                            junit env.STAGE_NAME + '/*/results.xml'
                            archiveArtifacts artifacts: env.STAGE_NAME + '/**'
                        }
                        /* temporarily moved into runTest->stepResult due to JENKINS-39203
                        success {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'SUCCESS'
                        }
                        unstable {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'FAILURE'
                        }
                        failure {
                            githubNotify credentialsId: 'daos-jenkins-commit-status',
                                         description: env.STAGE_NAME,
                                         context: 'test/' + env.STAGE_NAME,
                                         status: 'ERROR'
                        }
                        */
                    }
                }
            }
        }
    }
}
