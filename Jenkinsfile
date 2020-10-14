void buildBpfgen(String libc, String buildDir) {
  sh "docker pull untangleinc/bpfgen:build-${libc}"
  sh "docker-compose -f ${buildDir}/build/docker-compose.build.yml -p bpfgen_${libc} run ${libc}"
}

pipeline {
  agent none

  stages {
    stage('Build') {

      parallel {
        stage('Build musl') {
	  agent { label 'mfw' }

          environment {
            libc = 'musl'
            buildDir = "${env.HOME}/build-bpfgen-${env.BRANCH_NAME}-${libc}"
          }

	  stages {
            stage('Prep WS musl') {
              steps { dir(buildDir) { checkout scm } }
            }

            stage('Build bpfgen musl') {
              steps {
                buildBpfgen(libc, buildDir)
              }
            }
          }
        }

        stage('Build glibc') {
	  agent { label 'mfw' }

          environment {
            libc = 'glibc'
            buildDir = "${env.HOME}/build-bpfgen-${env.BRANCH_NAME}-${libc}"
          }

	  stages {
            stage('Prep WS glibc') {
              steps { dir(buildDir) { checkout scm } }
            }

            stage('Build bpfgen glibc') {
              steps {
                buildBpfgen(libc, buildDir)
              }
            }
          }
        }
      }

      post {
	changed {
	  script {
	    // set result before pipeline ends, so emailer sees it
	    currentBuild.result = currentBuild.currentResult
          }
          emailext(to:'nfgw-engineering@untangle.com', subject:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result}", body:"${env.BUILD_URL}")
          slackSend(channel:"#team_engineering", message:"${env.JOB_NAME} #${env.BUILD_NUMBER}: ${currentBuild.result} at ${env.BUILD_URL}")
	}
      }
    }
  }
}
