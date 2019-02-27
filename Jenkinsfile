pipeline {
    agent any
    stages {
        stage('Gradle Build') {
            steps {
                sh './gradlew clean jar'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'build/libs/*.jar', excludes: '*-beans-*.jar', fingerprint: true
        }
    }

}

