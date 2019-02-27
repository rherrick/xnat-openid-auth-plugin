pipeline {
    agent any
    stages {
        stage('Gradle Build') {
            steps {
                sh './gradlew clean jar'
            }
        }
    }
}

