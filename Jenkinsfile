pipeline {
    agent any

    environment {
        DOCKERHUB_USERNAME = 'abhiishek25'
        IMAGE_NAME = 'shieldguard-pro'
        IMAGE_TAG = 'latest'
    }

    stages {
        stage('Checkout') {
            steps {
                echo '✅ Checking out code from GitHub...'
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                echo '✅ Installing Python dependencies...'
                sh '''
                    python3 -m pip install --upgrade pip
                    pip3 install -r requirements.txt
                '''
            }
        }

        stage('Run Tests') {
            steps {
                echo '✅ Running health checks...'
                sh '''
                    python3 -c "import flask; import sklearn; import numpy; import pandas; print('All imports OK')"
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo '✅ Building Docker image...'
                sh '''
                    docker build -t ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG} .
                '''
            }
        }

        stage('Push to Docker Hub') {
            steps {
                echo '✅ Pushing to Docker Hub...'
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub-credentials',
                    usernameVariable: 'DOCKER_USER',
                    passwordVariable: 'DOCKER_PASS'
                )]) {
                    sh '''
                        echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
                        docker push ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}
                    '''
                }
            }
        }

        stage('Deploy') {
            steps {
                echo '✅ Deploying container...'
                sh '''
                    docker stop shieldguard-pro || true
                    docker rm shieldguard-pro || true
                    docker run -d \
                        --name shieldguard-pro \
                        -p 5000:5000 \
                        -e FLASK_ENV=production \
                        ${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${IMAGE_TAG}
                    echo "🚀 ShieldGuard Pro deployed successfully!"
                '''
            }
        }
    }

    post {
        success {
            echo '🎉 Pipeline completed successfully!'
        }
        failure {
            echo '❌ Pipeline failed! Check logs above.'
        }
    }
}