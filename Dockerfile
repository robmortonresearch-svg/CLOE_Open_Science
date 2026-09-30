FROM maven:3.9-eclipse-temurin-21

WORKDIR /app

# Install Python for running the evaluation scripts
RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*

# Copy backend code
COPY backend/ ./backend/

# Build backend
WORKDIR /app/backend
RUN mvn clean package -DskipTests

# Copy evaluation scripts
WORKDIR /app
COPY evaluate.py ./
COPY results.json ./
COPY index.html ./

# Expose ports
EXPOSE 8080

# Set working directory
WORKDIR /app

# Default command: show menu
CMD ["bash", "-c", "echo 'CLOE Open Science Artifact'; echo ''; echo 'Available commands:'; echo '  docker exec <container> java -jar backend/target/*.jar'; echo '  docker exec <container> python3 evaluate.py'; echo ''; java -jar backend/target/*.jar"]
