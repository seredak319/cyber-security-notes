# Use a base image with OpenJDK for running Java applications
FROM openjdk:17-jdk-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the packaged JAR file into the container
COPY target/security-0.0.1-SNAPSHOT.jar /app/security-notes.jar

# Expose port 8080 for the Spring Boot application
EXPOSE 8080

# Specify the command to run the Spring Boot application
CMD ["java", "-jar", "security-notes.jar"]
