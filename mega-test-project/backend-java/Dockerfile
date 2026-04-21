# =============================================================================
# backend-java/Dockerfile
# =============================================================================
# PURPOSE: Builds the Java Spring Boot API.
#
# ⚠️  INTENTIONAL ISSUES:
#   1. BAD: Using heavy JDK image (not JRE) — much larger container
#   2. BAD: No multi-stage build — source code included in final image
#   3. BAD: Running as root (no USER directive)
#   4. BAD: Maven wrapper downloads internet dependencies at build time (no cache)
# =============================================================================

# BAD: Should use eclipse-temurin:17-jre-alpine for production
# Full JDK exposes compiler tools to potential attackers
FROM maven:3.9-eclipse-temurin-17

WORKDIR /app

# Copy pom and download dependencies (no cache layer optimization)
COPY pom.xml .
RUN mvn dependency:go-offline -q

# BAD: Copies source code — final image includes all source (IP exposure risk)
COPY src ./src
RUN mvn package -DskipTests -q

EXPOSE 8080

# BAD: Running the fat jar as root with verbose error output
CMD ["java", "-jar", "target/backend-java-1.0.jar", "--spring.config.location=classpath:application.properties"]
