# Wraps the jar from `./mvnw package` (same pattern as Mirattic Sync).
FROM eclipse-temurin:21-jre
COPY target/auth-0.0.1-SNAPSHOT.jar /app.jar
USER 65534
EXPOSE 9000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app.jar"]
