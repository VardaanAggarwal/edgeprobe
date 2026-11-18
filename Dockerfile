# syntax=docker/dockerfile:1.7

# ---- build: compile the API module and split the jar into layers ----
FROM eclipse-temurin:17-jdk AS build
WORKDIR /src
COPY .mvn .mvn
COPY mvnw pom.xml ./
COPY edgeprobe-core edgeprobe-core
COPY edgeprobe-api edgeprobe-api
COPY edgeprobe-cli/pom.xml edgeprobe-cli/pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    ./mvnw -B -q -pl edgeprobe-api -am package -DskipTests \
 && java -Djarmode=tools -jar edgeprobe-api/target/edgeprobe-api.jar extract --layers --launcher --destination /extracted

# ---- run: JRE only, non-root, dependencies in their own layer so code changes rebuild fast ----
FROM eclipse-temurin:17-jre
RUN groupadd --system edgeprobe && useradd --system --gid edgeprobe --uid 10001 edgeprobe
WORKDIR /app
COPY --from=build /extracted/dependencies/ ./
COPY --from=build /extracted/spring-boot-loader/ ./
COPY --from=build /extracted/snapshot-dependencies/ ./
COPY --from=build /extracted/application/ ./
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "org.springframework.boot.loader.launch.JarLauncher"]
