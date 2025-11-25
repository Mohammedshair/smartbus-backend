FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY . .

RUN ./mvnw clean package || mvn -f pom.xml clean package

EXPOSE 8080

CMD ["java", "-jar", "target/smartbus-0.1.0.jar"]
