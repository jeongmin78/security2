FROM amazoncorretto:17-alpine
COPY build/libs/*.jar security2.jar
EXPOSE 80:80
CMD ["java", "-jar", "security2.jar"]