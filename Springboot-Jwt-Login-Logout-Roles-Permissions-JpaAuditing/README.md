# Spring Boot 3.2 Security with JWT Implementation
This project demonstrates the implementation of security using Spring Boot 3.2 and JSON Web Tokens (JWT). It includes the following features:

## Features
* User registration and login with JWT authentication
* Password encryption using BCrypt
* Role-based authorization with Spring Security
* Customized access denied handling
* Logout mechanism
* Refresh token

## Technologies
* Spring Boot 3.2
* Spring Security
* JSON Web Tokens (JWT)
* BCrypt
* Maven
 
## Getting Started
To get started with this project, you will need to have the following installed on your local machine:

* JDK 17+
* Maven 3+

  To build and run the project, follow these steps:

* Clone the repository: `git clone https://github.com/Malak88/Springboot-Jwt-Login-Logout-Roles-Permissions-JpaAuditing.git`
* Navigate to the project directory: cd Springboot-Jwt-Login-Logout-Roles-Permissions-JpaAuditing
* Add database "jsecurity_test" to postgres and change Database credentials in application.yml
* Build the project: mvn clean install
* Run the project: mvn spring-boot:run 

-> The application will be available at http://localhost:8080.
