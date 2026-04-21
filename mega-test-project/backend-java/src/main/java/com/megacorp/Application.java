// =============================================================================
// backend-java/src/main/java/com/megacorp/Application.java
// =============================================================================
// PURPOSE: Spring Boot application entry point.
//
// ⚠️  INTENTIONAL ISSUES:
//   1. BAD: @SpringBootApplication without any security config = open by default
//   2. BAD: CORS configured to allow all origins globally
// =============================================================================
package com.megacorp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// BAD: No @EnableWebSecurity — Spring Security disabled by default without it
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        // BAD: Prints sensitive startup info to console
        System.out.println("[STARTUP] MegaCorp Java API starting...");
        System.out.println("[STARTUP] DB Password: " + System.getenv("SPRING_DATASOURCE_PASSWORD")); // BAD!
        SpringApplication.run(Application.class, args);
    }

    // ==========================================================================
    // BAD: Global CORS config allows ALL origins, ALL methods, ALL headers
    // SonarQube: "Make sure allowing any origin is safe here"
    // ==========================================================================
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("*") // BAD: Wildcard origin
                        .allowedMethods("*") // BAD: Allows DELETE, PUT, PATCH, OPTIONS etc.
                        .allowedHeaders("*"); // BAD: Allows any header including custom attack headers
            }
        };
    }
}
