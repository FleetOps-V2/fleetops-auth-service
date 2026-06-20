package com.fleetops.auth.config;

import com.fleetops.auth.entity.Role;
import com.fleetops.auth.entity.User;
import com.fleetops.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the internal lambda-service account on every startup (all profiles).
 * The account is used by the EventBridge alert-processor Lambda to authenticate
 * with the vehicle service via JWT.
 *
 * The password is injected from the LAMBDA_SERVICE_PASSWORD environment variable,
 * which is sourced from AWS Secrets Manager (fleetops/{env}/lambda-service-credentials).
 * A local dev default is provided so the service starts without the env var.
 */
@Component
@Order(1)
public class LambdaServiceInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(LambdaServiceInitializer.class);

    private static final String USERNAME = "lambda-service";
    private static final String EMAIL    = "lambda-service@fleetops.internal";

    @Value("${LAMBDA_SERVICE_PASSWORD:LambdaLocal@dev123}")
    private String lambdaServicePassword;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public LambdaServiceInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        userRepository.findByUsername(USERNAME).ifPresentOrElse(
            existing -> {
                // Refresh the password hash on every startup so Secrets Manager rotation is picked up
                existing.setPasswordHash(passwordEncoder.encode(lambdaServicePassword));
                userRepository.save(existing);
                log.info("LambdaServiceInitializer: refreshed password hash for '{}'", USERNAME);
            },
            () -> {
                User user = new User();
                user.setUsername(USERNAME);
                user.setEmail(EMAIL);
                user.setPasswordHash(passwordEncoder.encode(lambdaServicePassword));
                user.setRole(Role.MANAGER);
                userRepository.save(user);
                log.info("LambdaServiceInitializer: created internal service account '{}'", USERNAME);
            }
        );
    }
}
