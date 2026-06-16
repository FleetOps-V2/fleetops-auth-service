package com.fleetops.auth.config;

import com.fleetops.auth.entity.Role;
import com.fleetops.auth.entity.User;
import com.fleetops.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * FleetOps Data Initializer
 *
 * Seeds the default system users on first startup if they do not already exist.
 * This is idempotent â€” safe to run on every startup.
 *
 * Default credentials (change via env vars in production):
 *   admin1  / Admin@123   (ADMIN)
 *   manager1 / Manager@123 (MANAGER)
 *   driver1  / Driver@123  (DRIVER)
 *   driver2  / Driver@123  (DRIVER)
 *   driver3  / Driver@123  (DRIVER)
 */
@Configuration
@Profile("dev")
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    @Value("${SEED_ADMIN_PASSWORD:Admin@123}")
    private String adminPassword;
    @Value("${SEED_MANAGER_PASSWORD:Manager@123}")
    private String managerPassword;
    @Value("${SEED_DRIVER_PASSWORD:Driver@123}")
    private String driverPassword;


    @Bean
    public CommandLineRunner seedDefaultUsers(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            seedUser(userRepository, passwordEncoder, "admin1",   "admin@fleetops.com",    adminPassword,   Role.ADMIN);
            seedUser(userRepository, passwordEncoder, "manager1", "manager@fleetops.com",  managerPassword, Role.MANAGER);
            seedUser(userRepository, passwordEncoder, "driver1",  "driver1@fleetops.com",  driverPassword,  Role.DRIVER);
            seedUser(userRepository, passwordEncoder, "driver2",  "driver2@fleetops.com",  driverPassword,  Role.DRIVER);
            seedUser(userRepository, passwordEncoder, "driver3",  "driver3@fleetops.com",  driverPassword,  Role.DRIVER);
            log.info("FleetOps: Default users initialized successfully.");
        };
    }

    private void seedUser(UserRepository repo, PasswordEncoder encoder,
                          String username, String email, String rawPassword, Role role) {
        if (!repo.existsByUsername(username)) {
            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setPasswordHash(encoder.encode(rawPassword));
            user.setRole(role);
            repo.save(user);
            log.info("FleetOps: Seeded user '{}' with role {}", username, role);
        } else {
            log.debug("FleetOps: User '{}' already exists, skipping.", username);
        }
    }
}

