-- Seed default users for FleetOps demo
-- Passwords: Admin@2024!  /  Manager@2024!  /  Driver@2024!
-- BCrypt 10 rounds — Spring's BCryptPasswordEncoder accepts $2b$ hashes
INSERT INTO users (created_at, username, email, password_hash, role) VALUES
  (NOW(), 'admin',    'admin@fleetops.internal',    '$2b$10$vHkF7rKmn3OMW9T.M9xfTu3CquU8I/2/urh5S7Tk4HQpLXgplx38S', 'ADMIN'),
  (NOW(), 'manager1', 'manager1@fleetops.internal', '$2b$10$j9IvmcKVLT2nTWbnBGGHhe.QdkECw8AUZAPFYrsMdBAKVRq/A3yjG', 'MANAGER'),
  (NOW(), 'driver1',  'driver1@fleetops.internal',  '$2b$10$BW4Tk.NYjWuHkZO5hDKOFu7JdenRsReOXhRLVWk/Y1J89S46iD/0C', 'DRIVER')
ON CONFLICT (username) DO NOTHING;
