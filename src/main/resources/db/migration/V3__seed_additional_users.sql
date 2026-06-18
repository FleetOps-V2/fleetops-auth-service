-- Add driver2 and driver3 to complete the demo user set
-- Passwords: Driver2@2024! / Driver3@2024!
INSERT INTO users (created_at, username, email, password_hash, role) VALUES
  (NOW(), 'driver2', 'driver2@fleetops.internal', '$2b$10$WWDJBGTpwEoxIxZLH5dyt.sKNbq1EikHW0gEHzWB5CpBjh513tbcC', 'DRIVER'),
  (NOW(), 'driver3', 'driver3@fleetops.internal', '$2b$10$b0X.PBQseGHdKzXYXWMUsexQpOZADnTwvu8LwESQtpFVqw1pksyaa', 'DRIVER')
ON CONFLICT (username) DO NOTHING;
