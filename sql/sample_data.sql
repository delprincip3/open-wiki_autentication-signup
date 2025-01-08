-- Inserimento di alcuni utenti di test
-- Note: le password sono hashate, questi sono solo esempi
INSERT INTO users (username, password) VALUES 
('test_user', 'pbkdf2:sha256:600000$dummyhash'),
('admin', 'pbkdf2:sha256:600000$dummyhash'); 