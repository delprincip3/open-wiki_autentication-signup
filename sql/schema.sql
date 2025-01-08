-- Creazione del database
CREATE DATABASE IF NOT EXISTS openwiki;
USE openwiki;

-- Tabella users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Indici
CREATE INDEX idx_username ON users(username); 