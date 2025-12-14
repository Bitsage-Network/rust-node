//! Database configuration for Bitsage Network
//!
//! This module handles database configuration and connection settings.

use serde::{Deserialize, Serialize};
use std::env;

/// Database configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database host
    pub host: String,
    /// Database port
    pub port: u16,
    /// Database name
    pub database: String,
    /// Database username
    pub username: String,
    /// Database password
    pub password: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of connections in the pool
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Idle timeout in seconds
    pub idle_timeout: u64,
    /// Enable SSL
    pub ssl_mode: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            database: "sage_network".to_string(),
            username: "sage_user".to_string(),
            password: "sage_password".to_string(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout: 30,
            idle_timeout: 600,
            ssl_mode: "prefer".to_string(),
        }
    }
}

impl DatabaseConfig {
    /// Create database configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            host: env::var("POSTGRES_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: env::var("POSTGRES_PORT")
                .unwrap_or_else(|_| "5432".to_string())
                .parse()
                .unwrap_or(5432),
            database: env::var("POSTGRES_DB").unwrap_or_else(|_| "sage_network".to_string()),
            username: env::var("POSTGRES_USER").unwrap_or_else(|_| "sage_user".to_string()),
            password: env::var("POSTGRES_PASSWORD").unwrap_or_else(|_| "sage_password".to_string()),
            max_connections: env::var("POSTGRES_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "20".to_string())
                .parse()
                .unwrap_or(20),
            min_connections: env::var("POSTGRES_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            connect_timeout: env::var("POSTGRES_CONNECT_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            idle_timeout: env::var("POSTGRES_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .unwrap_or(600),
            ssl_mode: env::var("POSTGRES_SSL_MODE").unwrap_or_else(|_| "prefer".to_string()),
        }
    }

    /// Generate database URL from configuration
    pub fn database_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode={}",
            self.username, self.password, self.host, self.port, self.database, self.ssl_mode
        )
    }

    /// Generate database URL without database name (for creating database)
    pub fn admin_database_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/postgres?sslmode={}",
            self.username, self.password, self.host, self.port, self.ssl_mode
        )
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() {
            return Err("Database host cannot be empty".to_string());
        }
        if self.database.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }
        if self.username.is_empty() {
            return Err("Database username cannot be empty".to_string());
        }
        if self.password.is_empty() {
            return Err("Database password cannot be empty".to_string());
        }
        if self.port == 0 {
            return Err("Database port must be greater than 0".to_string());
        }
        if self.max_connections == 0 {
            return Err("Max connections must be greater than 0".to_string());
        }
        if self.min_connections > self.max_connections {
            return Err("Min connections cannot be greater than max connections".to_string());
        }
        Ok(())
    }
}

/// Database connection pool configuration
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: std::time::Duration,
    pub idle_timeout: std::time::Duration,
    pub max_lifetime: std::time::Duration,
}

impl From<&DatabaseConfig> for PoolConfig {
    fn from(config: &DatabaseConfig) -> Self {
        Self {
            max_connections: config.max_connections,
            min_connections: config.min_connections,
            connect_timeout: std::time::Duration::from_secs(config.connect_timeout),
            idle_timeout: std::time::Duration::from_secs(config.idle_timeout),
            max_lifetime: std::time::Duration::from_secs(3600), // 1 hour
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "sage_network");
    }

    #[test]
    fn test_database_url_generation() {
        let config = DatabaseConfig::default();
        let url = config.database_url();
        assert!(url.contains("postgresql://"));
        assert!(url.contains("sage_user"));
        assert!(url.contains("sage_network"));
    }

    #[test]
    fn test_config_validation() {
        let mut config = DatabaseConfig::default();
        assert!(config.validate().is_ok());

        config.host = "".to_string();
        assert!(config.validate().is_err());

        config.host = "localhost".to_string();
        config.max_connections = 0;
        assert!(config.validate().is_err());
    }
} 