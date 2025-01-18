use dotenv::dotenv;
use std::env;
use tracing::Level;

pub struct Config {
    pub ws_url: String,
    pub app_port: u16,
    pub log_level: Level,
}

impl Config {
    pub fn from_env() -> Self {
        // Load the .env file
        dotenv().ok();

        let ws_url = env::var("WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());
        let app_port: u16 = env::var("APP_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .expect("APP_PORT must be a valid number");
        let log_level = env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info".to_string())
            .parse::<Level>()
            .unwrap_or(Level::INFO);

        // Return the configuration
        Config {
            ws_url,
            app_port,
            log_level,
        }
    }
}
