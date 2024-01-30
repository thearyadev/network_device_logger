use axum::{response::Html, routing::get, Extension, Router};
use network_device_logger::db::{Config, Database, to_time_since};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let shared_config = Arc::new(config);

    let app: Router = Router::new()
        .route("/", get(root))
        .route("/api/addrs", get(api_addrs))
        .layer(Extension(shared_config)); // config accessible in all routes

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> Html<&'static str> {
    Html(std::include_str!("./index.html"))
}

async fn api_addrs(Extension(config): Extension<Arc<Config>>) -> String {
    let db = Database::new(&config.DATABASE_FILE_PATH, &config.DATABASE_SEED_FILE_PATH);
    let records = db.get_all_records().unwrap(); // get all records
    let mut ordered_list = String::from("<ol class='addr_list'>");
    ordered_list.push_str("<li class='addr_list_item'><span class='ip_heading'>IP Address</span><span class='mac_heading'>MAC Address</span><span class='last_seen_heading'>Last Seen</span></li>");
    for record in records { // create list html 
        ordered_list.push_str(&format!(
            "<li class='addr_list_item'>
                <span class='ip'>{}</span>
                <span class='mac'>{}</span>
                <span class='last_seen'>{}</span>
            </li>",
            record.ip, record.mac, to_time_since(record.last_seen)

        ));
    }
    ordered_list.push_str("</ol>");
    ordered_list
}


