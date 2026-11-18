use authlyx_sdk_v3::{AuthlyX, Client, Error};
use serde_json::Value;
use std::io::{self, IsTerminal, Write};

fn interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn clear() {
    if !interactive() {
        return;
    }
    if cfg!(windows) {
        let _ = std::process::Command::new("cmd").args(["/c", "cls"]).status();
    } else {
        print!("\x1b[2J\x1b[H");
    }
}

fn title(text: &str) {
    clear();
    println!("AuthlyX  |  Rust example\n\n{text}\n");
}

fn ask(label: &str) -> String {
    print!("{label}: ");
    let _ = io::stdout().flush();
    let mut value = String::new();
    if io::stdin().read_line(&mut value).unwrap_or(0) == 0 {
        std::process::exit(0);
    }
    value.trim().to_owned()
}

fn pause() {
    ask("\nPress Enter to go back");
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(s) if s.is_empty() => "-".into(),
        Value::String(s) => s.clone(),
        Value::Bool(true) => "Yes".into(),
        Value::Bool(false) => "No".into(),
        other => other.to_string(),
    }
}

fn when(value: &Value) -> String {
    match value.as_str() {
        Some(s) if s.len() >= 16 => format!("{} {} UTC", &s[..10], &s[11..16]),
        _ => text(value),
    }
}

fn expiry(user: &Value) -> String {
    match user["expiry"].as_str() {
        Some(s) if s.len() >= 10 => s[..10].to_owned(),
        _ => "Never".into(),
    }
}

fn row(label: &str, value: &str) {
    println!("  {label:<16}{value}");
}

fn show_account(user: &Value) {
    title("Account details");
    match user["type"].as_str() {
        Some("license") => row("License key", &text(&user["name"])),
        Some("device") => row("Device", &text(&user["name"])),
        _ => {
            row("Username", &text(&user["name"]));
            if let Some(key) = user["licenseKey"].as_str().filter(|k| !k.is_empty()) {
                row("License key", key);
            }
        }
    }
    row("Email", &text(&user["email"]));
    row("Plan", &text(&user["plan"]));
    row("Expires", &expiry(user));
    let limit = &user["deviceLimit"];
    row("Device limit", &if limit.as_i64() == Some(0) { "Unlimited".into() } else { text(limit) });
    row("Registered", &when(&user["registeredAt"]));
    row("Last sign-in", &when(&user["lastLogin"]));
    row("System ID", &text(&user["systemId"]));
    row("IP address", &text(&user["ipAddress"]));
    row("Country", &text(&user["country"]));
}

fn show_list(heading: &str, values: &Value, empty: &str) {
    println!("{heading}");
    match values.as_object().filter(|v| !v.is_empty()) {
        None => println!("  {empty}"),
        Some(values) => {
            for (key, value) in values {
                row(key, &text(value));
            }
        }
    }
}

async fn sign_in(app: &Client, notice: &str) -> Option<String> {
    title("Sign in");
    if !notice.is_empty() {
        println!("{notice}\n");
    }
    println!("  1  Username and password\n  2  License key\n  3  This device\n  0  Exit\n");
    let result = match ask("Choose").as_str() {
        "1" => {
            let username = ask("Username");
            app.login(&username, &ask("Password")).await
        }
        "2" => app.licenseLogin(&ask("License key")).await,
        "3" => app.deviceLogin().await,
        "0" | "" => return None,
        _ => return Some("Choose 1, 2, 3 or 0.".into()),
    };
    Some(result.err().map(|error| error.message).unwrap_or_default())
}

async fn main_menu(app: &Client, notice: &str) -> Option<String> {
    let user = app.userData();
    title(&format!(
        "Signed in as {}  |  {} plan  |  Expires {}",
        text(&user["name"]),
        text(&user["plan"]),
        expiry(&user)
    ));
    if !notice.is_empty() {
        println!("{notice}\n");
    }
    println!(
        "  1  Account details          6  Check session\n\
         \x20 2  Read a variable          7  Send a log\n\
         \x20 3  Update a variable        8  Save offline access\n\
         \x20 4  Features and metadata    9  Sign out\n\
         \x20 5  Fetch a script           0  Exit\n"
    );
    let outcome: Result<(), Error> = match ask("Choose").as_str() {
        "0" | "" => return None,
        "1" => {
            show_account(&user);
            Ok(())
        }
        "2" => {
            let name = ask("Variable name");
            let result = app.getVariable(&name).await;
            title("Variable");
            result.map(|result| {
                row("Name", &name);
                row("Value", &text(&result.data["value"]));
            })
        }
        "3" => {
            let name = ask("Variable name");
            let value = ask("New value");
            let result = app.updateVariable(&name, &value).await;
            title("Update a variable");
            result.map(|result| println!("{}", result.message))
        }
        "4" => {
            let features = app.getFeatures().await;
            let metadata = app.getAllMetadata().await;
            title("Features and metadata");
            features.and_then(|features| {
                metadata.map(|metadata| {
                    show_list("Features", &features.data["features"], "No features on this plan.");
                    println!();
                    show_list("Metadata", &metadata.data["metadata"], "No metadata.");
                })
            })
        }
        "5" => {
            let name = ask("Script name");
            let result = app.getScript(&name, None).await;
            title(&format!("Script: {name}"));
            result.map(|result| println!("{}", text(&result.data["content"])))
        }
        "6" => {
            let result = app.checkSession().await;
            title("Session");
            result.map(|result| println!("{}", result.message))
        }
        "7" => {
            let message = ask("Log message");
            let result = app.log(&message).await;
            title("Send a log");
            result.map(|result| println!("{}", result.message))
        }
        "8" => {
            let result = app.saveOfflineAccess().await;
            title("Offline access");
            result.map(|result| println!("{}", result.message))
        }
        "9" => {
            return Some(match app.logout().await {
                Ok(()) => "You are signed out.".into(),
                Err(error) => error.message,
            })
        }
        _ => return Some("Choose one of the listed options.".into()),
    };
    if let Err(error) = outcome {
        println!("{}", error.message);
    }
    pause();
    Some(String::new())
}

#[tokio::main]
async fn main() {
    title("Connecting...");
    let app = match AuthlyX::new("test_09f6d82a741beb5078fbb11b49c178b3e03ec556a5d130fc", "1.0").await {
        Ok(app) => app,
        Err(error) => {
            println!("{}", error.message);
            std::process::exit(1);
        }
    };
    let start = loop {
        title("Connecting...");
        let message = match app.initialize().await {
            Ok(r) if r.ok() => break Some(if r.code == "OFFLINE_MODE" { r.message } else { String::new() }),
            Ok(r) => r.message,
            Err(error) => error.message,
        };
        title("Could not connect");
        println!("{message}");
        println!("\n  1  Try again\n  0  Exit\n");
        if ask("Choose") != "1" {
            break None;
        }
    };
    match start {
        None => {}
        Some(first) => {
            let mut notice = first;
            loop {
                let next = if app.hasAccess().await {
                    main_menu(&app, &notice).await
                } else {
                    sign_in(&app, &notice).await
                };
                match next {
                    Some(text) => notice = text,
                    None => break,
                }
            }
        }
    }
    app.close().await;
}
