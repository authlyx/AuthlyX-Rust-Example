mod authlyx;

use authlyx::AuthlyX;

fn show_result(title: &str, sdk: &AuthlyX) {
    let r = &sdk.response;
    let status = if r.success { "SUCCESS" } else { "FAILED" };
    println!();
    println!("{}: {}", title, status);
    println!("Message: {}", r.message);
    if !r.code.is_empty() {
        println!("Code: {}", r.code);
    }
    if r.status_code != 0 {
        println!("Status: {}", r.status_code);
    }
}

fn show_user(sdk: &AuthlyX) {
    let u = &sdk.user_data;
    println!();
    println!("USER PROFILE");
    println!("==============================================");
    println!("Username: {}", if u.username.is_empty() { "N/A" } else { &u.username });
    println!("Email: {}", if u.email.is_empty() { "N/A" } else { &u.email });
    println!("License Key: {}", if u.license_key.is_empty() { "N/A" } else { &u.license_key });
    println!("Subscription: {}", if u.subscription.is_empty() { "N/A" } else { &u.subscription });
    println!(
        "Subscription Level: {}",
        if u.subscription_level.is_empty() { "N/A" } else { &u.subscription_level }
    );
    println!("Expiry Date: {}", if u.expiry_date.is_empty() { "N/A" } else { &u.expiry_date });
    println!("Days Left: {}", u.days_left);
    println!("Last Login: {}", if u.last_login.is_empty() { "N/A" } else { &u.last_login });
    println!(
        "Registered At: {}",
        if u.registered_at.is_empty() { "N/A" } else { &u.registered_at }
    );
    println!("HWID/SID: {}", if u.hwid.is_empty() { "N/A" } else { &u.hwid });
    println!("IP Address: {}", if u.ip_address.is_empty() { "N/A" } else { &u.ip_address });
    println!("==============================================");
}

fn main() {
    let api = std::env::var("AUTHLYX_API").unwrap_or_else(|_| "https://authly.cc/api/v2".to_string());

    let mut sdk = AuthlyX::new(
        "12345678",
        "HI",
        "1.3",
        "your-secret",
        true,
        Some(&api),
    );

    sdk.init();
    show_result("Init", &sdk);
    if !sdk.response.success {
        return;
    }

    sdk.login("username", Some("password"), None);
    show_result("Login", &sdk);
    show_user(&sdk);

    sdk.set_variable("theme", "dark");
    show_result("Set Variable", &sdk);

    let value = sdk.get_variable("theme").unwrap_or_default();
    show_result("Get Variable", &sdk);
    if sdk.response.success {
        println!("Value: {}", value);
    }

    sdk.validate_session();
    show_result("Validate Session", &sdk);
}

