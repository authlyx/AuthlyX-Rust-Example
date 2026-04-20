# AuthlyX Rust SDK

This is a Rust authentication SDK for desktop and CLI applications that want simple integration with the AuthlyX API.

This folder includes the SDK in `src/authlyx.rs` and a runnable example in `src/main.rs`.

## Requirements

- Rust
- Cargo

## Quick Start

```rust
mod authlyx;

use authlyx::AuthlyX;

fn main() {
    let mut authlyx_app = AuthlyX::new(
        "12345678",
        "MYAPP",
        "1.0.0",
        "your-secret",
        true,
        None,
    );

    authlyx_app.init();
}
```

## Optional Parameters

```rust
let mut authlyx_app = AuthlyX::new(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false,
    Some("https://example.com/api/v2"),
);
```

### Available options

- `debug`
  - Default: `true`
  - Set `false` to disable SDK logs

- `api`
  - Default: `https://authly.cc/api/v2`
  - Use this for your custom domain

## Available Methods

- `init()`
- `login(identifier, password, device_type)`
- `register(username, password, license_key, email)`
- `change_password(old_password, new_password)`
- `extend_time(username, license_key)`
- `get_variable(key)`
- `set_variable(key, value)`
- `validate_session()`

## Authentication Example

```rust
// Username + password
authlyx_app.login("username", Some("password"), None);

// License key only
authlyx_app.login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", None, None);

// Device login
authlyx_app.login("YOUR_MOTHERBOARD_ID", None, Some("motherboard"));
```

## Username Login Example

```rust
authlyx_app.login("username", Some("password"), None);

if authlyx_app.response.success {
    println!("Login success");
    println!("{}", authlyx_app.user_data.username);
    println!("{}", authlyx_app.user_data.subscription_level);
} else {
    println!("{}", authlyx_app.response.message);
}
```

## Variable Example

```rust
authlyx_app.set_variable("theme", "dark");

let value = authlyx_app.get_variable("theme").unwrap_or_default();
println!("{}", value);
```

## Logging

By default, SDK logging is enabled.

Logs are written to:

`C:\ProgramData\AuthlyX\{AppName}\YYYY_MM_DD.log`

To disable logs:

```rust
let mut authlyx_app = AuthlyX::new(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false,
    None,
);
```

Sensitive values such as passwords, secrets, session IDs, request IDs, nonces, license keys, and hashes are masked automatically.

## Example Project

The runnable example in `src/main.rs` uses the public test app by default for `init()`.

If you want to run the authenticated example too, set:

- `AUTHLYX_USERNAME`
- `AUTHLYX_PASSWORD`

Then run:

```powershell
cargo run
```
