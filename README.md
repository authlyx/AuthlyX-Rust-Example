# AuthlyX Rust SDK

Official Rust SDK and console example for AuthlyX V3 (3.0.0 beta).

Full documentation: https://docs.authlyx.dev

## Requirements

- Windows
- Rust 1.88 or newer

## Run the example

Put your app key and version in `src/main.rs`:

```rust
let app = match AuthlyX::new("YOUR_APP_KEY", "1.0.0").await {
```

Then run it:

```bat
cargo run --release
```

You can find your app key under your app's credentials in the [dashboard](https://dash.authlyx.dev).

## Add it to your own project

Copy `src/AuthlyX.rs` into your project, or add this repo as a path dependency. The dependencies it needs are listed in `Cargo.toml`.

```rust
use authlyx_sdk_v3::AuthlyX;

let app = AuthlyX::new("YOUR_APP_KEY", "1.0.0").await?;
let result = app.initialize().await?;
if !result.success {
    println!("{}", result.message);
}
```

Every call returns a `Result`. `?` handles SDK errors, and `success` tells you whether AuthlyX approved the request.

## Signing in

```rust
app.login("YOUR_USERNAME", "YOUR_PASSWORD").await?;
app.licenseLogin("YOUR_LICENSE_KEY").await?;
app.deviceLogin().await?;
```

Device login signs in the current Windows user without a form. The device has to be approved in your app first. See [Device login](https://docs.authlyx.dev/guides/device-login).

After signing in, the account details are in `userData`:

```rust
let user = app.userData();
let username = user["name"].as_str().unwrap_or_default();
let plan = user["plan"].as_str().unwrap_or_default();
let expiry = user["expiry"].as_str().unwrap_or_default();
```

Every method has its own page with examples under [SDK methods](https://docs.authlyx.dev/sdks/methods/login).

## Offline access

Once someone is signed in, saving offline access stores a signed permit on that PC:

```rust
let saved = app.saveOfflineAccess().await?;
let available = app.hasOfflineAccess().await;
```

If they open your app later without internet, they sign in with the same username and password or license key, and the SDK checks it against the saved permit. Each permit belongs to one app and one account, and signing out removes it. More in [Offline access](https://docs.authlyx.dev/guides/offline).

## Errors

An `Error` has a `code` and a `message` you can show to the user. When the server turns a request down you get a response with `success` set to false instead. All codes are listed in [Errors](https://docs.authlyx.dev/api-reference/errors).

## Coming from 2.4

V3 is a new SDK, not a drop-in update. Apps use an app key instead of the old owner ID, app name and secret, and the method names changed. Read [Move from V2 to V3](https://docs.authlyx.dev/api-reference/migration) before you switch.

## License

MIT. See `LICENSE.txt`.
