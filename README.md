# AuthlyX Rust Example

This is a Rust example project demonstrating how to integrate with the AuthlyX v2 API.

## Requirements

- Rust (rustc + cargo)

## Quick Start

1. Open `src/main.rs` and set your credentials.
2. Run:

```powershell
cargo run
```

## What This Example Covers

- `init()`
- Unified `login(...)`:
  - username/password
  - license key
  - device (motherboard / processor)
- Variables (`get_variable`, `set_variable`)
- Chats (`get_chats`, `send_chat`)
- Extend time (`extend_time`)
- Change password (`change_password`)
- Validate session (`validate_session`)

