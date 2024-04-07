# Passenger - CLI Password Manager

Passenger is a command-line interface (CLI) password manager designed for simplicity and security, built with Rust. It allows you to securely store, retrieve, and manage your passwords from the terminal. With Passenger, your passwords are encrypted and accessible only through your master password.

## Features

- **Securely store passwords** with robust encryption.
- **Simple CLI** for easy navigation and password management.
- **Add, remove, and retrieve passwords** with straightforward commands.
- **Change your master password** anytime to ensure maximum security.
- **Built with Rust** for performance and safety.

## Installation

Before installing Passenger, make sure you have Rust and Cargo installed on your system. If you don't have them installed, visit [The Rust Programming Language website](https://www.rust-lang.org/tools/install) for installation instructions.

To install Passenger, clone the repository and build the project using Cargo:

```bash
git clone https://github.com/yourusername/passenger.git
cd passenger
cargo build --release
```

## Usage
To start using Passenger, you first need to sign up with a master password. This password will encrypt your vault and will be required for subsequent logins.

- signup    or s   - Sign up with a master password.
- login     or l   - Login with your master password.
- change    or c   - Change your master password.
- add       or a   - Add a new entry. Specify the entry name.
- remove    or r   - Remove an entry. Specify the entry name.
- get       or g   - Retrieve an entry's details. Specify the entry name.
- quit      or q   - Quit the application.
- help      or h   - Display help information.
