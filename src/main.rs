mod entry;
mod account;

use std::env;
use std::path::PathBuf;
use anyhow::{Result, anyhow};


fn extract_command(command: &String) -> &str {
    match command.find(' ') {
        None => { command }
        Some(value) => { &command[..value] }
    }
}

fn extract_name(command: &String) -> String {
    match command.find(' ') {
        None => { "".to_string() }
        Some(value) => { command[value + 1..].to_string() }
    }
}

fn read_password() -> Result<String> {
    return match rpassword::read_password() {
        Ok(pass) => {
            Ok(pass)
        },
        Err(_) => {
            Err(anyhow!("[ERROR]: Failed to read password, please try again!"))
        }
    }
}

fn main() {
    println!("Welcome to passenger! The best password manager to get your data stolen!");
    println!("Please sign up or login to get your doxing journey started (type help to see all commands): ");
    let mut password = String::new();
    let mut logged_in = false;

    loop {
        let mut command = String::new();

        match std::io::stdin().read_line(&mut command) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("[ERROR]: Failed to read command please try again: ");
                continue;
            }
        }

        let command_keyword = extract_command(&command).trim();
        let data = extract_name(&command).trim().to_string();

        match command_keyword {
            "signup" | "s" => {
                let mut path = env::var("APPDATA").map(PathBuf::from).unwrap_or(PathBuf::from("ERROR"));
                path.push("passenger");
                path.push("config.pass");
                if path.exists() {
                    println!("You already have an account!");
                    continue;
                }

                println!("Please type in your password (it is recommended to use a secure password)!");
                println!("IF YOU FORGET YOUR PASSWORD YOU WILL PERMANENTLY BE UNABLE TO OBTAIN ALL SAVED PASSWORDS!!!");
                password = read_password().unwrap_or(String::new());

                if let Err(result) = account::signup(&password) {
                    eprintln!("Failed to signup: {:?}", result);
                } else {
                    println!("Successfully signed up!");
                    logged_in = true;
                }
            }
            "login" | "l" => {
                println!("Please type in your password!");
                password = read_password().unwrap_or(String::new());

                if let Err(result) = account::login(&password) {
                    eprintln!("Failed to login: {:?}", result);
                } else {
                    println!("Successfully logged in!");
                    logged_in = true;
                }
            }
            "change" | "c" => {
                if !logged_in { println!("You haven't logged in or signed up yet!"); continue; }
                println!("Please type in your new password!");
                let new_password = read_password().unwrap_or(String::new());

                if let Err(result) = account::change(&password, &new_password) {
                    eprintln!("Failed to change password: {:?}", result)
                } else {
                    password = new_password;
                    println!("Successfully changed password!");
                }
            }
            "add" | "a" => {
                if !logged_in { println!("You haven't logged in or signed up yet!"); continue; }
                if let Err(result) = entry::add_entry(&password, data) {
                    eprintln!("Adding entry failed: {:?}", result)
                } else {
                    println!("Successfully added entry!");
                }
            }
            "remove" | "r" => {
                if !logged_in { println!("You haven't logged in or signed up yet!"); continue; }
                if let Err(result) = entry::remove_entry(data) {
                    eprintln!("Removing entry failed: {:?}", result)
                } else {
                    println!("Successfully removed entry!");
                }
            }
            "get" | "g" => {
                if !logged_in { println!("You haven't logged in or signed up yet!"); continue; }
                if let Err(result) = entry::get_entry(&password, data) {
                    eprintln!("{:?}", result)
                }
            }
            "quit" | "q" => {
                break;
            }
            "help" | "h" => {
                println!("signup              or s");
                println!("login               or l ");
                println!("change              or c");
                println!("add \"entry name\"    or a \"entry name\"");
                println!("remove \"entry name\" or r \"entry name\"");
                println!("get \"entry name\"    or g \"entry name\"");
                println!("quit                or q");
                println!("help                or h");

            }
            _ => {
                eprintln!("[ERROR]: Command: \"{}\" does not exist or was incorrectly used!", command_keyword.trim());
            }
        }
    }
}
