//! Subprocess recovery probe used by tests/test_journal_recovery.py. Local files only.
use ordavyn_core::{Identifier, Journal};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};
fn checkpoint(label: &str) {
    println!("{label}");
    io::stdout().flush().unwrap();
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).unwrap();
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let recipient = Identifier {
        namespace: "participant".into(),
        value: "service".into(),
        version: Some(u64::MAX),
    };
    let mode = &args[1];
    let path = &args[2];
    if mode == "create" {
        match Journal::create(path, recipient, 2) {
            Ok(j) => {
                j.close().unwrap();
                println!("created")
            }
            Err(_) => println!("rejected"),
        };
        return;
    }
    let j = match Journal::open(path, recipient, 2) {
        Ok(j) => Arc::new(j),
        Err(_) => {
            println!("rejected");
            return;
        }
    };
    if mode == "inspect" {
        for row in j.inspect().unwrap() {
            println!("{:?}", row.state)
        }
        j.close().unwrap();
        return;
    }
    let sender = Identifier::new("participant", "caller");
    let message = Identifier {
        namespace: "message".into(),
        value: args[4].clone(),
        version: Some(u64::MAX),
    };
    let operation = Identifier::new("logical-operation", &args[5]);
    checkpoint("ready");
    let reservation = match j.reserve(&sender, &message, &operation) {
        Ok(r) => r,
        Err(_) => {
            println!("rejected");
            return;
        }
    };
    checkpoint("reserved");
    let mut effect = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args[3])
        .unwrap();
    effect.write_all(b"effect\n").unwrap();
    effect.sync_all().unwrap();
    checkpoint("effect");
    if reservation.complete().is_err() {
        println!("rejected");
        return;
    }
    checkpoint("completed");
    drop(reservation);
    j.close().unwrap();
    println!("done");
}
