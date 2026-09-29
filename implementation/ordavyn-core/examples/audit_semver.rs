//! Verification-only JSON bridge to the Rust `semver` implementation.
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
struct Query {
    version: String,
    requirements: Vec<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Answer {
    Matches { matches: Vec<bool> },
    Error { error: &'static str },
}

fn evaluate(query: Query) -> Answer {
    let Ok(version) = Version::parse(&query.version) else {
        return Answer::Error {
            error: "invalid version",
        };
    };
    let mut matches = Vec::with_capacity(query.requirements.len());
    for requirement in query.requirements {
        let Ok(requirement) = VersionReq::parse(&requirement) else {
            return Answer::Error {
                error: "invalid requirement",
            };
        };
        matches.push(requirement.matches(&version));
    }
    Answer::Matches { matches }
}

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(2);
    }
    let Ok(queries) = serde_json::from_str::<Vec<Query>>(&input) else {
        std::process::exit(2);
    };
    let answers: Vec<_> = queries.into_iter().map(evaluate).collect();
    match serde_json::to_writer(io::stdout(), &answers) {
        Ok(()) => println!(),
        Err(_) => std::process::exit(2),
    }
}
