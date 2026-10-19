use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

type Head = (u64, [u8; 32]);

pub(super) enum Command {
    Help(String),
    Keygen(PathBuf),
    Checkpoints(PathBuf),
    Create {
        key: PathBuf,
        service: String,
        dir: PathBuf,
    },
    Checkpoint {
        key: PathBuf,
        head: Head,
        dir: PathBuf,
    },
    Rotate {
        key: PathBuf,
        actor: String,
        reason: String,
        bound: Head,
        head: Head,
        dir: PathBuf,
    },
    Resume {
        key: PathBuf,
        actor: String,
        reason: String,
        head: Head,
        lost: u64,
        dir: PathBuf,
    },
}

// ADR-0005 decision 11 is the source of these command arguments.
const COMMANDS: &[(&str, &str, &str)] = &[
    (
        "checkpoints",
        "<dir>",
        "Print checkpoint lines in sequence order.",
    ),
    (
        "checkpoint",
        "--key <keyfile> --expect-head <seq>:<hash> <dir>",
        "Sign a checkpoint at the expected head.",
    ),
    (
        "rotate",
        "--key <keyfile> --actor <who> --reason <why> --bound <seq>:<hash> --expect-head <seq>:<hash> <dir>",
        "Record a key rotation and sign a checkpoint.",
    ),
    (
        "create",
        "--key <keyfile> --service <name> <dir>",
        "Create a new audit trail.",
    ),
    (
        "resume",
        "--key <keyfile> --actor <who> --reason <why> --head <seq>:<hash> --lost-through <seq> <dir>",
        "Resume a trail after operator-confirmed loss.",
    ),
    (
        "keygen",
        "<keyfile>",
        "Generate a signing key and public key file.",
    ),
];

pub(super) fn usage(full: bool) -> String {
    let mut text = String::from("Usage:\n");
    for (name, arguments, description) in COMMANDS {
        text.push_str(&format!("  vigil-audit {name} {arguments}\n"));
        if full {
            text.push_str(&format!("    {description}\n"));
        }
    }
    text.push_str("  verify: not yet available (#13)\n");
    if full {
        text.push_str("\nUse vigil-audit <command> --help for command help.\n\nExit codes:\n  0  Success\n  1  AuditError or SignerError (except Io/InvalidConfig)\n  2  Usage, Io or InvalidConfig error\n");
    }
    text
}

pub(super) fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, String> {
    let command = args.next().ok_or("missing command")?;
    let command = command.to_str().ok_or("invalid command")?;
    let rest: Vec<_> = args.collect();
    if matches!(command, "--help" | "-h" | "help") && rest.is_empty() {
        return Ok(Command::Help(usage(true)));
    }
    let spec = COMMANDS
        .iter()
        .find(|spec| spec.0 == command)
        .ok_or_else(|| format!("unknown command: {command}"))?;
    if rest == [OsString::from("--help")] {
        return Ok(Command::Help(format!(
            "Usage: vigil-audit {} {}\n{}\n",
            spec.0, spec.1, spec.2
        )));
    }
    let flags: Vec<_> = spec
        .1
        .split_whitespace()
        .filter(|arg| arg.starts_with("--"))
        .collect();
    let mut args = rest.into_iter();
    let mut options = BTreeMap::new();
    let mut dir = None;
    while let Some(arg) = args.next() {
        if arg.as_encoded_bytes().starts_with(b"--") {
            let flag = arg.to_str().ok_or("invalid option")?.to_owned();
            if !flags.contains(&flag.as_str()) || options.contains_key(&flag) {
                return Err(format!("unknown or duplicate option: {flag}"));
            }
            options.insert(flag, args.next().ok_or("missing option value")?);
        } else if dir.replace(PathBuf::from(arg)).is_some() {
            return Err("unexpected positional argument".into());
        }
    }
    for flag in &flags {
        if !options.contains_key(*flag) {
            return Err(format!("missing {flag}"));
        }
    }
    let dir = dir.ok_or("missing path")?;
    let key = || PathBuf::from(&options["--key"]);
    let text = |flag: &str| {
        options[flag]
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{flag} requires UTF-8"))
    };
    Ok(match command {
        "keygen" => Command::Keygen(dir),
        "checkpoints" => Command::Checkpoints(dir),
        "create" => Command::Create {
            key: key(),
            service: text("--service")?,
            dir,
        },
        "checkpoint" => Command::Checkpoint {
            key: key(),
            head: head(&text("--expect-head")?)?,
            dir,
        },
        "rotate" => Command::Rotate {
            key: key(),
            actor: text("--actor")?,
            reason: text("--reason")?,
            bound: head(&text("--bound")?)?,
            head: head(&text("--expect-head")?)?,
            dir,
        },
        "resume" => Command::Resume {
            key: key(),
            actor: text("--actor")?,
            reason: text("--reason")?,
            head: head(&text("--head")?)?,
            lost: text("--lost-through")?
                .parse()
                .map_err(|_| "invalid --lost-through")?,
            dir,
        },
        _ => unreachable!(),
    })
}

fn head(value: &str) -> Result<Head, String> {
    let invalid = || "head must be <seq>:blake3:<64 lowercase hex>".to_owned();
    let (seq, hash) = value.split_once(":blake3:").ok_or_else(invalid)?;
    if seq.is_empty()
        || !seq.bytes().all(|b| b.is_ascii_digit())
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[2 * i..2 * i + 2], 16).map_err(|_| invalid())?;
    }
    Ok((seq.parse().map_err(|_| invalid())?, bytes))
}
