use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

type Head = (u64, [u8; 32]);

pub(super) enum Command {
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

pub(super) fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, String> {
    let command = args.next().ok_or("missing command")?;
    let command = command.to_str().ok_or("invalid command")?;
    let flags: &[&str] = match command {
        "keygen" | "checkpoints" => &[],
        "create" => &["--key", "--service"],
        "checkpoint" => &["--key", "--expect-head"],
        "rotate" => &["--key", "--actor", "--reason", "--bound", "--expect-head"],
        "resume" => &["--key", "--actor", "--reason", "--head", "--lost-through"],
        _ => return Err(format!("unknown command: {command}")),
    };
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
    for flag in flags {
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
