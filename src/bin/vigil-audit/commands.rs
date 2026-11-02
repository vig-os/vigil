use super::{
    args::Command,
    output::{Failure, Output, hex},
};
use std::{path::Path, sync::Arc};
use vigil::audit::{AuditConfig, KeyFileSigner, RecordSchema, checkpoints, keygen};

pub(super) fn run(command: Command, output: &mut Output) -> Result<(), Failure> {
    match command {
        Command::Help(text) => output.line(text),
        Command::Schema(path) => output.line(read_schema(&path)?.digest_string()),
        Command::Keygen(path) => output.line(hex(&keygen(path)?)),
        Command::Checkpoints(dir) => {
            for checkpoint in checkpoints(&dir)? {
                output.checkpoint(&checkpoint);
            }
        }
        Command::Create { key, service, dir } => {
            let trail = AuditConfig::new(service)
                .dir(dir)
                .create(Arc::new(KeyFileSigner::load(key)?))?;
            output.line(hex(&trail.trail()));
            output.checkpoint(&trail.close()?);
        }
        Command::Checkpoint { key, head, dir } => {
            let checkpoint = AuditConfig::new("vigil-audit")
                .dir(dir)
                .checkpoint(Arc::new(KeyFileSigner::load(key)?), head)?;
            output.checkpoint_receipt(&checkpoint);
            output.checkpoint(&checkpoint);
        }
        Command::Rotate {
            key,
            schema,
            actor,
            reason,
            bound,
            head,
            dir,
        } => {
            let (receipt, checkpoint) = operator_config(dir, schema)?.rotate(
                Arc::new(KeyFileSigner::load(key)?),
                bound,
                head,
                actor,
                reason,
            )?;
            output.receipt(&receipt);
            output.checkpoint(&checkpoint);
        }
        Command::Resume {
            key,
            schema,
            actor,
            reason,
            head,
            lost,
            dir,
        } => {
            let (trail, receipt, opening) = operator_config(dir, schema)?.resume(
                Arc::new(KeyFileSigner::load(key)?),
                head,
                lost,
                actor,
                reason,
            )?;
            output.checkpoint(&opening);
            output.receipt(&receipt);
            output.checkpoint(&trail.close()?);
        }
    }
    Ok(())
}

fn read_schema(path: &Path) -> Result<RecordSchema, Failure> {
    Ok(RecordSchema::parse(&std::fs::read_to_string(path)?)?)
}

fn operator_config(
    dir: std::path::PathBuf,
    schema: Option<std::path::PathBuf>,
) -> Result<AuditConfig, Failure> {
    let config = AuditConfig::new("vigil-audit").dir(dir);
    Ok(match schema {
        Some(path) => config.schema(read_schema(&path)?),
        None => config,
    })
}
