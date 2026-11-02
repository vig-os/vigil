use super::{
    args::Command,
    output::{Failure, Output, hex},
};
use std::sync::Arc;
use vigil::audit::{AuditConfig, KeyFileSigner, checkpoints, keygen};

pub(super) fn run(command: Command, output: &mut Output) -> Result<(), Failure> {
    match command {
        Command::Help(text) => output.line(text),
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
            actor,
            reason,
            bound,
            head,
            dir,
        } => {
            let (receipt, checkpoint) = AuditConfig::new("vigil-audit").dir(dir).rotate(
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
            actor,
            reason,
            head,
            lost,
            dir,
        } => {
            let (trail, receipt, opening) = AuditConfig::new("vigil-audit").dir(dir).resume(
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
