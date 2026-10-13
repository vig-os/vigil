//! Operator commands for durable audit trails (ADR-0005 decision 11).
mod args;
mod commands;
mod output;

fn main() -> std::process::ExitCode {
    let mut output = output::Output::default();
    let result = args::parse(std::env::args_os().skip(1))
        .map_err(|detail| output::Failure(2, format!("Usage: {detail}")))
        .and_then(|command| commands::run(command, &mut output));
    let flushed = output.flush();
    if let Err(output::Failure(code, detail)) = flushed.and(result) {
        eprintln!("error: {detail}");
        return code.into();
    }
    std::process::ExitCode::SUCCESS
}
