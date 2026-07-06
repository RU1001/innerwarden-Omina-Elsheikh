use std::process::Command;

/// Invoke the real binary in dry-run with a tempdir config and assert the
/// command reaches the dispatch arm + Discord configure path. Covers the
/// `notify discord` / `config discord` clap dispatch (spec 078 P3b).
fn run_discord(subcommand: &[&str]) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let sensor = tmp.path().join("config.toml");
    let agent = tmp.path().join("agent.toml");
    std::fs::write(&sensor, "").expect("write sensor config");
    std::fs::write(&agent, "").expect("write agent config");

    let mut args: Vec<String> = vec![
        "--dry-run".into(),
        "--sensor-config".into(),
        sensor.to_string_lossy().into_owned(),
        "--agent-config".into(),
        agent.to_string_lossy().into_owned(),
        "--data-dir".into(),
        tmp.path().to_string_lossy().into_owned(),
    ];
    args.extend(subcommand.iter().map(|s| s.to_string()));

    let output = Command::new(env!("CARGO_BIN_EXE_innerwarden-ctl"))
        .args(&args)
        .output()
        .expect("run innerwarden-ctl");

    assert!(
        output.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("discord.enabled") || stdout.contains("[dry-run]"),
        "unexpected stdout:\n{stdout}"
    );
}

#[test]
fn notify_discord_dry_run_goes_through_cli_dispatch() {
    run_discord(&[
        "notify",
        "discord",
        "--webhook-url",
        "https://discord.com/api/webhooks/123456789/AbCdEf-token",
        "--no-test",
    ]);
}

#[test]
fn config_discord_dry_run_goes_through_cli_dispatch() {
    run_discord(&[
        "config",
        "discord",
        "--webhook-url",
        "https://discord.com/api/webhooks/123456789/AbCdEf-token",
        "--no-test",
    ]);
}
