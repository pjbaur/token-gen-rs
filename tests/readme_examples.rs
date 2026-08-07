//! Executable coverage for workflows documented in README.md.

#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
const CLI_PATH: &str = env!("CARGO_BIN_EXE_token-gen");
#[cfg(unix)]
const TEST_SECRET: &str = "readme-test-secret-at-least-32-bytes";

#[cfg(unix)]
#[test]
fn documented_cli_workflows_succeed() {
    const START: &str = "<!-- readme-cli-smoke:start -->";
    const END: &str = "<!-- readme-cli-smoke:end -->";

    let readme = include_str!("../README.md");
    let fenced_block = readme
        .split_once(START)
        .and_then(|(_, rest)| rest.split_once(END).map(|(block, _)| block))
        .expect("README should contain marked CLI smoke block")
        .trim();
    let script = fenced_block
        .strip_prefix("```bash\n")
        .and_then(|block| block.strip_suffix("\n```"))
        .expect("README CLI smoke block should be fenced as bash");

    let cli_dir = std::path::Path::new(CLI_PATH)
        .parent()
        .expect("CLI binary should have a parent directory");
    let path = std::env::join_paths(std::iter::once(cli_dir.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .expect("CLI path should be valid");

    let output = Command::new("bash")
        .args(["-c", &format!("set -euo pipefail\n{script}")])
        .env("PATH", path)
        .env("TOKEN_GEN_SECRET", TEST_SECRET)
        .output()
        .expect("README CLI workflow should start");

    assert!(
        output.status.success(),
        "README CLI workflow failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn readme_does_not_put_literal_secrets_on_token_gen_commands() {
    let readme = include_str!("../README.md");

    for line in readme.lines().filter(|line| line.contains("token-gen")) {
        assert!(
            !line.contains(" -s ") && !line.contains("--secret"),
            "README command exposes a literal secret: {line}"
        );
    }
}
