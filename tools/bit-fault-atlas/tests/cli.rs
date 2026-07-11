use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn published_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.deps/hfhe-challenge/secret.ct")
}

#[test]
fn spans_command_emits_json_lines() {
    let out = Command::new(env!("CARGO_BIN_EXE_bit-fault-atlas"))
        .args(["spans", published_path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.lines()
            .next()
            .unwrap()
            .contains("\"path\":\"bundle.magic\"")
    );
    assert!(text.lines().count() > 1_000);
}

#[test]
fn mutate_command_flips_exactly_one_requested_bit() {
    let dir = std::env::temp_dir();
    let output = dir.join(format!("bit-fault-atlas-{}.ct", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_bit-fault-atlas"))
        .args([
            "mutate",
            published_path().to_str().unwrap(),
            "0",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let before = fs::read(published_path()).unwrap();
    let after = fs::read(&output).unwrap();
    fs::remove_file(output).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before[0] ^ after[0], 1);
    assert_eq!(&before[1..], &after[1..]);
}
