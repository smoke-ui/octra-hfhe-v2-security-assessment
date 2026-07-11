use bit_fault_atlas::{flip_bit, parse_bundle, write_schedule_jsonl, write_spans_jsonl};
use std::env;
use std::fs;
use std::io::{self, ErrorKind};

fn usage() -> &'static str {
    "usage:\n  bit-fault-atlas parse <bundle>\n  bit-fault-atlas spans <bundle>\n  bit-fault-atlas mutate <bundle> <absolute-bit> <output>\n  bit-fault-atlas schedule <bundle>"
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).ok_or_else(|| usage().to_owned())?;
    let path = args.get(2).ok_or_else(|| usage().to_owned())?;
    let data = fs::read(path).map_err(|e| format!("read {path}: {e}"))?;

    match command.as_str() {
        "parse" if args.len() == 3 => {
            let atlas = parse_bundle(&data).map_err(|e| e.to_string())?;
            println!(
                "{{\"type\":\"atlas\",\"bytes\":{},\"bits\":{},\"members\":{},\"spans\":{}}}",
                atlas.byte_len,
                atlas.total_bits(),
                atlas.members.len(),
                atlas.fields.len()
            );
            Ok(())
        }
        "spans" if args.len() == 3 => {
            let atlas = parse_bundle(&data).map_err(|e| e.to_string())?;
            ignore_broken_pipe(write_spans_jsonl(&atlas, io::stdout().lock()))
        }
        "mutate" if args.len() == 5 => {
            parse_bundle(&data).map_err(|e| format!("input does not parse: {e}"))?;
            let bit = args[3]
                .parse::<usize>()
                .map_err(|e| format!("invalid absolute bit coordinate: {e}"))?;
            let mutated = flip_bit(&data, bit)?;
            fs::write(&args[4], mutated).map_err(|e| format!("write {}: {e}", args[4]))
        }
        "schedule" if args.len() == 3 => {
            let atlas = parse_bundle(&data).map_err(|e| e.to_string())?;
            ignore_broken_pipe(write_schedule_jsonl(&atlas, io::stdout().lock()))
        }
        _ => Err(usage().to_owned()),
    }
}

fn ignore_broken_pipe(result: io::Result<()>) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("write JSONL: {e}")),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("bit-fault-atlas: {e}");
        std::process::exit(1);
    }
}
