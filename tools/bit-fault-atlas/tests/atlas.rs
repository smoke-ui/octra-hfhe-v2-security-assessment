use bit_fault_atlas::{Span, bit_coordinates, flip_bit, parse_bundle};
use std::fs;
use std::path::PathBuf;

fn published() -> Vec<u8> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.deps/hfhe-challenge/secret.ct");
    fs::read(path).expect("pinned published secret.ct must be present")
}

#[test]
fn published_member_zero_offsets_are_semantic() {
    let atlas = parse_bundle(&published()).unwrap();
    assert_eq!(atlas.byte_len, 1_963_107);
    assert_eq!(atlas.members.len(), 22);
    let m = &atlas.members[0];
    assert_eq!(m.length, Span::new(24, 32));
    assert_eq!(m.record.start, 32);
    assert_eq!(m.fields[0].path, "members[0].magic");
    assert_eq!(m.fields[0].span, Span::new(32, 36));
    assert_eq!(m.fields[1].path, "members[0].version");
    assert_eq!(m.fields[1].span, Span::new(36, 37));
    assert_eq!(m.fields[2].path, "members[0].type_tag");
    assert_eq!(m.fields[2].span, Span::new(37, 38));
    assert_eq!(m.fields[3].path, "members[0].slots");
    assert_eq!(m.fields[3].span, Span::new(38, 46));
    assert_eq!(m.fields[4].path, "members[0].layers.count");
    assert_eq!(m.fields[4].span, Span::new(46, 54));
}

#[test]
fn fp_bit_127_is_rejected_as_noncanonical() {
    let data = published();
    let atlas = parse_bundle(&data).unwrap();
    let fp = atlas.fields.iter().find(|f| f.kind == "fp").unwrap();
    let mutated = flip_bit(&data, fp.span.start * 8 + 127).unwrap();
    let error = parse_bundle(&mutated).unwrap_err();
    assert!(error.to_string().contains("non-canonical Fp"));
}

#[test]
fn every_truncation_near_eof_is_rejected() {
    let data = published();
    for removed in 1..=16 {
        assert!(parse_bundle(&data[..data.len() - removed]).is_err());
    }
}

#[test]
fn published_schedule_has_exact_total_and_is_lazy() {
    let atlas = parse_bundle(&published()).unwrap();
    assert_eq!(atlas.total_bits(), 15_704_856);
    let mut coordinates = bit_coordinates(&atlas);
    assert_eq!(coordinates.size_hint(), (15_704_856, Some(15_704_856)));
    let first = coordinates.next().unwrap();
    assert_eq!(first.absolute_bit, 0);
    assert_eq!(first.byte_offset, 0);
    assert_eq!(first.bit_in_byte, 0);
    assert_eq!(coordinates.last().unwrap().absolute_bit, 15_704_855);
}

#[test]
fn exact_eof_rejects_trailing_bytes() {
    let mut data = published();
    data.push(0);
    assert!(
        parse_bundle(&data)
            .unwrap_err()
            .to_string()
            .contains("trailing")
    );
}
