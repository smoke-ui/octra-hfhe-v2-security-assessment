use std::fmt;
use std::io::{self, Write};

const BUNDLE_MAGIC: &[u8; 16] = b"OCTRA-HFHE-BTY02";
const PVAC_MAGIC: &[u8; 4] = b"PVAC";
const MAX_COUNT: u64 = 1 << 24;
const MAX_BITVEC_BITS: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}
impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn len(self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldSpan {
    pub path: String,
    pub kind: &'static str,
    pub span: Span,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberAtlas {
    pub index: usize,
    pub length: Span,
    pub record: Span,
    pub fields: Vec<FieldSpan>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Atlas {
    pub byte_len: usize,
    pub fields: Vec<FieldSpan>,
    pub members: Vec<MemberAtlas>,
}
impl Atlas {
    pub fn total_bits(&self) -> usize {
        self.byte_len * 8
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "at byte {}: {}", self.offset, self.message)
    }
}
impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: usize,
    fields: Vec<FieldSpan>,
}
impl<'a> Reader<'a> {
    fn new(data: &'a [u8], base: usize) -> Self {
        Self {
            data,
            pos: 0,
            base,
            fields: Vec::new(),
        }
    }
    fn err(&self, message: impl Into<String>) -> ParseError {
        ParseError {
            offset: self.base + self.pos,
            message: message.into(),
        }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn raw(&mut self, n: usize, path: String, kind: &'static str) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(self.err(format!("truncated: need {n}, have {}", self.remaining())));
        }
        let start = self.base + self.pos;
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        self.fields.push(FieldSpan {
            path,
            kind,
            span: Span::new(start, start + n),
        });
        Ok(bytes)
    }
    fn u8(&mut self, p: String, k: &'static str) -> Result<u8> {
        Ok(self.raw(1, p, k)?[0])
    }
    fn u16(&mut self, p: String, k: &'static str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.raw(2, p, k)?.try_into().unwrap()))
    }
    fn u32(&mut self, p: String, k: &'static str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.raw(4, p, k)?.try_into().unwrap()))
    }
    fn u64(&mut self, p: String, k: &'static str) -> Result<u64> {
        Ok(u64::from_le_bytes(self.raw(8, p, k)?.try_into().unwrap()))
    }
    fn count(&mut self, p: String, min: usize) -> Result<usize> {
        let n = self.u64(p, "count")?;
        if n > MAX_COUNT {
            return Err(self.err(format!("count exceeds maximum: {n}")));
        }
        let n = usize::try_from(n).map_err(|_| self.err("count does not fit usize"))?;
        if min != 0 && n > self.remaining() / min {
            return Err(self.err(format!("count {n} exceeds remaining data")));
        }
        Ok(n)
    }
    fn fp(&mut self, p: String) -> Result<()> {
        let b = self.raw(16, p, "fp")?;
        if b[15] & 0x80 != 0 {
            return Err(self.err("non-canonical Fp: bit 127 set"));
        }
        Ok(())
    }
}

fn parse_member(blob: &[u8], base: usize, index: usize) -> Result<Vec<FieldSpan>> {
    let root = format!("members[{index}]");
    let mut r = Reader::new(blob, base);
    if r.raw(4, format!("{root}.magic"), "magic")? != PVAC_MAGIC {
        return Err(r.err("bad PVAC magic"));
    }
    if r.u8(format!("{root}.version"), "version")? != 3 {
        return Err(r.err("bad PVAC version"));
    }
    if r.u8(format!("{root}.type_tag"), "tag")? != 0 {
        return Err(r.err("wrong PVAC type tag"));
    }
    let slots = r.u64(format!("{root}.slots"), "u64")?;
    if slots == 0 {
        return Err(r.err("zero cipher slots"));
    }
    let layers = r.count(format!("{root}.layers.count"), 1)?;
    for li in 0..layers {
        let p = format!("{root}.layers[{li}]");
        let rule = r.u8(format!("{p}.rule"), "rule")?;
        match rule {
            0 => {
                r.u64(format!("{p}.base.ztag"), "u64")?;
                r.raw(16, format!("{p}.base.nonce"), "nonce")?;
            }
            1 => {
                let pa = r.u32(format!("{p}.product.parent_a"), "u32")? as usize;
                let pb = r.u32(format!("{p}.product.parent_b"), "u32")? as usize;
                if pa >= li || pb >= li {
                    return Err(r.err(format!("invalid product parents at layer {li}")));
                }
            }
            _ => return Err(r.err(format!("invalid layer rule {rule}"))),
        }
        let pcs = r.count(format!("{p}.commitments.count"), 32)?;
        for ci in 0..pcs {
            r.raw(32, format!("{p}.commitments[{ci}]"), "commitment")?;
        }
    }
    let c0 = r.count(format!("{root}.c0.count"), 16)?;
    if c0 != 0 && c0 as u64 != slots {
        return Err(r.err("c0/slots mismatch"));
    }
    for i in 0..c0 {
        r.fp(format!("{root}.c0[{i}]"))?;
    }
    let edges = r.count(format!("{root}.edges.count"), 15)?;
    for ei in 0..edges {
        let p = format!("{root}.edges[{ei}]");
        let layer = r.u32(format!("{p}.layer_id"), "u32")? as usize;
        if layer >= layers {
            return Err(r.err(format!("edge layer {layer} out of range")));
        }
        r.u16(format!("{p}.index"), "u16")?;
        let sign = r.u8(format!("{p}.sign"), "sign")?;
        if sign > 1 {
            return Err(r.err(format!("invalid edge sign {sign}")));
        }
        let weights = r.count(format!("{p}.weights.count"), 16)?;
        if weights as u64 != slots {
            return Err(r.err("edge weight/slots mismatch"));
        }
        for wi in 0..weights {
            r.fp(format!("{p}.weights[{wi}]"))?;
        }
        let bits = r.u64(format!("{p}.bits.length"), "u64")?;
        if bits > MAX_BITVEC_BITS {
            return Err(r.err(format!("bit vector too large: {bits}")));
        }
        let words = r.count(format!("{p}.bits.words.count"), 8)?;
        let expected =
            usize::try_from(bits.div_ceil(64)).map_err(|_| r.err("bit-vector word overflow"))?;
        if words != expected {
            return Err(r.err(format!("bit-vector word mismatch: {words} != {expected}")));
        }
        for wi in 0..words {
            let raw = r.raw(8, format!("{p}.bits.words[{wi}]"), "bitvec_word")?;
            if wi + 1 == words && bits % 64 != 0 {
                let last = u64::from_le_bytes(raw.try_into().unwrap());
                if last >> (bits % 64) != 0 {
                    return Err(r.err("nonzero unused bit-vector tail bits"));
                }
            }
        }
    }
    if r.remaining() != 0 {
        return Err(r.err(format!("cipher trailing bytes: {}", r.remaining())));
    }
    Ok(r.fields)
}

pub fn parse_bundle(data: &[u8]) -> Result<Atlas> {
    let mut r = Reader::new(data, 0);
    if r.raw(16, "bundle.magic".into(), "magic")? != BUNDLE_MAGIC {
        return Err(r.err("bad bundle magic"));
    }
    let count = r.u64("bundle.members.count".into(), "count")?;
    if count == 0 || count > 1024 {
        return Err(r.err(format!("invalid cipher count {count}")));
    }
    let mut members = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let length_start = r.pos;
        let size64 = r.u64(format!("members[{index}].length"), "length")?;
        let size = usize::try_from(size64).map_err(|_| r.err("cipher length overflow"))?;
        if size == 0 || size > r.remaining() {
            return Err(r.err(format!("invalid cipher {index} length {size}")));
        }
        let start = r.pos;
        let blob = &r.data[start..start + size];
        r.pos += size;
        let member_fields = parse_member(blob, start, index).map_err(|mut e| {
            e.message = format!("cipher {index}: {}", e.message);
            e
        })?;
        r.fields.extend(member_fields.iter().cloned());
        members.push(MemberAtlas {
            index,
            length: Span::new(length_start, length_start + 8),
            record: Span::new(start, start + size),
            fields: member_fields,
        });
    }
    if r.remaining() != 0 {
        return Err(r.err(format!("bundle trailing bytes: {}", r.remaining())));
    }
    Ok(Atlas {
        byte_len: data.len(),
        fields: r.fields,
        members,
    })
}

pub fn flip_bit(data: &[u8], absolute_bit: usize) -> std::result::Result<Vec<u8>, String> {
    if absolute_bit >= data.len().checked_mul(8).ok_or("bit length overflow")? {
        return Err(format!("bit coordinate {absolute_bit} out of range"));
    }
    let mut out = data.to_vec();
    out[absolute_bit / 8] ^= 1 << (absolute_bit % 8);
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitCoordinate<'a> {
    pub absolute_bit: usize,
    pub byte_offset: usize,
    pub bit_in_byte: u8,
    pub field_path: &'a str,
    pub field_kind: &'static str,
}

pub struct BitCoordinates<'a> {
    atlas: &'a Atlas,
    next: usize,
    field: usize,
}
impl<'a> Iterator for BitCoordinates<'a> {
    type Item = BitCoordinate<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.atlas.total_bits() {
            return None;
        }
        let byte = self.next / 8;
        while self.field + 1 < self.atlas.fields.len()
            && byte >= self.atlas.fields[self.field].span.end
        {
            self.field += 1;
        }
        let f = &self.atlas.fields[self.field];
        let out = BitCoordinate {
            absolute_bit: self.next,
            byte_offset: byte,
            bit_in_byte: (self.next % 8) as u8,
            field_path: &f.path,
            field_kind: f.kind,
        };
        self.next += 1;
        Some(out)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.atlas.total_bits() - self.next;
        (n, Some(n))
    }
}
impl ExactSizeIterator for BitCoordinates<'_> {}
pub fn bit_coordinates(atlas: &Atlas) -> BitCoordinates<'_> {
    BitCoordinates {
        atlas,
        next: 0,
        field: 0,
    }
}

fn escaped_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn write_spans_jsonl(atlas: &Atlas, mut out: impl Write) -> io::Result<()> {
    for f in &atlas.fields {
        writeln!(
            out,
            "{{\"type\":\"span\",\"path\":{},\"kind\":\"{}\",\"start\":{},\"end\":{}}}",
            escaped_json(&f.path),
            f.kind,
            f.span.start,
            f.span.end
        )?;
    }
    Ok(())
}
pub fn write_schedule_jsonl(atlas: &Atlas, mut out: impl Write) -> io::Result<()> {
    for c in bit_coordinates(atlas) {
        writeln!(
            out,
            "{{\"type\":\"bit\",\"absolute_bit\":{},\"byte_offset\":{},\"bit_in_byte\":{},\"path\":{},\"kind\":\"{}\"}}",
            c.absolute_bit,
            c.byte_offset,
            c.bit_in_byte,
            escaped_json(c.field_path),
            c.field_kind
        )?;
    }
    Ok(())
}
