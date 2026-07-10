use std::collections::HashSet;
use std::env;
use std::fs;

const BUNDLE_MAGIC: &[u8; 16] = b"OCTRA-HFHE-BTY02";
const PVAC_MAGIC: &[u8; 4] = b"PVAC";
const PVAC_VERSION: u8 = 3;
const CIPHER_TAG: u8 = 0;
const MAX_COUNT: u64 = 1 << 24;
const MAX_BITVEC_BITS: u64 = 1 << 20;

#[derive(Debug)]
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.remaining() {
            return Err(format!(
                "truncated at {}: need {n}, have {}",
                self.pos,
                self.remaining()
            ));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn count(&mut self, element_min: usize) -> Result<usize, String> {
        let n = self.u64()?;
        if n > MAX_COUNT {
            return Err(format!("count exceeds maximum: {n}"));
        }
        let n = usize::try_from(n).map_err(|_| "count does not fit usize")?;
        if element_min > 0 && n > self.remaining() / element_min {
            return Err(format!("count {n} exceeds remaining data"));
        }
        Ok(n)
    }
    fn fp(&mut self) -> Result<(), String> {
        let _lo = self.u64()?;
        let hi = self.u64()?;
        if hi >> 63 != 0 {
            return Err("non-canonical Fp top bit set".into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct Stats {
    ciphers: usize,
    layers: usize,
    base_layers: usize,
    product_layers: usize,
    edges: usize,
    commitments: usize,
    nonces: HashSet<(u64, u64)>,
    duplicate_nonces: usize,
}

fn parse_cipher(blob: &[u8], stats: &mut Stats) -> Result<(), String> {
    let mut r = Reader::new(blob);
    if r.take(4)? != PVAC_MAGIC {
        return Err("bad PVAC magic".into());
    }
    if r.u8()? != PVAC_VERSION {
        return Err("bad PVAC version".into());
    }
    if r.u8()? != CIPHER_TAG {
        return Err("wrong PVAC type tag".into());
    }

    let slots = r.u64()?;
    if slots == 0 {
        return Err("zero cipher slots".into());
    }
    let layer_count = r.count(1)?;
    let mut layer_rules = Vec::with_capacity(layer_count);
    for layer_id in 0..layer_count {
        let rule = r.u8()?;
        match rule {
            0 => {
                let _ztag = r.u64()?;
                let lo = r.u64()?;
                let hi = r.u64()?;
                if !stats.nonces.insert((lo, hi)) {
                    stats.duplicate_nonces += 1;
                }
                stats.base_layers += 1;
            }
            1 => {
                let pa = r.u32()? as usize;
                let pb = r.u32()? as usize;
                if pa >= layer_id || pb >= layer_id {
                    return Err(format!("invalid product parents at layer {layer_id}"));
                }
                stats.product_layers += 1;
            }
            _ => return Err(format!("invalid layer rule {rule}")),
        }
        let pc_count = r.count(32)?;
        r.take(pc_count.checked_mul(32).ok_or("commitment size overflow")?)?;
        stats.commitments += pc_count;
        layer_rules.push(rule);
    }

    let c0_count = r.count(16)?;
    if c0_count != 0 && c0_count as u64 != slots {
        return Err("c0/slots mismatch".into());
    }
    for _ in 0..c0_count {
        r.fp()?;
    }

    let edge_count = r.count(4 + 2 + 1 + 8)?;
    for _ in 0..edge_count {
        let layer_id = r.u32()? as usize;
        if layer_id >= layer_count {
            return Err(format!("edge layer {layer_id} out of range"));
        }
        let _idx = r.u16()?;
        let sign = r.u8()?;
        if sign > 1 {
            return Err(format!("invalid edge sign {sign}"));
        }
        let weights = r.count(16)?;
        if weights as u64 != slots {
            return Err("edge weight/slots mismatch".into());
        }
        for _ in 0..weights {
            r.fp()?;
        }
        let bits = r.u64()?;
        if bits > MAX_BITVEC_BITS {
            return Err(format!("bit vector too large: {bits}"));
        }
        let words = r.count(8)?;
        let expected = usize::try_from((bits + 63) / 64).map_err(|_| "bit-vector word overflow")?;
        if words != expected {
            return Err(format!("bit-vector word mismatch: {words} != {expected}"));
        }
        let raw = r.take(words.checked_mul(8).ok_or("bit-vector size overflow")?)?;
        if bits % 64 != 0 && !raw.is_empty() {
            let last = u64::from_le_bytes(raw[raw.len() - 8..].try_into().unwrap());
            if last >> (bits % 64) != 0 {
                return Err("nonzero unused bit-vector tail bits".into());
            }
        }
    }
    if r.remaining() != 0 {
        return Err(format!("cipher trailing bytes: {}", r.remaining()));
    }
    stats.layers += layer_count;
    stats.edges += edge_count;
    Ok(())
}

fn run(path: &str) -> Result<Stats, String> {
    let data = fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut r = Reader::new(&data);
    if r.take(16)? != BUNDLE_MAGIC {
        return Err("bad bundle magic".into());
    }
    let count = r.u64()?;
    if count == 0 || count > 1024 {
        return Err(format!("invalid cipher count {count}"));
    }
    let mut stats = Stats::default();
    for i in 0..count {
        let size = usize::try_from(r.u64()?).map_err(|_| "cipher length overflow")?;
        if size == 0 || size > r.remaining() {
            return Err(format!("invalid cipher {i} length {size}"));
        }
        parse_cipher(r.take(size)?, &mut stats).map_err(|e| format!("cipher {i}: {e}"))?;
        stats.ciphers += 1;
    }
    if r.remaining() != 0 {
        return Err(format!("bundle trailing bytes: {}", r.remaining()));
    }
    Ok(stats)
}

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| "secret.ct".into());
    match run(&path) {
        Ok(s) => {
            println!("wire_audit=PASS");
            println!("ciphers={}", s.ciphers);
            println!(
                "layers={} base={} product={}",
                s.layers, s.base_layers, s.product_layers
            );
            println!("edges={} commitments={}", s.edges, s.commitments);
            println!(
                "unique_nonces={} duplicate_nonces={}",
                s.nonces.len(),
                s.duplicate_nonces
            );
        }
        Err(e) => {
            eprintln!("wire_audit=FAIL: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_check_rejects_truncation() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.take(4).is_err());
    }

    #[test]
    fn rejects_noncanonical_fp() {
        let mut bytes = [0u8; 16];
        bytes[15] = 0x80;
        assert!(Reader::new(&bytes).fp().is_err());
    }
}
