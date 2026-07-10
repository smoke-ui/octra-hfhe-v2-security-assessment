import crypto from 'crypto';
import nacl from 'tweetnacl';
import bip39 from 'bip39';

const target = 'octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ';
const count = Number(process.argv[2] ?? '1000');
const start = BigInt(process.argv[3] ?? '0');
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let n = BigInt('0x' + Buffer.from(buf).toString('hex'));
  let out = '';
  while (n > 0n) {
    const r = Number(n % 58n);
    n /= 58n;
    out = alphabet[r] + out;
  }
  for (const b of buf) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

function entropyHex(n) {
  return n.toString(16).padStart(32, '0');
}

const t0 = performance.now();
let found = null;
for (let i = 0; i < count; i++) {
  const entropy = entropyHex(start + BigInt(i));
  const mnemonic = bip39.entropyToMnemonic(entropy);
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const master = crypto.createHmac('sha512', Buffer.from('Octra seed')).update(seed).digest();
  const kp = nacl.sign.keyPair.fromSeed(master.subarray(0, 32));
  const address = 'oct' + base58Encode(crypto.createHash('sha256').update(kp.publicKey).digest());
  if (address === target) {
    found = { index: (start + BigInt(i)).toString(), mnemonic };
    break;
  }
}
const seconds = (performance.now() - t0) / 1000;
console.log(JSON.stringify({count, start: start.toString(), seconds, candidates_per_second: count / seconds, found}, null, 2));
