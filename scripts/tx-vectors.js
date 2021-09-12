'use strict';

const util = require('bcoin/lib/utils/util');
const TX = require('bcoin/lib/primitives/tx');
const Output = require('bcoin/lib/primitives/output');
const Outpoint = require('bcoin/lib/primitives/outpoint');
const Script = require('bcoin/lib/script/script');
const validTests = require('bcoin/test/data/tx-valid.json');
const invalidTests = require('bcoin/test/data/tx-invalid.json');
const sighashTests = require('bcoin/test/data/sighash-tests.json');

function parseTXTest(data, comments) {
  const coins = data[0];
  const hex = data[1];
  const names = data[2] || 'NONE';
  const out = [];

  for (const [txid, index, str, amount] of coins) {
    const hash = util.fromRev(txid);
    const script = Script.fromString(str);
    const value = parseInt(amount || '0', 10);

    // Ignore the coinbase tests.
    // They should all fail.
    if ((index >>> 0) === 0xffffffff)
      continue;

    const prevout = new Outpoint(hash, index);
    const output = new Output({script, value});

    out.push([prevout, output]);
  }

  const raw = Buffer.from(hex, 'hex');
  const tx = TX.fromRaw(raw);

  return {
    tx: tx,
    coins: out,
    flags: names.split(',').map(s => 'BTC_SCRIPT_VERIFY_' + s),
    comments: comments
  };
}

function toBytes(raw, pad) {
  const out = [];

  for (let i = 0; i < raw.length; i++) {
    let ch = raw[i].toString(16);

    if (ch.length < 2)
      ch = '0' + ch;

    ch = '0x' + ch;

    out.push(ch);

    if (out.length === 8) {
      console.log('%s%s', pad, out.join(', ') + ',');
      out.length = 0;
    }
  }

  if (out.length > 0) {
    console.log('%s%s', pad, out.join(', ') + ',');
    out.length = 0;
  }
}

const type = process.argv[2] || 'valid';

console.log(`typedef struct test_${type}_coins_s {
  btc_outpoint_t outpoint;
  const uint8_t *output_raw;
  size_t output_len;
} test_${type}_coins_t;

typedef struct test_${type}_vector_t {
  const uint8_t *tx_raw;
  size_t tx_len;
  const test_${type}_coins_t *coins;
  size_t coins_len;
  unsigned int flags;
  const char *comments;
} test_${type}_vector_t;
`);

const tests = [];

let comment = '';

for (const json of (type === 'valid' ? validTests : invalidTests)) {
  if (json.length === 1) {
    comment += ' ' + json[0];
    continue;
  }

  tests.push(parseTXTest(json, comment.trim()));

  comment = '';
}

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log(`static const uint8_t test_${type}_tx_%d[] = {`, i);
  toBytes(test.tx.toRaw(), '  ');
  console.log('};');
  console.log('');

  for (let j = 0; j < test.coins.length; j++) {
    const [, output] = test.coins[j];

    console.log(`static const uint8_t test_${type}_output_%d_%d[] = {`, i, j);
    toBytes(output.toRaw(), '  ');
    console.log('};');
    console.log('');
  }

  console.log(`static const test_${type}_coins_t test_${type}_coins_%d[] = {`, i);

  for (let j = 0; j < test.coins.length; j++) {
    const [prevout, output] = test.coins[j];

    console.log('  {');
    console.log('    {');
    console.log('      {');
    toBytes(prevout.hash, '        ');
    console.log('      },');
    console.log('      %d', prevout.index);
    console.log('    },');
    console.log(`    test_${type}_output_%d_%d,`, i, j);
    console.log('    %d', output.getSize());
    console.log('  },');
  }

  console.log('};');
  console.log('');
}

console.log(`static const test_${type}_vector_t test_${type}_vectors[] = {`);

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log('  {');
  console.log(`    test_${type}_tx_%d,`, i);
  console.log('    %d,', test.tx.getSize());
  console.log(`    test_${type}_coins_%d,`, i);
  console.log('    %d,', test.coins.length);
  console.log('    %s,', test.flags.join(' | '));
  console.log('    "%s"', test.comments);
  console.log('  },');
}

console.log('};');
