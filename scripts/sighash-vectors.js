'use strict';

const util = require('bcoin/lib/utils/util');
const TX = require('bcoin/lib/primitives/tx');
const Output = require('bcoin/lib/primitives/output');
const Outpoint = require('bcoin/lib/primitives/outpoint');
const Script = require('bcoin/lib/script/script');
const sighashTests = require('bcoin/test/data/sighash-tests.json');

function parseSighashTest(data) {
  const [txHex, scriptHex, index, type, hash] = data;
  const tx = TX.fromRaw(txHex, 'hex');
  const script = Script.fromRaw(scriptHex, 'hex');
  const expected = util.fromRev(hash);

  return {
    tx: tx,
    script: script,
    index: index,
    type: type,
    expected: expected,
    comments: expected.toString('hex')
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

console.log(`typedef struct test_sighash_vector_s {
  const uint8_t *tx_raw;
  size_t tx_len;
  const uint8_t *script_raw;
  size_t script_len;
  size_t index;
  int type;
  uint8_t expected[32];
  const char *comments;
} test_sighash_vector_t;
`);

const tests = [];

for (const json of sighashTests) {
  if (json.length === 1)
    continue;

  tests.push(parseSighashTest(json));
}

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log('static const uint8_t test_sighash_tx_%d[] = {', i);
  toBytes(test.tx.toRaw(), '  ');
  console.log('};');
  console.log('');

  console.log('static const uint8_t test_sighash_script_%d[] = {', i);
  if (test.script.code.length === 0)
    console.log('  0x00,');
  else
    toBytes(test.script.toRaw(), '  ');
  console.log('};');
  console.log('');
}

console.log('static const test_sighash_vector_t test_sighash_vectors[] = {');

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log('  {');
  console.log('    test_sighash_tx_%d,', i);
  console.log('    %d,', test.tx.getSize());
  console.log('    test_sighash_script_%d,', i);
  console.log('    %d,', test.script.getSize());
  console.log('    %d,', test.index);
  console.log('    %d,', test.type);
  console.log('    {');
  toBytes(test.expected, '      ');
  console.log('    },');
  console.log('    "%s"', test.comments);
  console.log('  },');
}

console.log('};');
