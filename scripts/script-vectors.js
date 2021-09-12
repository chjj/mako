'use strict';

const Script = require('bcoin/lib/script/script');
const Witness = require('bcoin/lib/script/witness');
const Opcode = require('bcoin/lib/script/opcode');
const TX = require('bcoin/lib/primitives/tx');
const consensus = require('bcoin/lib/protocol/consensus');
const {fromFloat} = require('bcoin/lib/utils/fixed');
const scriptVectors = require('bcoin/test/data/script-tests.json');

function parseScriptTest(data) {
  const witArr = Array.isArray(data[0]) ? data.shift() : [];
  const inpHex = data[0];
  const outHex = data[1];
  const names = data[2] || 'NONE';

  let expected = data[3];

  if (expected === 'NULLFAIL')
    expected = 'SIG_NULLFAIL';

  let comments = data[4];

  if (!comments)
    comments = outHex.slice(0, 60);

  comments += ` (${expected})`;

  let value = 0;

  if (witArr.length > 0)
    value = fromFloat(witArr.pop(), 8);

  const witness = Witness.fromString(witArr);
  const input = Script.fromString(inpHex);
  const output = Script.fromString(outHex);

  // Funding transaction.
  const prev = new TX({
    version: 1,
    inputs: [{
      prevout: {
        hash: consensus.ZERO_HASH,
        index: 0xffffffff
      },
      script: [
        Opcode.fromInt(0),
        Opcode.fromInt(0)
      ],
      witness: [],
      sequence: 0xffffffff
    }],
    outputs: [{
      script: output,
      value: value
    }],
    locktime: 0
  });

  // Spending transaction.
  const tx = new TX({
    version: 1,
    inputs: [{
      prevout: {
        hash: prev.hash(),
        index: 0
      },
      script: input,
      witness: witness,
      sequence: 0xffffffff
    }],
    outputs: [{
      script: [],
      value: value
    }],
    locktime: 0
  });

  return {
    witness: witness,
    input: input,
    output: output,
    value: value,
    flags: names.split(',').map(s => 'BTC_SCRIPT_VERIFY_' + s),
    expected: expected,
    comments: comments,
    prev: prev,
    tx: tx
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

const tests = [];

for (const json of scriptVectors) {
  if (json.length === 1)
    continue;

  tests.push(parseScriptTest(json));
}

console.log(`typedef struct script_vector_s {
  const uint8_t *prev_raw;
  size_t prev_len;
  const uint8_t *tx_raw;
  size_t tx_len;
  unsigned int flags;
  int expected;
  const char *comments;
} script_vector_t;
`);

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log('static const uint8_t script_prev_raw_%d[] = {', i);
  toBytes(test.prev.toRaw(), '  ');
  console.log('};');
  console.log('');
  console.log('static const uint8_t script_tx_raw_%d[] = {', i);
  toBytes(test.tx.toRaw(), '  ');
  console.log('};');
  console.log('');
}

console.log('static const script_vector_t script_vectors[] = {');

for (let i = 0; i < tests.length; i++) {
  const test = tests[i];

  console.log('  {');
  console.log('    script_prev_raw_%d,', i);
  console.log('    %d,', test.prev.getSize());
  console.log('    script_tx_raw_%d,', i);
  console.log('    %d,', test.tx.getSize());
  console.log('    %s,', test.flags.join(' | '));
  console.log('    %s,', 'BTC_SCRIPT_ERR_' + test.expected);
  console.log('    "%s"', test.comments);
  console.log('  },');
}

console.log('};');
