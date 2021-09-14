'use strict';

const BN = require('bcrypto/lib/bn');
const elliptic = require('bcrypto/lib/js/elliptic');
const extra = require('bcrypto/test/util/curves');
const Ristretto = require('bcrypto/lib/js/ristretto');

class Element {
  constructor(m) {
    this.m = m.clone();
    this.bits = m.bitLength();
  }

  encode(num, width) {
    const space = width === 32 ? 4 : 2;
    const limbs = this.convert(num, width);
    const out = [];

    for (const limb of limbs) {
      let hex = '0x' + limb.toString(16, width / 4);

      if (width === 64)
        hex = `UINT64_C(${hex})`;

      out.push(hex);
    }

    if (out.length < space)
      return '{' + out.join(', ') + '}';

    let str = '{\n';

    for (let i = 0; i < out.length; i += space)
      str += '  ' + out.slice(i, i + space).join(', ') + ',\n';

    str = str.slice(0, -2) + '\n';
    str += '}';

    return str;
  }
}

class Saturated extends Element {
  constructor(m) {
    super(m);
  }

  convert(num, width) {
    const x = num.red ? num.fromRed() : num.clone();
    const limbs = Math.ceil(num.bitLength() / width);
    const out = new Array(limbs);

    for (let i = 0; i < limbs; i++) {
      out[i] = x.umaskn(width);

      x.iushrn(width);
    }

    return out;
  }
}

class Unsaturated extends Element {
  constructor(m, bounds32, bounds64) {
    super(m);

    this.bounds32 = bounds32.map(n => new BN(n, 16));
    this.bounds64 = bounds64.map(n => new BN(n, 16));
  }

  convert(num, width) {
    const bounds = width === 32 ? this.bounds32 : this.bounds64;
    const x = num.red ? num.fromRed() : num.clone();
    const limbs = bounds.length;
    const out = new Array(limbs);

    for (let i = 0; i < limbs; i++) {
      out[i] = x.mod(bounds[i]);

      x.idiv(bounds[i]);
    }

    return out;
  }
}

class Montgomery extends Element {
  constructor(m) {
    super(m);
  }

  convert(num, width) {
    const x = num.red ? num.fromRed() : num.clone();
    const n = align(this.bits, width);
    const k = x.ushln(n).imod(this.m);
    const limbs = Math.ceil(this.bits / width);
    const out = new Array(limbs);

    for (let i = 0; i < limbs; i++) {
      out[i] = k.umaskn(width);

      k.iushrn(width);
    }

    return out;
  }
}

function align(bits, width) {
  if (bits % width)
    bits += width - (bits % width);

  return bits;
}

const curves = {
  P192: new elliptic.curves.P192(),
  P224: new elliptic.curves.P224(),
  P256: new elliptic.curves.P256(),
  P384: new elliptic.curves.P384(),
  P521: new elliptic.curves.P521(),
  SECP256K1: new elliptic.curves.SECP256K1(),
  X25519: new elliptic.curves.X25519(),
  X448: new elliptic.curves.X448(),
  ED25519: new elliptic.curves.ED25519(),
  ED448: new elliptic.curves.ED448(),
  ED1174: new extra.ED1174(),
  ISO448: new elliptic.curves.ISO448(),
  MONT448: new elliptic.curves.MONT448(),
  MONT1174: new extra.MONT1174()
};

const isomorphism = {
  X25519: [curves.ED25519, false],
  X448: [curves.ISO448, true],
  ED25519: [curves.X25519, false],
  ED448: [curves.MONT448, true],
  ED1174: [curves.MONT1174, true]
};

const fields = {
  Q192: new Saturated(curves.P192.n),
  Q224: new Saturated(curves.P224.n),
  Q256: new Saturated(curves.P256.n),
  Q384: new Saturated(curves.P384.n),
  Q521: new Saturated(curves.P521.n),
  SECQ256K1: new Saturated(curves.SECP256K1.n),
  Q25519: new Saturated(curves.ED25519.n),
  Q448: new Saturated(curves.ED448.n),
  Q251: new Saturated(curves.ED1174.n),

  P192: new Unsaturated(curves.P192.p,
                        ['400000', '200000', '200000', '400000',
                         '200000', '200000', '400000', '200000',
                         '200000'],
                        ['1000000000000', '1000000000000',
                         '1000000000000', '1000000000000']),
  P224: new Montgomery(curves.P224.p),
  P256: new Montgomery(curves.P256.p),
  P384: new Montgomery(curves.P384.p),
  P521: new Unsaturated(curves.P521.p,
                        ['10000000', '8000000', '10000000', '8000000',
                         '10000000', '8000000', '8000000', '10000000',
                         '8000000', '10000000', '8000000', '10000000',
                         '8000000', '8000000', '10000000', '8000000',
                         '10000000', '8000000', '8000000'],
                        ['400000000000000', '400000000000000',
                         '400000000000000', '400000000000000',
                         '400000000000000', '400000000000000',
                         '400000000000000', '400000000000000',
                         '200000000000000']),
  SECP256K1: new Unsaturated(curves.SECP256K1.p,
                             ['466667', '233334', '233334', '466667',
                              '233334', '233334', '466667', '233334',
                              '233334', '466667', '233334', '233334'],
                             ['80000000000', '80000000000',
                              '40000000000', '80000000000',
                              '80000000000', '40000000000']),
  P25519: new Unsaturated(curves.ED25519.p,
                          ['4000000', '2000000', '4000000', '2000000',
                           '4000000', '2000000', '4000000', '2000000',
                           '4000000', '2000000'],
                          ['8000000000000', '8000000000000',
                           '8000000000000', '8000000000000',
                           '8000000000000']),
  P448: new Unsaturated(curves.ED448.p,
                        ['2000000', '2000000', '2000000', '2000000',
                         '2000000', '2000000', '2000000', '2000000',
                         '1000000', '2000000', '2000000', '2000000',
                         '2000000', '2000000', '2000000', '2000000',
                         '2000000', '1000000'],
                        ['100000000000000', '100000000000000',
                         '100000000000000', '100000000000000',
                         '100000000000000', '100000000000000',
                         '100000000000000', '100000000000000']),
  P251: new Unsaturated(curves.ED1174.p,
                        ['4000000', '2000000', '2000000', '2000000',
                         '2000000', '2000000', '2000000', '2000000',
                         '2000000', '2000000'],
                        ['8000000000000', '4000000000000',
                         '4000000000000', '4000000000000',
                         '4000000000000'])
};

function indent(str, n = 1) {
  return str.replace(/^/gm, Array(n * 2 + 1).join(' '));
}

function encodeBytes(raw) {
  const out = [];

  for (let i = 0; i < raw.length; i++) {
    let hex = raw[i].toString(16);

    if (hex.length < 2)
      hex = '0' + hex;

    hex = '0x' + hex;

    out.push(hex);
  }

  if (out.length < 8)
    return '{' + out.join(', ') + '}';

  let str = '{\n';

  for (let i = 0; i < out.length; i += 8)
    str += '  ' + out.slice(i, i + 8).join(', ') + ',\n';

  str = str.slice(0, -2) + '\n';
  str += '}';

  return str;
}

function encodeField(x, field, width) {
  return fields[field].encode(x, width);
}

function encodeAffine(p, field, width) {
  let str = '';

  str += '{\n';
  str += indent(encodeField(p.x, field, width)) + ',';
  str += '\n';
  str += indent(encodeField(p.y, field, width)) + ',';
  str += '\n';
  str += '  ' + (p.inf | 0);
  str += '\n}';

  return str;
}

function encodeX(p, field, width) {
  let str = '';

  p.normalize();

  str += '{\n';
  str += indent(encodeField(p.x, field, width)) + ',';
  str += '\n';
  str += indent(encodeField(p.z, field, width));
  str += '\n}';

  return str;
}

function encodeEdwards(p, field, width) {
  let str = '';

  p.normalize();

  str += '{\n';
  str += indent(encodeField(p.x, field, width)) + ',';
  str += '\n';
  str += indent(encodeField(p.y, field, width)) + ',';
  str += '\n';
  str += indent(encodeField(p.z, field, width)) + ',';
  str += '\n';
  str += indent(encodeField(p.t, field, width));
  str += '\n}';

  return str;
}

function encodePoint(p, field, width) {
  if (p.curve.type === 'short')
    return encodeAffine(p, field, width);

  if (p.curve.type === 'mont' && p.inf != null)
    return encodeAffine(p, field, width);

  if (p.curve.type === 'mont')
    return encodeX(p, field, width);

  if (p.curve.type === 'edwards')
    return encodeEdwards(p, field, width);

  throw new Error();
}

function encodePoints(points, field, width) {
  let str = '{\n';

  if (points.length > 0) {
    for (let i = 0; i < points.length - 1; i++) {
      str += indent(encodePoint(points[i], field, width)) + ',';
      str += '\n';
    }

    str += indent(encodePoint(points[points.length - 1], field, width));
  }

  str += '\n}';

  return str;
}

class FieldEncoder {
  constructor(field, width) {
    this.id = field.toLowerCase();
    this.fieldName = field;
    this.width = width;
    this.m = fields[field].m;
    this.saturated = new Saturated(this.m);
  }

  bytes(num) {
    return encodeBytes(num.encode('be', this.m.byteLength()));
  }

  integer(num) {
    if (this.width === 64)
      return `UINT64_C(0x${num.toString(16)})`;

    return `0x${num.toString(16)}`;
  }

  scalar(num) {
    return this.saturated.encode(num, this.width);
  }

  field(num) {
    return encodeField(num, this.fieldName, this.width);
  }

  output(type, name, val) {
    console.log(`static const ${type} field_${this.id}_${name} = %s;\n`, val);
  }
}

class CurveEncoder {
  constructor(curve, primeField, scalarField, width) {
    this.id = curve.id.toLowerCase();
    this.curve = curve;
    this.primeField = primeField;
    this.scalarField = scalarField;
    this.width = width;
  }

  bytes(num) {
    return encodeBytes(num.encode('be', this.curve.fieldSize));
  }

  scalar(num) {
    return encodeField(num, this.scalarField, this.width);
  }

  field(num) {
    return encodeField(num, this.primeField, this.width);
  }

  point(p) {
    return encodePoint(p, this.primeField, this.width);
  }

  points(points) {
    return encodePoints(points, this.primeField, this.width);
  }

  output(type, name, val) {
    console.log(`static const ${type} ${this.id}_${name} = %s;\n`, val);
  }
}

function encodePrimeField(field, width) {
  const c = new FieldEncoder(field, width);

  c.output('mp_limb_t', 'p[REDUCE_LIMBS]', c.scalar(c.m));
  c.output('unsigned char', 'raw[FIELD_SIZE]', c.bytes(c.m));
  c.output('fe_t', 'zero', c.field(new BN(0)));
  c.output('fe_t', 'one', c.field(new BN(1)));
  c.output('fe_t', 'two', c.field(new BN(2)));
  c.output('fe_t', 'three', c.field(new BN(3)));
  c.output('fe_t', 'four', c.field(new BN(4)));
  c.output('fe_t', 'mone', c.field(new BN(-1).mod(c.m)));
}

function encodePrimeField2(field) {
  console.log('#if defined(BTC_HAVE_INT128)');
  encodePrimeField(field, 64);
  console.log('#else');
  encodePrimeField(field, 32);
  console.log('#endif');
}

function montify(q, width, limbs) {
  const pow = BN.shift(1, width);
  const word = q.umaskn(width);

  // k = -q^-1 mod 2^width
  let k = new BN(2).sub(word).imod(pow);
  let t = word.subn(1).imod(pow);

  for (let i = 1; i < width; i *= 2) {
    t = t.sqr().imod(pow);
    k = k.mul(t.addn(1)).imod(pow);
  }

  k = k.neg().imod(pow);

  // r = 2^(2 * limbs * width) mod q
  const r = BN.shift(1, 2 * limbs * width).imod(q);

  return [k, r];
}

function encodeScalarField(field, width) {
  const c = new FieldEncoder(field, width);
  const bits = c.m.bitLength();
  const limbs = Math.ceil(bits / width);
  const shift = limbs * 2 + 2;
  const m = BN.shift(1, shift * width).div(c.m);
  const [k, r2] = montify(c.m, width, limbs);
  const nh = c.m.ushrn(1);
  const n = c.m;

  c.output('mp_limb_t', 'n[SCALAR_LIMBS]', c.scalar(n));
  c.output('mp_limb_t', 'nh[SCALAR_LIMBS]', c.scalar(nh));
  c.output('mp_limb_t', 'm[REDUCE_LIMBS - SCALAR_LIMBS + 1]', c.scalar(m));
  c.output('mp_limb_t', 'k', c.integer(k));
  c.output('mp_limb_t', 'r2[SCALAR_LIMBS]', c.scalar(r2));
}

function encodeScalarField2(field) {
  console.log('#if MP_LIMB_BITS == 64');
  encodeScalarField(field, 64);
  console.log('#else');
  encodeScalarField(field, 32);
  console.log('#endif');
}

function encodeShortCurve(curve, primeField, scalarField, width) {
  const c = new CurveEncoder(curve, primeField, scalarField, width);
  const fixed = curve.g._getWindows(4, curve.n.bitLength()).points;
  const naf = curve.g._getNAF(12).points;

  c.output('mp_limb_t', 'sc_p[REDUCE_LIMBS]', c.scalar(curve.pmodn));
  c.output('fe_t', 'fe_n', c.field(curve.n.mod(curve.p)));
  c.output('fe_t', 'a', c.field(curve.a));
  c.output('fe_t', 'b', c.field(curve.b));
  c.output('fe_t', 'c', c.field(curve.c));
  c.output('fe_t', 'z', c.field(curve.z));
  c.output('fe_t', 'ai', c.field(curve.ai));
  c.output('fe_t', 'zi', c.field(curve.zi));
  c.output('fe_t', 'i2', c.field(curve.i2));
  c.output('fe_t', 'i3', c.field(curve.i3));
  c.output('wge_t', 'g', c.point(curve.g));
  c.output('wge_t', 'wnd_fixed[FIXED_MAX_LENGTH]', c.points(fixed));
  c.output('wge_t', 'wnd_naf[NAF_SIZE_PRE]', c.points(naf));
  c.output('wge_t', 'torsion[8]', c.points(curve.torsion));

  if (curve.endo) {
    const beta = curve.endo.beta;
    const lambda = curve.endo.lambda.neg().imod(curve.n);
    const b1 = curve.endo.basis[0].b.neg().imod(curve.n);
    const b2 = curve.endo.basis[1].b.neg().imod(curve.n);
    const g1 = curve.endo.pre[1];
    const g2 = curve.endo.pre[2].neg();
    // const prec = curve.endo.pre[0];
    const wnd = naf.map(p => p._getBeta());

    c.output('fe_t', 'beta', c.field(beta));
    c.output('sc_t', 'lambda', c.scalar(lambda));
    c.output('sc_t', 'b1', c.scalar(b1));
    c.output('sc_t', 'b2', c.scalar(b2));
    c.output('sc_t', 'g1', c.scalar(g1));
    c.output('sc_t', 'g2', c.scalar(g2));
    c.output('wge_t', 'wnd_endo[NAF_SIZE_PRE]', c.points(wnd));
    // c.output('int', 'prec', prec);
  }
}

function encodeMontCurve(curve, primeField, scalarField, width) {
  const c = new CurveEncoder(curve, primeField, scalarField, width);
  const [iso, invert] = isomorphism[curve.id];
  const c0 = curve._scale(iso, invert);

  c.output('fe_t', 'a', c.field(curve.a));
  c.output('fe_t', 'b', c.field(curve.b));
  c.output('fe_t', 'z', c.field(curve.z));
  c.output('fe_t', 'c', c.field(c0));
  c.output('fe_t', 'bi', c.field(curve.bi));
  c.output('fe_t', 'i4', c.field(curve.i4));
  c.output('fe_t', 'a24', c.field(curve.a24));
  c.output('fe_t', 'a0', c.field(curve.a0));
  c.output('fe_t', 'b0', c.field(curve.b0));
  c.output('sc_t', 'i16', c.scalar(curve.scalar(16).invert(curve.n)));
  c.output('mge_t', 'g', c.point(curve.g));
  c.output('mge_t', 'torsion[8]', c.points(curve.torsion));
}

function encodeEdwardsCurve(curve, primeField, scalarField, width) {
  const rist = new Ristretto(curve);
  const c = new CurveEncoder(curve, primeField, scalarField, width);
  const fixed = curve.g._getWindows(4, curve.n.bitLength()).points;
  const naf = curve.g._getNAF(12).points;
  const [iso, invert] = isomorphism[curve.id];
  const c0 = curve._scale(iso, invert);

  c.output('fe_t', 'a', c.field(curve.a));
  c.output('fe_t', 'd', c.field(curve.d));
  c.output('fe_t', 'k', c.field(curve.k));
  c.output('fe_t', 'z', c.field(curve.z));
  c.output('fe_t', 'c', c.field(c0));
  c.output('fe_t', 'A', c.field(iso.a));
  c.output('fe_t', 'B', c.field(iso.b));
  c.output('fe_t', 'Bi', c.field(iso.bi));
  c.output('fe_t', 'A0', c.field(iso.a0));
  c.output('fe_t', 'B0', c.field(iso.b0));
  c.output('xge_t', 'g', c.point(curve.g));
  c.output('xge_t', 'wnd_fixed[FIXED_MAX_LENGTH]', c.points(fixed));
  c.output('xge_t', 'wnd_naf[NAF_SIZE_PRE]', c.points(naf));
  c.output('xge_t', 'torsion[8]', c.points(curve.torsion));

  c.output('fe_t', 'qnr', c.field(rist.qnr));
  c.output('fe_t', 'qnrds', c.field(rist.qnrds));
  c.output('fe_t', 'adm1s', c.field(rist.adm1s));
  c.output('fe_t', 'adm1si', c.field(rist.adm1si));
  c.output('fe_t', 'dmaddpa', c.field(rist.dmaddpa));
  c.output('fe_t', 'amdsi', c.field(rist.amdsi));
  c.output('fe_t', 'dmasi', c.field(rist.dmasi));
}

function encodeCurve(curve, primeField, scalarField, width) {
  if (curve.type === 'short')
    return encodeShortCurve(curve, primeField, scalarField, width);

  if (curve.type === 'mont')
    return encodeMontCurve(curve, primeField, scalarField, width);

  if (curve.type === 'edwards')
    return encodeEdwardsCurve(curve, primeField, scalarField, width);

  throw new Error();
}

function encodeCurve2(curve, primeField, scalarField) {
  console.log('#if defined(BTC_HAVE_INT128)');
  encodeCurve(curve, primeField, scalarField, 64);
  console.log('#else');
  encodeCurve(curve, primeField, scalarField, 32);
  console.log('#endif');
}

const desc = {
  P192: [curves.P192, 'P192', 'Q192'],
  P224: [curves.P224, 'P224', 'Q224'],
  P256: [curves.P256, 'P256', 'Q256'],
  P384: [curves.P384, 'P384', 'Q384'],
  P521: [curves.P521, 'P521', 'Q521'],
  SECP256K1: [curves.SECP256K1, 'SECP256K1', 'SECQ256K1'],
  X25519: [curves.X25519, 'P25519', 'Q25519'],
  X448: [curves.X448, 'P448', 'Q448'],
  ED25519: [curves.ED25519, 'P25519', 'Q25519'],
  ED448: [curves.ED448, 'P448', 'Q448'],
  ED1174: [curves.ED1174, 'P251', 'Q251']
};

{
  switch (process.argv[2]) {
    case 'scalar': {
      encodeScalarField2(process.argv[3]);
      break;
    }

    case 'prime': {
      encodePrimeField2(process.argv[3]);
      break;
    }

    case 'curve': {
      const [curve, primeField, scalarField] = desc[process.argv[3]];

      encodeCurve2(curve, primeField, scalarField);

      break;
    }

    default: {
      throw new Error('Unknown argument.');
    }
  }
}
