/*!
 * script.h - script for libsatoshi
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/libsatoshi
 */

#ifndef BTC_SCRIPT_H
#define BTC_SCRIPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "buffer.h"
#include "impl.h"
#include "types.h"

enum btc_sighash_flags {
  BTC_SIGHASH_ALL = 1,
  BTC_SIGHASH_NONE = 2,
  BTC_SIGHASH_SINGLE = 3,
  BTC_SIGHASH_ANYONECANPAY = 0x80
};

enum btc_script_flags {
  BTC_SCRIPT_VERIFY_NONE = 0,
  BTC_SCRIPT_VERIFY_P2SH = (1U << 0),
  BTC_SCRIPT_VERIFY_STRICTENC = (1U << 1),
  BTC_SCRIPT_VERIFY_DERSIG = (1U << 2),
  BTC_SCRIPT_VERIFY_LOW_S = (1U << 3),
  BTC_SCRIPT_VERIFY_NULLDUMMY = (1U << 4),
  BTC_SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),
  BTC_SCRIPT_VERIFY_MINIMALDATA = (1U << 6),
  BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),
  BTC_SCRIPT_VERIFY_CLEANSTACK = (1U << 8),
  BTC_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),
  BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),
  BTC_SCRIPT_VERIFY_WITNESS = (1U << 11),
  BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),
  BTC_SCRIPT_VERIFY_MINIMALIF = (1U << 13),
  BTC_SCRIPT_VERIFY_NULLFAIL = (1U << 14),
  BTC_SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),
  BTC_SCRIPT_VERIFY_CONST_SCRIPTCODE = (1U << 16),
  BTC_SCRIPT_MANDATORY_VERIFY_FLAGS = BTC_SCRIPT_VERIFY_P2SH,
  BTC_SCRIPT_STANDARD_VERIFY_FLAGS = 0
    | BTC_SCRIPT_MANDATORY_VERIFY_FLAGS
    | BTC_SCRIPT_VERIFY_DERSIG
    | BTC_SCRIPT_VERIFY_STRICTENC
    | BTC_SCRIPT_VERIFY_MINIMALDATA
    | BTC_SCRIPT_VERIFY_NULLDUMMY
    | BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    | BTC_SCRIPT_VERIFY_CLEANSTACK
    | BTC_SCRIPT_VERIFY_MINIMALIF
    | BTC_SCRIPT_VERIFY_NULLFAIL
    | BTC_SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | BTC_SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | BTC_SCRIPT_VERIFY_LOW_S
    | BTC_SCRIPT_VERIFY_WITNESS
    | BTC_SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | BTC_SCRIPT_VERIFY_WITNESS_PUBKEYTYPE,
  BTC_SCRIPT_ONLY_STANDARD_VERIFY_FLAGS = BTC_SCRIPT_STANDARD_VERIFY_FLAGS
                                       & ~BTC_SCRIPT_MANDATORY_VERIFY_FLAGS
};

enum btc_script_error {
  BTC_SCRIPT_ERR_OK = 0,
  BTC_SCRIPT_ERR_UNKNOWN_ERROR,
  BTC_SCRIPT_ERR_EVAL_FALSE,
  BTC_SCRIPT_ERR_OP_RETURN,

  /* Max sizes */
  BTC_SCRIPT_ERR_SCRIPT_SIZE,
  BTC_SCRIPT_ERR_PUSH_SIZE,
  BTC_SCRIPT_ERR_OP_COUNT,
  BTC_SCRIPT_ERR_STACK_SIZE,
  BTC_SCRIPT_ERR_SIG_COUNT,
  BTC_SCRIPT_ERR_PUBKEY_COUNT,

  /* Failed verify operations */
  BTC_SCRIPT_ERR_VERIFY,
  BTC_SCRIPT_ERR_EQUALVERIFY,
  BTC_SCRIPT_ERR_CHECKMULTISIGVERIFY,
  BTC_SCRIPT_ERR_CHECKSIGVERIFY,
  BTC_SCRIPT_ERR_NUMEQUALVERIFY,

  /* Logical/Format/Canonical errors */
  BTC_SCRIPT_ERR_BAD_OPCODE,
  BTC_SCRIPT_ERR_DISABLED_OPCODE,
  BTC_SCRIPT_ERR_INVALID_STACK_OPERATION,
  BTC_SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
  BTC_SCRIPT_ERR_UNBALANCED_CONDITIONAL,

  /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
  BTC_SCRIPT_ERR_NEGATIVE_LOCKTIME,
  BTC_SCRIPT_ERR_UNSATISFIED_LOCKTIME,

  /* Malleability */
  BTC_SCRIPT_ERR_SIG_HASHTYPE,
  BTC_SCRIPT_ERR_SIG_DER,
  BTC_SCRIPT_ERR_MINIMALDATA,
  BTC_SCRIPT_ERR_SIG_PUSHONLY,
  BTC_SCRIPT_ERR_SIG_HIGH_S,
  BTC_SCRIPT_ERR_SIG_NULLDUMMY,
  BTC_SCRIPT_ERR_PUBKEYTYPE,
  BTC_SCRIPT_ERR_CLEANSTACK,
  BTC_SCRIPT_ERR_MINIMALIF,
  BTC_SCRIPT_ERR_SIG_NULLFAIL,

  /* softfork safeness */
  BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS,
  BTC_SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,

  /* segregated witness */
  BTC_SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH,
  BTC_SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY,
  BTC_SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
  BTC_SCRIPT_ERR_WITNESS_MALLEATED,
  BTC_SCRIPT_ERR_WITNESS_MALLEATED_P2SH,
  BTC_SCRIPT_ERR_WITNESS_UNEXPECTED,
  BTC_SCRIPT_ERR_WITNESS_PUBKEYTYPE,

  /* Constant scriptCode */
  BTC_SCRIPT_ERR_OP_CODESEPARATOR,
  BTC_SCRIPT_ERR_SIG_FINDANDDELETE,

  BTC_SCRIPT_ERR_ERROR_COUNT
};

enum btc_opcode {
  /* push value */
  BTC_OP_0 = 0x00,
  BTC_OP_FALSE = BTC_OP_0,
  BTC_OP_PUSHDATA1 = 0x4c,
  BTC_OP_PUSHDATA2 = 0x4d,
  BTC_OP_PUSHDATA4 = 0x4e,
  BTC_OP_1NEGATE = 0x4f,
  BTC_OP_RESERVED = 0x50,
  BTC_OP_1 = 0x51,
  BTC_OP_TRUE = BTC_OP_1,
  BTC_OP_2 = 0x52,
  BTC_OP_3 = 0x53,
  BTC_OP_4 = 0x54,
  BTC_OP_5 = 0x55,
  BTC_OP_6 = 0x56,
  BTC_OP_7 = 0x57,
  BTC_OP_8 = 0x58,
  BTC_OP_9 = 0x59,
  BTC_OP_10 = 0x5a,
  BTC_OP_11 = 0x5b,
  BTC_OP_12 = 0x5c,
  BTC_OP_13 = 0x5d,
  BTC_OP_14 = 0x5e,
  BTC_OP_15 = 0x5f,
  BTC_OP_16 = 0x60,

  /* control */
  BTC_OP_NOP = 0x61,
  BTC_OP_VER = 0x62,
  BTC_OP_IF = 0x63,
  BTC_OP_NOTIF = 0x64,
  BTC_OP_VERIF = 0x65,
  BTC_OP_VERNOTIF = 0x66,
  BTC_OP_ELSE = 0x67,
  BTC_OP_ENDIF = 0x68,
  BTC_OP_VERIFY = 0x69,
  BTC_OP_RETURN = 0x6a,

  /* stack ops */
  BTC_OP_TOALTSTACK = 0x6b,
  BTC_OP_FROMALTSTACK = 0x6c,
  BTC_OP_2DROP = 0x6d,
  BTC_OP_2DUP = 0x6e,
  BTC_OP_3DUP = 0x6f,
  BTC_OP_2OVER = 0x70,
  BTC_OP_2ROT = 0x71,
  BTC_OP_2SWAP = 0x72,
  BTC_OP_IFDUP = 0x73,
  BTC_OP_DEPTH = 0x74,
  BTC_OP_DROP = 0x75,
  BTC_OP_DUP = 0x76,
  BTC_OP_NIP = 0x77,
  BTC_OP_OVER = 0x78,
  BTC_OP_PICK = 0x79,
  BTC_OP_ROLL = 0x7a,
  BTC_OP_ROT = 0x7b,
  BTC_OP_SWAP = 0x7c,
  BTC_OP_TUCK = 0x7d,

  /* splice ops */
  BTC_OP_CAT = 0x7e,
  BTC_OP_SUBSTR = 0x7f,
  BTC_OP_LEFT = 0x80,
  BTC_OP_RIGHT = 0x81,
  BTC_OP_SIZE = 0x82,

  /* bit logic */
  BTC_OP_INVERT = 0x83,
  BTC_OP_AND = 0x84,
  BTC_OP_OR = 0x85,
  BTC_OP_XOR = 0x86,
  BTC_OP_EQUAL = 0x87,
  BTC_OP_EQUALVERIFY = 0x88,
  BTC_OP_RESERVED1 = 0x89,
  BTC_OP_RESERVED2 = 0x8a,

  /* numeric */
  BTC_OP_1ADD = 0x8b,
  BTC_OP_1SUB = 0x8c,
  BTC_OP_2MUL = 0x8d,
  BTC_OP_2DIV = 0x8e,
  BTC_OP_NEGATE = 0x8f,
  BTC_OP_ABS = 0x90,
  BTC_OP_NOT = 0x91,
  BTC_OP_0NOTEQUAL = 0x92,

  BTC_OP_ADD = 0x93,
  BTC_OP_SUB = 0x94,
  BTC_OP_MUL = 0x95,
  BTC_OP_DIV = 0x96,
  BTC_OP_MOD = 0x97,
  BTC_OP_LSHIFT = 0x98,
  BTC_OP_RSHIFT = 0x99,

  BTC_OP_BOOLAND = 0x9a,
  BTC_OP_BOOLOR = 0x9b,
  BTC_OP_NUMEQUAL = 0x9c,
  BTC_OP_NUMEQUALVERIFY = 0x9d,
  BTC_OP_NUMNOTEQUAL = 0x9e,
  BTC_OP_LESSTHAN = 0x9f,
  BTC_OP_GREATERTHAN = 0xa0,
  BTC_OP_LESSTHANOREQUAL = 0xa1,
  BTC_OP_GREATERTHANOREQUAL = 0xa2,
  BTC_OP_MIN = 0xa3,
  BTC_OP_MAX = 0xa4,

  BTC_OP_WITHIN = 0xa5,

  /* crypto */
  BTC_OP_RIPEMD160 = 0xa6,
  BTC_OP_SHA1 = 0xa7,
  BTC_OP_SHA256 = 0xa8,
  BTC_OP_HASH160 = 0xa9,
  BTC_OP_HASH256 = 0xaa,
  BTC_OP_CODESEPARATOR = 0xab,
  BTC_OP_CHECKSIG = 0xac,
  BTC_OP_CHECKSIGVERIFY = 0xad,
  BTC_OP_CHECKMULTISIG = 0xae,
  BTC_OP_CHECKMULTISIGVERIFY = 0xaf,

  /* expansion */
  BTC_OP_NOP1 = 0xb0,
  BTC_OP_CHECKLOCKTIMEVERIFY = 0xb1,
  BTC_OP_NOP2 = BTC_OP_CHECKLOCKTIMEVERIFY,
  BTC_OP_CHECKSEQUENCEVERIFY = 0xb2,
  BTC_OP_NOP3 = BTC_OP_CHECKSEQUENCEVERIFY,
  BTC_OP_NOP4 = 0xb3,
  BTC_OP_NOP5 = 0xb4,
  BTC_OP_NOP6 = 0xb5,
  BTC_OP_NOP7 = 0xb6,
  BTC_OP_NOP8 = 0xb7,
  BTC_OP_NOP9 = 0xb8,
  BTC_OP_NOP10 = 0xb9,

  BTC_OP_INVALIDOPCODE = 0xff
};

/*
 * Small Integer
 */

#define btc_smi_encode(x) ((x) == 0 ? BTC_OP_0 : ((x) + (BTC_OP_1 - 1)))
#define btc_smi_decode(x) ((x) == BTC_OP_0 ? 0 : ((x) - (BTC_OP_1 - 1)))

/*
 * Script Number
 */

BTC_EXTERN int
btc_scriptnum_is_minimal(const uint8_t *xp, size_t xn);

BTC_EXTERN size_t
btc_scriptnum_export(uint8_t *zp, int64_t x);

BTC_EXTERN int64_t
btc_scriptnum_import(const uint8_t *xp, size_t xn);

/*
 * Stack
 */

BTC_DEFINE_HASHABLE_VECTOR(btc_stack, btc_buffer, BTC_EXTERN)

BTC_EXTERN btc_buffer_t *
btc_stack_get(const btc_stack_t *stack, int index);

BTC_EXTERN int
btc_stack_get_num(int64_t *num,
                  const btc_stack_t *stack,
                  int index,
                  int minimal,
                  size_t limit);

BTC_EXTERN int
btc_stack_get_int(int *num,
                  const btc_stack_t *stack,
                  int index,
                  int minimal,
                  size_t limit);

BTC_EXTERN int
btc_stack_get_bool(const btc_stack_t *stack, int index);

BTC_EXTERN void
btc_stack_push_data(btc_stack_t *stack, const uint8_t *data, size_t length);

BTC_EXTERN void
btc_stack_push_num(btc_stack_t *stack, int64_t num);

BTC_EXTERN void
btc_stack_push_bool(btc_stack_t *stack, int value);

/*
 * Opcode
 */

BTC_DEFINE_SERIALIZABLE_OBJECT(btc_opcode, BTC_EXTERN)

BTC_EXTERN void
btc_opcode_init(btc_opcode_t *z);

BTC_EXTERN void
btc_opcode_clear(btc_opcode_t *z);

BTC_EXTERN void
btc_opcode_copy(btc_opcode_t *z, const btc_opcode_t *x);

BTC_EXTERN int
btc_opcode_equal(const btc_opcode_t *x, const btc_opcode_t *y);

BTC_EXTERN int
btc_opcode_is_minimal(const btc_opcode_t *x);

BTC_EXTERN int
btc_opcode_is_disabled(const btc_opcode_t *x);

BTC_EXTERN int
btc_opcode_is_branch(const btc_opcode_t *x);

BTC_EXTERN void
btc_opcode_set_push(btc_opcode_t *z, const uint8_t *data, size_t length);

BTC_EXTERN void
btc_opcode_set_num(btc_opcode_t *z, int64_t value, uint8_t *scratch);

BTC_EXTERN size_t
btc_opcode_size(const btc_opcode_t *x);

BTC_EXTERN uint8_t *
btc_opcode_write(uint8_t *zp, const btc_opcode_t *x);

BTC_EXTERN int
btc_opcode_read(btc_opcode_t *z, const uint8_t **xp, size_t *xn);

/*
 * Script
 */

#define btc_script_create btc_buffer_create
#define btc_script_destroy btc_buffer_destroy
#define btc_script_clone btc_buffer_clone
#define btc_script_ref btc_buffer_ref
#define btc_script_refconst btc_buffer_refconst

#define btc_script_export btc_buffer_export
#define btc_script_encode btc_buffer_encode
#define btc_script_import btc_buffer_import
#define btc_script_decode btc_buffer_decode

#define btc_script_init btc_buffer_init
#define btc_script_clear btc_buffer_clear
#define btc_script_grow btc_buffer_grow
#define btc_script_resize btc_buffer_resize
#define btc_script_set btc_buffer_set
#define btc_script_copy btc_buffer_copy
#define btc_script_roset btc_buffer_roset
#define btc_script_rocopy btc_buffer_rocopy
#define btc_script_roclone btc_buffer_roclone
#define btc_script_equal btc_buffer_equal
#define btc_script_size btc_buffer_size
#define btc_script_write btc_buffer_write
#define btc_script_read btc_buffer_read
#define btc_script_update btc_buffer_update

BTC_EXTERN void
btc_script_hash160(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN void
btc_script_sha256(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_p2pk(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_p2pk(btc_script_t *script, const uint8_t *pub, size_t len);

BTC_EXTERN int
btc_script_get_p2pk(uint8_t *pub, size_t *len, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_p2pkh(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_p2pkh(btc_script_t *script, const uint8_t *hash);

BTC_EXTERN int
btc_script_get_p2pkh(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_multisig(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_multisig(btc_script_t *script,
                        unsigned int m,
                        const btc_multikey_t *keys,
                        unsigned int n);

BTC_EXTERN int
btc_script_get_multisig(unsigned int *m,
                        btc_multikey_t *keys,
                        unsigned int *n,
                        const btc_script_t *script);

BTC_EXTERN void
btc_multikey_sort(btc_multikey_t *keys, unsigned int n);

BTC_EXTERN int
btc_script_is_p2sh(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_p2sh(btc_script_t *script, const uint8_t *hash);

BTC_EXTERN int
btc_script_get_p2sh(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_nulldata(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_nulldata(btc_script_t *script, const uint8_t *data, size_t len);

BTC_EXTERN int
btc_script_get_nulldata(const uint8_t **data,
                        size_t *len,
                        const btc_script_t *script);

BTC_EXTERN int
btc_script_is_commitment(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_commitment(btc_script_t *script, const uint8_t *hash);

BTC_EXTERN int
btc_script_get_commitment(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_program(const btc_script_t *script);

BTC_EXTERN void
btc_script_set_program(btc_script_t *script, const btc_program_t *program);

BTC_EXTERN int
btc_script_get_program(btc_program_t *program, const btc_script_t *script);

BTC_EXTERN int
btc_script_is_p2wpkh(const btc_script_t *script);

BTC_EXTERN int
btc_script_get_p2wpkh(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN void
btc_script_set_p2wpkh(btc_script_t *script, const uint8_t *hash);

BTC_EXTERN int
btc_script_is_p2wsh(const btc_script_t *script);

BTC_EXTERN int
btc_script_get_p2wsh(uint8_t *hash, const btc_script_t *script);

BTC_EXTERN void
btc_script_set_p2wsh(btc_script_t *script, const uint8_t *hash);

BTC_EXTERN int
btc_script_is_unknown(const btc_script_t *script);

BTC_EXTERN int
btc_script_is_standard(const btc_script_t *script);

BTC_EXTERN int
btc_script_is_unspendable(const btc_script_t *script);

BTC_EXTERN int
btc_script_is_push_only(const btc_script_t *script);

BTC_EXTERN int32_t
btc_script_get_height(const btc_script_t *script);

BTC_EXTERN int
btc_script_get_redeem(btc_script_t *redeem, const btc_script_t *script);

BTC_EXTERN int
btc_script_sigops(const btc_script_t *script, int accurate);

BTC_EXTERN int
btc_script_p2sh_sigops(const btc_script_t *script, const btc_script_t *input);

BTC_EXTERN int
btc_script_witness_sigops(const btc_script_t *script,
                          const btc_script_t *input,
                          const btc_stack_t *witness);

BTC_EXTERN int
btc_script_find_and_delete(btc_script_t *z, const btc_buffer_t *sig);

BTC_EXTERN void
btc_script_remove_separators(btc_script_t *z, const btc_script_t *x);

BTC_EXTERN int
btc_script_execute(const btc_script_t *script,
                   btc_stack_t *stack,
                   unsigned int flags,
                   const btc_tx_t *tx,
                   size_t index,
                   int64_t value,
                   int version,
                   btc_tx_cache_t *cache);

BTC_EXTERN int
btc_script_verify(const btc_script_t *input,
                  const btc_stack_t *witness,
                  const btc_script_t *output,
                  const btc_tx_t *tx,
                  size_t index,
                  int64_t value,
                  unsigned int flags,
                  btc_tx_cache_t *cache);

BTC_EXTERN size_t
btc_script_deflate(const btc_script_t *x);

BTC_EXTERN uint8_t *
btc_script_compress(uint8_t *zp, const btc_script_t *x);

BTC_EXTERN int
btc_script_decompress(btc_script_t *z, const uint8_t **xp, size_t *xn);

/*
 * Reader
 */

BTC_EXTERN void
btc_reader_init(btc_reader_t *z, const btc_script_t *x);

BTC_EXTERN int
btc_reader_next(btc_opcode_t *z, btc_reader_t *x);

BTC_EXTERN int
btc_reader_op(btc_reader_t *z);

/*
 * Writer
 */

BTC_EXTERN void
btc_writer_init(btc_writer_t *z);

BTC_EXTERN void
btc_writer_clear(btc_writer_t *z);

BTC_EXTERN void
btc_writer_push(btc_writer_t *z, btc_opcode_t *x);

BTC_EXTERN void
btc_writer_push_op(btc_writer_t *z, int value);

BTC_EXTERN void
btc_writer_push_data(btc_writer_t *z, const uint8_t *data, size_t length);

BTC_EXTERN void
btc_writer_push_num(btc_writer_t *z, int64_t value, uint8_t *scratch);

BTC_EXTERN void
btc_writer_compile(btc_script_t *z, const btc_writer_t *x);

/*
 * Disassembler
 */

BTC_EXTERN char *
btc_script_asm(const btc_script_t *script);

#ifdef __cplusplus
}
#endif

#endif /* BTC_SCRIPT_H */
