/*!
 * wallet.h - wallet for mako
 * Copyright (c) 2021, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/mako
 */

#ifndef BTC_WALLET_H
#define BTC_WALLET_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../mako/select.h"
#include "types.h"

/*
 * Macros
 */

#define BTC_WATCH_ONLY(x) ((x) >= 0x80000000U && (x) <= 0xfffffffeU)

/*
 * Wallet Options
 */

extern const btc_walopt_t *btc_walopt_default;

/*
 * Wallet
 */

btc_wallet_t *
btc_wallet_create(const btc_network_t *network, const btc_walopt_t *options);

void
btc_wallet_destroy(btc_wallet_t *wallet);

int
btc_wallet_open(btc_wallet_t *wallet, const char *path);

void
btc_wallet_close(btc_wallet_t *wallet);

int32_t
btc_wallet_height(btc_wallet_t *wallet);

int64_t
btc_wallet_rate(btc_wallet_t *wallet, int64_t rate);

void
btc_wallet_tick(void *ptr);

int
btc_wallet_locked(btc_wallet_t *wallet);

int
btc_wallet_encrypted(btc_wallet_t *wallet);

int64_t
btc_wallet_until(btc_wallet_t *wallet);

void
btc_wallet_lock(btc_wallet_t *wallet);

int
btc_wallet_unlock(btc_wallet_t *wallet, const char *pass, int64_t msec);

int
btc_wallet_encrypt(btc_wallet_t *wallet, const char *pass);

int
btc_wallet_decrypt(btc_wallet_t *wallet);

int
btc_wallet_master(btc_mnemonic_t *mnemonic,
                  btc_hdnode_t *master,
                  btc_wallet_t *wallet);

int
btc_wallet_purpose(uint32_t *purpose,
                   uint32_t *account,
                   btc_wallet_t *wallet,
                   uint32_t number);

int
btc_wallet_path(btc_path_t *path,
                btc_wallet_t *wallet,
                const btc_address_t *addr);

int
btc_wallet_output_path(btc_path_t *path,
                       btc_wallet_t *wallet,
                       const btc_output_t *output);

int
btc_wallet_lookup(uint32_t *account, btc_wallet_t *wallet, const char *name);

int
btc_wallet_name(char *name, size_t size,
                btc_wallet_t *wallet,
                uint32_t account);

int
btc_wallet_balance(btc_balance_t *bal, btc_wallet_t *wallet, uint32_t account);

int
btc_wallet_watched(btc_balance_t *bal, btc_wallet_t *wallet, uint32_t account);

int
btc_wallet_privkey(uint8_t *privkey,
                   btc_wallet_t *wallet,
                   const btc_path_t *path);

int
btc_wallet_pubkey(uint8_t *pubkey,
                  btc_wallet_t *wallet,
                  const btc_path_t *path);

int
btc_wallet_address(btc_address_t *addr,
                   btc_wallet_t *wallet,
                   const btc_path_t *path);

int
btc_wallet_receive(btc_address_t *addr,
                   btc_wallet_t *wallet,
                   uint32_t account);

int
btc_wallet_change(btc_address_t *addr,
                  btc_wallet_t *wallet,
                  uint32_t account);

int
btc_wallet_next(btc_address_t *addr,
                btc_wallet_t *wallet,
                uint32_t account);

int
btc_wallet_prev(btc_address_t *addr,
                btc_wallet_t *wallet,
                uint32_t account);

int
btc_wallet_create_account(btc_wallet_t *wallet,
                          const char *name,
                          uint32_t account);

int
btc_wallet_create_watcher(btc_wallet_t *wallet,
                          const char *name,
                          const btc_hdnode_t *node);

btc_outset_t *
btc_wallet_frozen(btc_wallet_t *wallet);

void
btc_wallet_freeze(btc_wallet_t *wallet, const btc_outpoint_t *outpoint);

void
btc_wallet_unfreeze(btc_wallet_t *wallet, const btc_outpoint_t *outpoint);

int
btc_wallet_is_frozen(btc_wallet_t *wallet, const btc_outpoint_t *outpoint);

void
btc_wallet_freezes(btc_wallet_t *wallet, const btc_tx_t *tx);

void
btc_wallet_unfreezes(btc_wallet_t *wallet, const btc_tx_t *tx);

int
btc_wallet_fund(btc_wallet_t *wallet,
                uint32_t account,
                const btc_selopt_t *options,
                btc_tx_t *tx);

int
btc_wallet_sign(btc_wallet_t *wallet, btc_tx_t *tx, const btc_view_t *view);

int
btc_wallet_send(btc_wallet_t *wallet,
                uint32_t account,
                const btc_selopt_t *options,
                btc_tx_t *tx);

int
btc_wallet_add_tx(btc_wallet_t *wallet, const btc_tx_t *tx);

int
btc_wallet_add_block(btc_wallet_t *wallet,
                     const btc_entry_t *entry,
                     const btc_block_t *block);

int
btc_wallet_remove_block(btc_wallet_t *wallet, const btc_entry_t *entry);

int
btc_wallet_rollback(btc_wallet_t *wallet, int32_t height);

int
btc_wallet_rescan(btc_wallet_t *wallet, int32_t height);

int
btc_wallet_abandon(btc_wallet_t *wallet, const uint8_t *hash);

int
btc_wallet_backup(btc_wallet_t *wallet, const char *path);

int
btc_wallet_coin(btc_coin_t **coin,
                btc_wallet_t *wallet,
                const uint8_t *hash,
                uint32_t index);

int
btc_wallet_meta(btc_txmeta_t *meta, btc_wallet_t *wallet, const uint8_t *hash);

int
btc_wallet_tx(btc_tx_t **tx, btc_wallet_t *wallet, const uint8_t *hash);

btc_view_t *
btc_wallet_view(btc_wallet_t *wallet, const btc_tx_t *tx);

btc_view_t *
btc_wallet_undo(btc_wallet_t *wallet, const btc_tx_t *tx);

btc_acctiter_t *
btc_wallet_accounts(btc_wallet_t *wallet);

btc_addriter_t *
btc_wallet_addresses(btc_wallet_t *wallet);

btc_coiniter_t *
btc_wallet_coins(btc_wallet_t *wallet);

btc_txiter_t *
btc_wallet_txs(btc_wallet_t *wallet);

#ifdef __cplusplus
}
#endif

#endif /* BTC_WALLET_H */
