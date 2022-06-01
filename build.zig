//! build.zig - zig build for mako
//! Copyright (c) 2022, Christopher Jeffrey (MIT License).
//! https://github.com/chjj/mako

const std = @import("std");
const ArrayList = std.ArrayList;
const Builder = std.build.Builder;
const CrossTarget = std.zig.CrossTarget;
const LibExeObjStep = std.build.LibExeObjStep;
const Mode = std.builtin.Mode;
const fs = std.fs;

//
// Helpers
//

fn buildLib(b: *Builder,
            name: []const u8,
            target: CrossTarget,
            mode: Mode,
            sources: []const []const u8,
            flags: []const []const u8,
            defines: []const []const u8) *LibExeObjStep {
  const lib = b.addStaticLibrary(name, null);

  lib.setTarget(target);
  lib.setBuildMode(mode);
  lib.linkLibC();
  lib.addIncludeDir("./include");
  lib.addIncludeDir("./deps/lcdb/include");
  lib.addCSourceFiles(sources, flags);

  for (defines) |def| {
    lib.defineCMacroRaw(def);
  }

  return lib;
}

fn buildExe(b: *Builder,
            name: []const u8,
            target: CrossTarget,
            mode: Mode,
            sources: []const []const u8,
            flags: []const []const u8,
            defines: []const []const u8,
            libs: []const []const u8) *LibExeObjStep {
  const exe = b.addExecutable(name, null);

  exe.setTarget(target);
  exe.setBuildMode(mode);
  exe.linkLibC();
  exe.addIncludeDir("./include");
  exe.addCSourceFiles(sources, flags);

  for (defines) |def| {
    exe.defineCMacroRaw(def);
  }

  for (libs) |lib| {
    exe.linkSystemLibrary(lib);
  }

  return exe;
}

//
// Build
//

pub fn build(b: *Builder) void {
  const pkg_version = "0.0.0";
  const abi_version = b.version(0, 0, 0);
  const inst_step = b.getInstallStep();
  const test_step = b.step("test", "Run tests");

  //
  // Options
  //
  b.setPreferredReleaseMode(.ReleaseFast);

  const target = b.standardTargetOptions(.{});
  const mode = b.standardReleaseOptions();

  const prefix = b.option([]const u8, "prefix",
                          "System install prefix (/usr/local)");
  const enable_asm = b.option(bool, "asm",
                              "Use inline assembly (true)") orelse true;
  const enable_int128 = b.option(bool, "int128",
                          "Use __int128 if available (true)") orelse true;
  const enable_node = b.option(bool, "node",
                               "Build the fullnode (true)") orelse true;
  const enable_pic = b.option(bool, "pic", "Force PIC (false)");
  const enable_portable = b.option(bool, "portable",
                            "Be as portable as possible (false)") orelse false;
  const enable_pthread = b.option(bool, "pthread",
                                  "Use pthread (true)") orelse true;
  const enable_shared = b.option(bool, "shared",
                                 "Build shared library (true)") orelse true;
  const enable_tests = b.option(bool, "tests",
                                "Enable tests (true)") orelse true;

  const strip = (b.is_release and !target.isWindows());

  //
  // Variables
  //
  var flags = ArrayList([]const u8).init(b.allocator);
  var defines = ArrayList([]const u8).init(b.allocator);
  var libs = ArrayList([]const u8).init(b.allocator);

  defer flags.deinit();
  defer defines.deinit();
  defer libs.deinit();

  //
  // Global Flags
  //
  if (target.isGnuLibC()) {
    flags.append("-std=c89") catch unreachable;
  }

  flags.append("-fvisibility=hidden") catch unreachable;

  if (target.isDarwin()) {
    flags.append("-mmacosx-version-min=10.7") catch unreachable;
  }

  if (mode == .ReleaseFast) {
    flags.append("-O3") catch unreachable;
  }

  //
  // Feature Test Macros
  //
  if (target.isWindows()) {
    defines.append("_WIN32_WINNT=0x501") catch unreachable;
  }

  if (target.isGnuLibC()) {
    defines.append("_GNU_SOURCE") catch unreachable;
  }

  if (target.getOsTag() == .solaris) {
    defines.append("_TS_ERRNO") catch unreachable;
  }

  if (target.getOsTag() == .aix) {
    defines.append("_THREAD_SAFE_ERRNO") catch unreachable;
  }

  //
  // System Libraries
  //
  if (target.isWindows()) {
    libs.append("kernel32") catch unreachable;
    libs.append("advapi32") catch unreachable;
    libs.append("ws2_32") catch unreachable;
  } else {
    libs.append("m") catch unreachable;

    if (enable_portable and target.isGnuLibC()) {
      libs.append("rt") catch unreachable;
    }

    if (enable_pthread and target.getOsTag() != .wasi) {
      flags.append("-pthread") catch unreachable;
      libs.append("pthread") catch unreachable;
      defines.append("BTC_PTHREAD") catch unreachable;
      defines.append("LDB_PTHREAD") catch unreachable;
    }

    if (target.getOsTag() == .haiku) {
      libs.append("network") catch unreachable;
    }

    if (target.getOsTag() == .solaris) {
      libs.append("socket") catch unreachable;
      libs.append("nsl") catch unreachable;
    }
  }

  //
  // Sources
  //
  const mako_sources = [_][]const u8{
    "src/crypto/chacha20.c",
    "src/crypto/drbg.c",
    "src/crypto/ecc.c",
    "src/crypto/hash160.c",
    "src/crypto/hash256.c",
    "src/crypto/hmac256.c",
    "src/crypto/hmac512.c",
    "src/crypto/merkle.c",
    "src/crypto/poly1305.c",
    "src/crypto/pbkdf256.c",
    "src/crypto/pbkdf512.c",
    "src/crypto/rand.c",
    "src/crypto/rand_env.c",
    "src/crypto/rand_sys.c",
    "src/crypto/ripemd160.c",
    "src/crypto/salsa20.c",
    "src/crypto/secretbox.c",
    "src/crypto/sha1.c",
    "src/crypto/sha256.c",
    "src/crypto/sha512.c",
    "src/crypto/siphash.c",
    "src/json/json_builder.c",
    "src/json/json_extra.c",
    "src/json/json_parser.c",
    "src/map/addrmap.c",
    "src/map/addrset.c",
    "src/map/hashmap.c",
    "src/map/hashset.c",
    "src/map/hashtab.c",
    "src/map/intmap.c",
    "src/map/longmap.c",
    "src/map/longset.c",
    "src/map/longtab.c",
    "src/map/netmap.c",
    "src/map/outmap.c",
    "src/map/outset.c",
    "src/address.c",
    "src/amount.c",
    "src/array.c",
    "src/base16.c",
    "src/base58.c",
    "src/bech32.c",
    "src/bip32.c",
    "src/bip37.c",
    "src/bip39.c",
    "src/bip152.c",
    "src/block.c",
    "src/bloom.c",
    "src/buffer.c",
    "src/coin.c",
    "src/compact.c",
    "src/compress.c",
    "src/consensus.c",
    "src/entry.c",
    "src/header.c",
    "src/heap.c",
    "src/input.c",
    "src/inpvec.c",
    "src/inspect.c",
    "src/internal.c",
    "src/json.c",
    "src/mainnet.c",
    "src/mpi.c",
    "src/murmur3.c",
    "src/netaddr.c",
    "src/netmsg.c",
    "src/network.c",
    "src/outpoint.c",
    "src/output.c",
    "src/outvec.c",
    "src/policy.c",
    "src/printf.c",
    "src/printf_core.c",
    "src/regtest.c",
    "src/script.c",
    "src/select.c",
    "src/sign.c",
    "src/signet.c",
    "src/simnet.c",
    "src/sprintf.c",
    "src/testnet.c",
    "src/tx.c",
    "src/undo.c",
    "src/util.c",
    "src/vector.c",
    "src/view.c"
  };

  const io_sources = [_][]const u8{
    "src/io/http/http_client.c",
    "src/io/http/http_common.c",
    "src/io/http/http_parser.c",
    "src/io/http/http_server.c",
    "src/io/addrinfo.c",
    "src/io/core.c",
    "src/io/loop.c",
    "src/io/net.c",
    "src/io/sockaddr.c",
    "src/io/workers.c"
  };

  const base_sources = [_][]const u8{
    "src/base/addrman.c",
    "src/base/config.c",
    "src/base/logger.c",
    "src/base/timedata.c"
  };

  const lcdb_sources = [_][]const u8{
    "deps/lcdb/src/util/arena.c",
    "deps/lcdb/src/util/array.c",
    "deps/lcdb/src/util/atomic.c",
    "deps/lcdb/src/util/bloom.c",
    "deps/lcdb/src/util/buffer.c",
    "deps/lcdb/src/util/cache.c",
    "deps/lcdb/src/util/comparator.c",
    "deps/lcdb/src/util/crc32c.c",
    "deps/lcdb/src/util/env.c",
    "deps/lcdb/src/util/hash.c",
    "deps/lcdb/src/util/internal.c",
    "deps/lcdb/src/util/logger.c",
    "deps/lcdb/src/util/options.c",
    "deps/lcdb/src/util/port.c",
    "deps/lcdb/src/util/random.c",
    "deps/lcdb/src/util/rbt.c",
    "deps/lcdb/src/util/slice.c",
    "deps/lcdb/src/util/snappy.c",
    "deps/lcdb/src/util/status.c",
    "deps/lcdb/src/util/strutil.c",
    "deps/lcdb/src/util/thread_pool.c",
    "deps/lcdb/src/util/vector.c",
    "deps/lcdb/src/table/block.c",
    "deps/lcdb/src/table/block_builder.c",
    "deps/lcdb/src/table/filter_block.c",
    "deps/lcdb/src/table/format.c",
    "deps/lcdb/src/table/iterator.c",
    "deps/lcdb/src/table/merger.c",
    "deps/lcdb/src/table/table.c",
    "deps/lcdb/src/table/table_builder.c",
    "deps/lcdb/src/table/two_level_iterator.c",
    "deps/lcdb/src/builder.c",
    "deps/lcdb/src/c.c",
    "deps/lcdb/src/db_impl.c",
    "deps/lcdb/src/db_iter.c",
    "deps/lcdb/src/dbformat.c",
    "deps/lcdb/src/dumpfile.c",
    "deps/lcdb/src/filename.c",
    "deps/lcdb/src/log_reader.c",
    "deps/lcdb/src/log_writer.c",
    "deps/lcdb/src/memtable.c",
    "deps/lcdb/src/repair.c",
    "deps/lcdb/src/skiplist.c",
    "deps/lcdb/src/table_cache.c",
    "deps/lcdb/src/version_edit.c",
    "deps/lcdb/src/version_set.c",
    "deps/lcdb/src/write_batch.c"
  };

  const node_sources = [_][]const u8{
    "src/node/chain.c",
    "src/node/chaindb.c",
    "src/node/mempool.c",
    "src/node/miner.c",
    "src/node/node.c",
    "src/node/pool.c",
    "src/node/rpc.c"
  };

  const wallet_sources = [_][]const u8{
    "src/wallet/account.c",
    "src/wallet/client.c",
    "src/wallet/iterator.c",
    "src/wallet/master.c",
    "src/wallet/record.c",
    "src/wallet/txdb.c",
    "src/wallet/wallet.c"
  };

  const client_sources = [_][]const u8{
    "src/client/client.c"
  };

  const test_sources = [_][]const u8{
    "test/lib/tests.c",
    "test/lib/rimraf.c"
  };

  //
  // Flags
  //
  const warn_flags = [_][]const u8{
    "-pedantic",
    "-Wall",
    "-Wextra",
    "-Wcast-align",
    "-Wconditional-uninitialized",
    "-Wmissing-prototypes",
    "-Wno-implicit-fallthrough",
    "-Wno-long-long",
    "-Wno-overlength-strings",
    "-Wshadow",
    "-Wstrict-prototypes",
    "-Wundef"
  };

  for (warn_flags) |flag| {
    flags.append(flag) catch unreachable;
  }

  if (!target.isNative()) {
    // Ensure we are redistributable on other OSes.
    flags.append("-static-libgcc") catch unreachable;
  }

  if (target.isWindows() and target.cpu_arch != null) {
    // Much compatibility.
    if (enable_portable and target.cpu_arch.? == .i386) {
      flags.append("-march=i486") catch unreachable;
      flags.append("-mtune=i686") catch unreachable;
    }
  }

  //
  // Defines
  //
  if (enable_asm) {
    defines.append("BTC_HAVE_ASM") catch unreachable;
  }

  if (target.getCpuArch().endian() == .Big) {
    defines.append("BTC_BIGENDIAN") catch unreachable;
  }

  if (!enable_portable and !target.isWindows()) {
    defines.append("BTC_HAVE_CLOCK") catch unreachable;
  }

  if (mode == .Debug) {
    defines.append("BTC_DEBUG") catch unreachable;
    defines.append("LDB_DEBUG") catch unreachable;
  }

  if (!enable_portable) {
    defines.append("LDB_HAVE_FDATASYNC") catch unreachable;
  }

  if (!enable_portable or target.isWindows()) {
    defines.append("BTC_HAVE_GETHOSTNAME") catch unreachable;
  }

  if (!enable_portable and !target.isWindows()) {
    defines.append("BTC_HAVE_GETIFADDRS") catch unreachable;
  }

  if (enable_int128 and target.getCpuArch().ptrBitWidth() > 32) {
    defines.append("BTC_HAVE_INT128") catch unreachable;
  }

  if (enable_portable) {
    defines.append("BTC_PORTABLE") catch unreachable;
  }

  if (!enable_portable) {
    defines.append("LDB_HAVE_PREAD") catch unreachable;
  }

  if (!enable_portable) {
    defines.append("BTC_HAVE_RFC3493") catch unreachable;
  }

  //
  // Targets
  //
  const libname = if (target.isWindows()) "libmako" else "mako";
  const mako = buildLib(b, libname, target, mode, &mako_sources,
                                    flags.items, defines.items);

  mako.install();
  mako.force_pic = enable_pic;
  mako.strip = strip;

  if (enable_shared and target.getOsTag() != .wasi) {
    const shared = b.addSharedLibrary("mako", null, abi_version);

    shared.setTarget(target);
    shared.setBuildMode(mode);
    shared.install();
    shared.linkLibC();
    shared.addIncludeDir("./include");
    shared.addCSourceFiles(&mako_sources, flags.items);
    shared.strip = strip;

    for (defines.items) |def| {
      shared.defineCMacroRaw(def);
    }

    shared.defineCMacroRaw("BTC_EXPORT");

    for (libs.items) |lib| {
      shared.linkSystemLibrary(lib);
    }
  }

  const testlib = buildLib(b, "test", target, mode, &test_sources,
                                      flags.items, defines.items);

  //
  // Node Targets
  //
  if (enable_node and target.getOsTag() != .wasi) {
    const lcdb = buildLib(b, "lcdb", target, mode, &lcdb_sources,
                                     flags.items, defines.items);

    const io = buildLib(b, "io", target, mode, &io_sources,
                                 flags.items, defines.items);

    const base = buildLib(b, "base", target, mode, &base_sources,
                                     flags.items, defines.items);

    const node = buildLib(b, "node", target, mode, &node_sources,
                                     flags.items, defines.items);

    const wallet = buildLib(b, "wallet", target, mode, &wallet_sources,
                                         flags.items, defines.items);

    const client = buildLib(b, "client", target, mode, &client_sources,
                                         flags.items, defines.items);

    const daemon = buildExe(b, "makod", target, mode,
                                        &.{ "src/node/main.c" },
                                        flags.items,
                                        defines.items,
                                        libs.items);

    daemon.linkLibrary(node);
    daemon.linkLibrary(wallet);
    daemon.linkLibrary(base);
    daemon.linkLibrary(io);
    daemon.linkLibrary(mako);
    daemon.linkLibrary(lcdb);
    daemon.install();
    daemon.strip = strip;

    const cli = buildExe(b, "mako", target, mode,
                                    &.{ "src/client/main.c" },
                                    flags.items,
                                    defines.items,
                                    libs.items);

    cli.linkLibrary(client);
    cli.linkLibrary(base);
    cli.linkLibrary(io);
    cli.linkLibrary(mako);
    cli.install();
    cli.strip = strip;

    //
    // Node Tests
    //
    const node_tests = [_][]const u8{
      // io
      "addrinfo",
      "sockaddr",
      "fs",
      "loop",
      "thread",
      "http",
      "workers",
      // base
      "addrman",
      "config",
      "timedata",
      // node
      "chaindb",
      "chain",
      "mempool",
      "miner",
      "rpc",
      // wallet
      "wallet"
    };

    for (node_tests) |name| {
      const src = b.fmt("test/t-{s}.c", .{ name });
      const bin = b.fmt("t-{s}", .{ name });
      const t = buildExe(b, bin,
                         target,
                         mode,
                         &.{ src },
                         flags.items,
                         defines.items,
                         libs.items);

      t.linkLibrary(node);
      t.linkLibrary(wallet);
      t.linkLibrary(client);
      t.linkLibrary(base);
      t.linkLibrary(io);
      t.linkLibrary(testlib);
      t.linkLibrary(mako);
      t.linkLibrary(lcdb);

      if (enable_tests) {
        inst_step.dependOn(&t.step);
      }

      test_step.dependOn(&t.run().step);
    }
  }

  //
  // Tests
  //
  const tests = [_][]const u8{
    // crypto
    "bip340",
    "chacha20",
    "drbg",
    "ecdsa",
    "hash160",
    "hash256",
    "hmac",
    "merkle",
    "poly1305",
    "pbkdf2",
    "rand",
    "ripemd160",
    "salsa20",
    "secretbox",
    "sha1",
    "sha256",
    "sha512",
    "siphash",
    // lib
    "address",
    "array",
    "base16",
    "base58",
    "bech32",
    "bip32",
    "bip37",
    "bip39",
    "bip152",
    "block",
    "bloom",
    "coin",
    "entry",
    "header",
    "heap",
    "input",
    "list",
    "map",
    "mpi",
    "murmur3",
    "netaddr",
    "netmsg",
    "outpoint",
    "output",
    "printf",
    "script",
    "sighash",
    "tx",
    "util",
    "vector",
    "view"
  };

  for (tests) |name| {
    const src = b.fmt("test/t-{s}.c", .{ name });
    const bin = b.fmt("t-{s}", .{ name });
    const t = buildExe(b, bin,
                       target,
                       mode,
                       &.{ src },
                       flags.items,
                       defines.items,
                       libs.items);

    t.linkLibrary(testlib);
    t.linkLibrary(mako);

    if (enable_tests) {
      inst_step.dependOn(&t.step);
    }

    test_step.dependOn(&t.run().step);
  }

  //
  // Package Config
  //
  if (!target.isWindows() and target.getOsTag() != .wasi) {
    const pkg_prefix = prefix orelse "/usr/local";
    const pkg_libs = if (enable_pthread) "-lpthread" else "";
    const pkg_conf = b.fmt(
      \\prefix={s}
      \\exec_prefix=${{prefix}}
      \\libdir=${{exec_prefix}}/{s}
      \\includedir=${{prefix}}/{s}
      \\
      \\Name: libmako
      \\Version: {s}
      \\Description: Bitcoin library.
      \\URL: https://github.com/chjj/mako
      \\
      \\Cflags: -I${{includedir}}
      \\Libs: -L${{libdir}} -lmako
      \\Libs.private: -lm {s}
      \\
      ,
      .{
        pkg_prefix,
        "lib",
        "include",
        pkg_version,
        pkg_libs
      }
    );

    fs.cwd().writeFile(b.pathFromRoot("libmako.pc"), pkg_conf) catch {};
  }

  //
  // Install
  //
  b.installDirectory(.{
    .source_dir = "include/mako",
    .install_dir = .header,
    .install_subdir = "mako"
  });

  if (!target.isWindows() and target.getOsTag() != .wasi) {
    b.installFile("LICENSE", "share/licenses/mako/LICENSE");
    b.installFile("README.md", "share/doc/mako/README.md");
    b.installFile("libmako.pc", "lib/pkgconfig/libmako.pc");
  } else {
    b.installFile("LICENSE", "LICENSE");
    b.installFile("README.md", "README.md");
  }
}
