//! Structural contract tests for the KeyOS TRNG wiring.
//!
//! Statistics can NEVER catch disclosure bug 1 (a fixed-seed CSPRNG is
//! statistically perfect — see `entropy.rs`'s
//! `control_fixed_seed_passes_and_that_is_the_point`, which proves this
//! battery cannot see it either). The only defence against that failure
//! mode is structural: assert that the RNG we *think* we linked is the RNG
//! we *actually* linked, at every layer that could silently substitute it.
//!
//! Every assertion here is written as a pure function over its input (repo
//! text, a dependency-resolve graph, a file list) plus a thin wrapper that
//! feeds it the real repo. That split is deliberate: it lets each contract
//! be MUTATION-TESTED — fed a deliberately-broken variant of the thing it
//! guards, with a permanent test asserting the break is caught. A contract
//! test that cannot fail is worse than no test at all.
//!
//! `vendor/getrandom` and its four hardened files are DO-NOT-EDIT
//! (workspace CLAUDE.md / this repo's CLAUDE.md); this file only reads
//! them.
//!
//! Lives at the APP level (not in notes-core) since 2026-09-02, when
//! notes-core moved to the `ByteApps/graffito` repo: everything here is
//! about THIS workspace's `[patch.crates-io]` and vendored backend, and the
//! graph guard now walks from the app root — a superset of notes-core's
//! graph (graffito-core + the vendored security-api included). notes-core's
//! portable half (getrandom 0.2-only, no `register_custom_getrandom!`)
//! lives with it as `graffito/notes-core/tests/rng_backend.rs`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

// =======================================================================
// 1. Cargo.toml redirects getrandom to vendor/getrandom via
//    [patch.crates-io].
// =======================================================================

fn patches_getrandom_to_vendor(cargo_toml: &str) -> bool {
    let mut in_patch_section = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.trim();
        if let Some(inner) = line.strip_prefix('[') {
            let name = inner.trim_end_matches(']').trim();
            in_patch_section = name == "patch.crates-io";
            continue;
        }
        if !in_patch_section {
            continue;
        }
        if let Some(rest) = line.strip_prefix("getrandom") {
            let rest = rest.trim_start();
            if let Some(rhs) = rest.strip_prefix('=') {
                return rhs.contains("path") && rhs.contains("vendor/getrandom");
            }
        }
    }
    false
}

#[test]
fn contract_cargo_toml_patches_getrandom_to_vendor() {
    let cargo_toml = include_str!("../Cargo.toml");
    assert!(
        patches_getrandom_to_vendor(cargo_toml),
        "repo Cargo.toml must [patch.crates-io] getrandom to path \"vendor/getrandom\" — \
         without this the TRNG override never links on device"
    );
}

#[test]
fn mutation_missing_patch_section_is_caught() {
    let mutated = "[package]\nname = \"x\"\n[dependencies]\ngetrandom = \"0.2\"\n";
    assert!(!patches_getrandom_to_vendor(mutated), "no [patch.crates-io] section at all must fail");
}

#[test]
fn mutation_patch_pointing_at_registry_is_caught() {
    let mutated = "[patch.crates-io]\ngetrandom = \"0.2.10\"\n";
    assert!(!patches_getrandom_to_vendor(mutated), "a version-only patch (no path override) must fail");
}

#[test]
fn mutation_patch_wrong_path_is_caught() {
    let mutated = "[patch.crates-io]\ngetrandom = { path = \"some/other/getrandom\" }\n";
    assert!(!patches_getrandom_to_vendor(mutated), "a patch pointing somewhere other than vendor/getrandom must fail");
}

#[test]
fn mutation_patch_section_present_but_empty_is_caught() {
    let mutated = "[patch.crates-io]\nsome-other-crate = { path = \"vendor/other\" }\n";
    assert!(!patches_getrandom_to_vendor(mutated), "a patch section that never mentions getrandom must fail");
}

// =======================================================================
// 2. vendor/getrandom/src/lib.rs: the backend cfg_if! chain has a
//    #[cfg(keyos)] arm BEFORE the feature="custom" arm, and its final
//    fallback arm is compile_error!. Ordering is load-bearing: if custom
//    ever won, an unflagged device build would silently rebind instead of
//    failing to compile.
// =======================================================================

/// Slice out just the backend-selection `cfg_if! { ... }` chain (up to the
/// `pub fn getrandom(` that follows it) so arm-order checks can't be
/// confused by the unrelated `#[cfg(feature = "custom")] mod custom;`
/// line earlier in the file.
fn extract_backend_chain(src: &str) -> Option<&str> {
    let start = src.find("cfg_if! {")?;
    let after = &src[start..];
    let end = after.find("pub fn getrandom(")?;
    Some(&after[..end])
}

/// `None` if either arm is missing entirely (a stronger failure than
/// ordering — the caller must not treat that as "ok").
fn keyos_arm_precedes_custom(chain: &str) -> Option<bool> {
    let keyos_pos = chain.find("cfg(keyos)")?;
    let custom_pos = chain.find("feature = \"custom\"")?;
    Some(keyos_pos < custom_pos)
}

fn final_arm_is_compile_error(chain: &str) -> bool {
    match chain.rfind("} else {") {
        Some(pos) => chain[pos..].contains("compile_error!"),
        None => false,
    }
}

#[test]
fn contract_backend_cfg_order_and_fallback() {
    let src = include_str!("../vendor/getrandom/src/lib.rs");
    let chain = extract_backend_chain(src).expect("backend cfg_if! chain not found in lib.rs");
    assert_eq!(
        keyos_arm_precedes_custom(chain),
        Some(true),
        "#[cfg(keyos)] must appear BEFORE the feature=\"custom\" arm — if custom ever won, \
         an unflagged device build would silently rebind instead of failing to compile"
    );
    assert!(
        final_arm_is_compile_error(chain),
        "the final fallback arm of the backend chain must be compile_error!, not a silent \
         no-op/default backend"
    );
}

#[test]
fn mutation_custom_before_keyos_is_caught() {
    let chain = r#"
        if #[cfg(feature = "custom")] {
            use custom as imp;
        } else if #[cfg(keyos)] {
            #[path = "xous.rs"] mod imp;
        } else {
            compile_error!("nope");
        }
    "#;
    assert_eq!(keyos_arm_precedes_custom(chain), Some(false), "custom before keyos must be caught");
}

#[test]
fn mutation_missing_keyos_arm_is_caught() {
    let chain = r#"
        if #[cfg(feature = "custom")] {
            use custom as imp;
        } else {
            compile_error!("nope");
        }
    "#;
    assert_eq!(
        keyos_arm_precedes_custom(chain),
        None,
        "a chain with no #[cfg(keyos)] arm at all must be detected as absent, not silently ok"
    );
}

#[test]
fn mutation_final_arm_not_compile_error_is_caught() {
    let chain = r#"
        if #[cfg(keyos)] {
            #[path = "xous.rs"] mod imp;
        } else if #[cfg(feature = "custom")] {
            use custom as imp;
        } else {
            #[path = "some_default.rs"] mod imp;
        }
    "#;
    assert!(!final_arm_is_compile_error(chain), "a non-compile_error! fallback must be caught");
}

// =======================================================================
// 3. vendor/getrandom/src/xous.rs still calls write_sentinel,
//    looks_unfilled and words_for — the fill-verification hardening
//    cannot be silently reverted.
// =======================================================================

fn calls_hardening_functions(src: &str) -> bool {
    // Match call syntax (`name(`), not bare identifier text — xous.rs's own
    // `use crate::trng_check::{looks_unfilled, words_for, write_sentinel};`
    // import line mentions all three names without calling them, so a bare
    // substring check would stay "true" even if every call site were
    // deleted and only the (now-unused) import remained.
    ["write_sentinel(", "looks_unfilled(", "words_for("].iter().all(|f| src.contains(f))
}

#[test]
fn contract_xous_backend_calls_hardening_functions() {
    let src = include_str!("../vendor/getrandom/src/xous.rs");
    assert!(
        calls_hardening_functions(src),
        "xous.rs must still call write_sentinel/looks_unfilled/words_for — losing any of \
         these silently reverts the fill-verification hardening"
    );
}

#[test]
fn mutation_missing_write_sentinel_is_caught() {
    let src = "fn f(b: &mut [u8]) { let u = looks_unfilled(b); let w = words_for(4); }";
    assert!(!calls_hardening_functions(src));
}

#[test]
fn mutation_missing_looks_unfilled_is_caught() {
    let src = "fn f(b: &mut [u8]) { write_sentinel(b); let w = words_for(4); }";
    assert!(!calls_hardening_functions(src));
}

#[test]
fn mutation_missing_words_for_is_caught() {
    let src = "fn f(b: &mut [u8]) { write_sentinel(b); let u = looks_unfilled(b); }";
    assert!(!calls_hardening_functions(src));
}

// =======================================================================
// 4. register_custom_getrandom! appears nowhere in the repo outside
//    vendor/getrandom.
// =======================================================================

/// Files whose content contains `needle`, excluding this contract test
/// file itself (which necessarily names the macro, in comments/asserts,
/// to test for it).
fn files_matching<'a>(files: &'a [(String, String)], needle: &str, exclude_file_name: &str) -> Vec<&'a str> {
    files
        .iter()
        .filter(|(path, _)| !path.ends_with(exclude_file_name))
        .filter(|(_, content)| content.contains(needle))
        .map(|(path, _)| path.as_str())
        .collect()
}

/// Recursively collect `(path, content)` for every `.rs` file under
/// `root`, skipping VCS/build/dependency directories, symlinks (so an SDK
/// symlink like `ui/ui` never pulls in unrelated source trees), and the
/// vendored getrandom crate itself.
fn collect_rust_files(root: &Path, skip_dir_names: &[&str], vendor_getrandom: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                if path == vendor_getrandom {
                    continue;
                }
                let name = entry.file_name();
                if skip_dir_names.iter().any(|s| name == std::ffi::OsStr::new(s)) {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    out.push((path.to_string_lossy().into_owned(), content));
                }
            }
        }
    }
    out
}

#[test]
fn contract_register_custom_getrandom_only_in_vendor() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vendor_getrandom = repo_root.join("vendor").join("getrandom");
    let files = collect_rust_files(&repo_root, &[".git", "target", "node_modules"], &vendor_getrandom);
    assert!(
        !files.is_empty(),
        "sanity: the repo scan found zero .rs files — the walker is broken, not the repo"
    );
    let hits = files_matching(&files, "register_custom_getrandom", "rng_backend.rs");
    assert!(
        hits.is_empty(),
        "register_custom_getrandom! must appear nowhere outside vendor/getrandom, found in: {hits:?}"
    );
}

#[test]
fn mutation_stray_register_custom_getrandom_is_caught() {
    let files = vec![
        ("src/lib.rs".to_string(), "fn boot() {}".to_string()),
        (
            "src/some_crate/lib.rs".to_string(),
            "getrandom::register_custom_getrandom!(my_fn);".to_string(),
        ),
    ];
    let hits = files_matching(&files, "register_custom_getrandom", "rng_backend.rs");
    assert_eq!(
        hits,
        vec!["src/some_crate/lib.rs"],
        "a register_custom_getrandom! call outside vendor/getrandom MUST be flagged"
    );
}

#[test]
fn mutation_own_test_file_is_excluded_by_name_not_by_luck() {
    // Confirms the exclusion is an explicit filename check, not an
    // accident of scan order: a file that happens to share the excluded
    // name is skipped even though it "contains" the needle.
    let files = vec![("notes-core/tests/rng_backend.rs".to_string(), "register_custom_getrandom".to_string())];
    let hits = files_matching(&files, "register_custom_getrandom", "rng_backend.rs");
    assert!(hits.is_empty());
}

// =======================================================================
// 5. Dependency-graph guard: no crate reachable through NORMAL/BUILD
//    (non-dev) dependencies from the app root, ON THE DEVICE TARGET,
//    pulls a getrandom other than the vendored 0.2.x. getrandom 0.3.x/0.4.x sit in Cargo.lock
//    today (jobserver/tempfile/rand_core 0.9) but must be dev-only-
//    reachable — one dependency bump to a rand-0.9 consumer would
//    otherwise silently bypass the TRNG patch.
// =======================================================================

struct DepEdge<'a> {
    to: &'a str,
    /// True for a NORMAL or BUILD edge (`dep_kinds` contains kind `null`
    /// or `"build"`) — the edges cargo actually links into a device
    /// build. False for a DEV-only edge, which must not be followed.
    linked: bool,
}

/// BFS from `root` over `linked` edges only, collecting every reached
/// package id whose name is "getrandom".
fn reachable_getrandom_ids<'a>(
    root: &'a str,
    edges: &HashMap<&'a str, Vec<DepEdge<'a>>>,
    pkg_name: &HashMap<&'a str, &'a str>,
) -> BTreeSet<&'a str> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut stack = vec![root];
    let mut found = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if pkg_name.get(id) == Some(&"getrandom") {
            found.insert(id);
        }
        if let Some(es) = edges.get(id) {
            for e in es {
                if e.linked {
                    stack.push(e.to);
                }
            }
        }
    }
    found
}

fn assert_single_vendored(found: &BTreeSet<&str>, vendored_marker: &str) -> Result<(), String> {
    if found.len() != 1 {
        return Err(format!(
            "expected exactly 1 reachable getrandom package, found {}: {found:?}",
            found.len()
        ));
    }
    let only = found.iter().next().unwrap();
    if !only.contains(vendored_marker) {
        return Err(format!("the only reachable getrandom is NOT the vendored copy: {only}"));
    }
    Ok(())
}

/// The KeyOS device target. Only reachable through the Foundation SDK's
/// Nix-provided nightly rustc (see `cargo_metadata_json`).
const DEVICE_TARGET: &str = "armv7a-unknown-xous-elf";

fn nix_binary() -> String {
    if std::process::Command::new("nix").arg("--version").output().is_ok_and(|o| o.status.success()) {
        return "nix".to_string();
    }
    const FALLBACK: &str = "/nix/var/nix/profiles/default/bin/nix";
    if Path::new(FALLBACK).exists() {
        return FALLBACK.to_string();
    }
    panic!(
        "no `nix` executable found on PATH or at {FALLBACK} — the device-target dependency \
         graph check needs the Foundation SDK's Nix shell, which needs Nix itself"
    );
}

/// `cargo metadata --filter-platform armv7a-unknown-xous-elf` for THIS
/// app — the graph the device actually links. The filter is not optional:
/// walked target-blind from the app root, `getrandom 0.3` (via `nix` →
/// `cc` → `jobserver`, a host build-dep of the SDK's shared-memory crate)
/// and `getrandom 0.4` (via the hosted-simulator winit backend → zbus →
/// `uds_windows` → `tempfile`, `cfg(windows)`) both show up through
/// normal/build edges and the guard fails for the wrong reason (verified
/// 2026-09-02, the day this test moved up from notes-core). Same routine
/// as pgp-core's/wallet-core's: the device target is a patched-in
/// "custom" target only the SDK's nightly knows, gated behind
/// `-Zunstable-options`, so the call goes through `nix develop <sdk root>
/// --command cargo metadata` with that flag scoped to the one subprocess.
fn cargo_metadata_json() -> String {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    // Trust FOUNDATION_SDK_ROOT only when it is the SDK checkout (has a
    // flake.nix): inside `nix develop <sdk> --command cargo test` the SDK
    // shell exports it pointing at the current PROJECT instead.
    let sdk_root = std::env::var("FOUNDATION_SDK_ROOT")
        .ok()
        .filter(|p| Path::new(p).join("flake.nix").exists())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{home}/.foundation/sdk/current")
        });
    let nix = nix_binary();
    let out = std::process::Command::new(&nix)
        .args(["develop", &sdk_root, "--command", "cargo", "metadata", "--format-version", "1", "--filter-platform", DEVICE_TARGET, "--manifest-path"])
        .arg(&manifest)
        .env("RUSTFLAGS", "-Zunstable-options")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run `{nix} develop {sdk_root} --command cargo metadata` for the device \
                 target: {e}\n\nThis check needs the Foundation SDK's Nix shell — run `foundation \
                 doctor` and make sure `nix develop {sdk_root}` works on its own first."
            )
        });
    assert!(
        out.status.success(),
        "`nix develop {sdk_root} --command cargo metadata --filter-platform {DEVICE_TARGET}` failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("cargo metadata output was not UTF-8");
    // The SDK flake's shellHook prints a "Foundation SDK user shell ready."
    // banner onto stdout ahead of the command's output; the JSON document
    // starts at the first `{`.
    match stdout.find('{') {
        Some(idx) => stdout[idx..].to_string(),
        None => panic!("no JSON object found in `nix develop` output:\n{stdout}"),
    }
}

fn run_cargo_metadata() -> serde_json::Value {
    serde_json::from_str(&cargo_metadata_json()).expect("cargo metadata did not produce valid JSON")
}

fn edge_is_linked(dep_kinds: &serde_json::Value) -> bool {
    dep_kinds
        .as_array()
        .map(|kinds| {
            kinds.iter().any(|k| match k.get("kind").and_then(|v| v.as_str()) {
                None => true, // JSON null (or missing) kind == a normal dependency
                Some("build") => true,
                _ => false, // "dev", or anything else — not linked into a device build
            })
        })
        .unwrap_or(false)
}

#[test]
fn contract_dependency_graph_reaches_only_vendored_getrandom() {
    let meta = run_cargo_metadata();
    let resolve = &meta["resolve"];
    let root = resolve["root"].as_str().expect("resolve.root missing — is this run from a workspace member?");

    let mut pkg_name: HashMap<&str, &str> = HashMap::new();
    for p in meta["packages"].as_array().expect("packages") {
        pkg_name.insert(
            p["id"].as_str().expect("package id"),
            p["name"].as_str().expect("package name"),
        );
    }

    let mut edges: HashMap<&str, Vec<DepEdge>> = HashMap::new();
    for n in resolve["nodes"].as_array().expect("resolve.nodes") {
        let id = n["id"].as_str().expect("node id");
        let mut es = Vec::new();
        for d in n["deps"].as_array().expect("node deps") {
            es.push(DepEdge {
                to: d["pkg"].as_str().expect("dep pkg id"),
                linked: edge_is_linked(&d["dep_kinds"]),
            });
        }
        edges.insert(id, es);
    }

    let found = reachable_getrandom_ids(root, &edges, &pkg_name);
    if let Err(msg) = assert_single_vendored(&found, "vendor/getrandom") {
        panic!(
            "{msg}\n\ngetrandom 0.3.x/0.4.x are expected to sit in Cargo.lock via dev-only \
             paths (jobserver/tempfile/rand_core 0.9) — they must NOT be reachable through a \
             normal/build edge from the app root. If this trips after a dependency bump, a \
             new normal dependency now pulls a getrandom the TRNG patch does not cover."
        );
    }
}

#[test]
fn mutation_extra_reachable_getrandom_is_caught() {
    // Simulates a dependency bump introducing e.g. a rand-0.9 consumer
    // reached through a normal edge — a second, unpatched getrandom.
    let mut edges: HashMap<&str, Vec<DepEdge>> = HashMap::new();
    edges.insert(
        "root",
        vec![
            DepEdge { to: "path+file:///repo/vendor/getrandom#0.2.10", linked: true },
            DepEdge { to: "bumped-dep#1.0", linked: true },
        ],
    );
    edges.insert("bumped-dep#1.0", vec![DepEdge { to: "registry#getrandom@0.3.4", linked: true }]);
    let mut pkg_name: HashMap<&str, &str> = HashMap::new();
    pkg_name.insert("path+file:///repo/vendor/getrandom#0.2.10", "getrandom");
    pkg_name.insert("bumped-dep#1.0", "bumped-dep");
    pkg_name.insert("registry#getrandom@0.3.4", "getrandom");

    let found = reachable_getrandom_ids("root", &edges, &pkg_name);
    assert_eq!(found.len(), 2, "sanity: both getrandoms must be reachable in this mutated graph");
    assert!(
        assert_single_vendored(&found, "vendor/getrandom").is_err(),
        "a second reachable getrandom (simulating a dependency bump bypassing the patch) MUST be caught"
    );
}

#[test]
fn mutation_dev_only_edge_is_correctly_excluded() {
    // The known-benign case this contract exists to distinguish from the
    // mutation above: today's real graph has getrandom 0.3.x/0.4.x
    // reachable ONLY via dev-kind edges (jobserver/tempfile/rand_core
    // 0.9). Those must NOT count, or this test would be permanently red
    // against a correct repo.
    let mut edges: HashMap<&str, Vec<DepEdge>> = HashMap::new();
    edges.insert(
        "root",
        vec![
            DepEdge { to: "path+file:///repo/vendor/getrandom#0.2.10", linked: true },
            DepEdge { to: "dev-only-dep#1.0", linked: false }, // dev-kind edge: not linked
        ],
    );
    edges.insert("dev-only-dep#1.0", vec![DepEdge { to: "registry#getrandom@0.3.4", linked: true }]);
    let mut pkg_name: HashMap<&str, &str> = HashMap::new();
    pkg_name.insert("path+file:///repo/vendor/getrandom#0.2.10", "getrandom");
    pkg_name.insert("dev-only-dep#1.0", "dev-only-dep");
    pkg_name.insert("registry#getrandom@0.3.4", "getrandom");

    let found = reachable_getrandom_ids("root", &edges, &pkg_name);
    assert_eq!(found.len(), 1, "a dev-only-reachable getrandom must not be counted");
    assert!(assert_single_vendored(&found, "vendor/getrandom").is_ok());
}

#[test]
fn mutation_patch_not_applied_is_caught() {
    // Simulates the [patch.crates-io] silently failing to apply: the ONLY
    // reachable getrandom is a plain registry copy, not vendor/getrandom.
    let mut edges: HashMap<&str, Vec<DepEdge>> = HashMap::new();
    edges.insert("root", vec![DepEdge { to: "registry#getrandom@0.2.10", linked: true }]);
    let mut pkg_name: HashMap<&str, &str> = HashMap::new();
    pkg_name.insert("registry#getrandom@0.2.10", "getrandom");

    let found = reachable_getrandom_ids("root", &edges, &pkg_name);
    assert_eq!(found.len(), 1);
    assert!(
        assert_single_vendored(&found, "vendor/getrandom").is_err(),
        "a reachable getrandom that isn't the vendored copy must be caught even when it's the only one"
    );
}

#[test]
fn mutation_edge_is_linked_excludes_dev_kind() {
    // Direct unit check on the JSON-shape classifier used by the real
    // wrapper: a dep_kinds array containing only {"kind": "dev"} must not
    // be linked, but {"kind": null} (normal) and {"kind": "build"} must.
    let normal: serde_json::Value = serde_json::json!([{"kind": null, "target": null}]);
    let build: serde_json::Value = serde_json::json!([{"kind": "build", "target": null}]);
    let dev: serde_json::Value = serde_json::json!([{"kind": "dev", "target": null}]);
    assert!(edge_is_linked(&normal));
    assert!(edge_is_linked(&build));
    assert!(!edge_is_linked(&dev), "a dev-kind-only dep_kinds must not be treated as linked");
}
