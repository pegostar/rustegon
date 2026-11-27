// SPDX-License-Identifier: Apache-2.0
// Copyright The Rustegon Authors

//! `cargo xtask`: repository automation (repository-structure.md). Tooling only: it is never
//! shipped, so it uses `std::fs`/`std::process` directly instead of the `rustegon-sim-api`
//! traits of the production crates (PD-154).
//!
//! `cargo xtask dist [--target <t>]...` writes the unsigned R1 archives of FR-INS-003 (PD-147,
//! PD-154) to `dist/`:
//! `rustegon-<version>-<target>.{zip,tar.gz}` with `rustegond`, `rustegon`, `README.md` (quick
//! start), `LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES.txt` (generated, PD-155) and a commented
//! sample `rustegon.toml`, plus `dist/SHA256SUMS` over every archive of that version.
//!
//! `--packages` also builds the unsigned installers of FR-INS-001/002 (PD-200…PD-202):
//! `rustegon-<version>-windows-x86_64.msi` (`WiX` 5, Windows host only),
//! `rustegon-<version>-<amd64|arm64>.deb` and `rustegon-<version>-<x86_64|aarch64>.rpm` (nfpm in
//! a container), all covered by `SHA256SUMS`. `--site` then copies every file of that version
//! into `site/downloads/` and writes `site/downloads/manifest.js` (PD-204).

// Tooling runs on the real clock and file system (see above).
#![allow(clippy::disallowed_methods)]

mod licenses;

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::SystemTime,
};

use clap::{Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};

/// Errors of a tooling command: a message for the operator, nothing to recover.
type Result<T> = std::result::Result<T, String>;

#[derive(Parser)]
#[command(name = "cargo xtask", about = "Rustegon repository automation")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the release archives and `dist/SHA256SUMS` (FR-INS-003, PD-154).
    Dist {
        /// Archives to build (repeatable; default `all`). `host` = the platform running xtask.
        #[arg(long = "target", value_enum)]
        targets: Vec<TargetArg>,
        /// Also build the MSI (Windows target) and DEB + RPM (Linux targets) (FR-INS-001/002).
        #[arg(long)]
        packages: bool,
        /// Copy every file of this version into `site/downloads/` with `manifest.js` (PD-204).
        #[arg(long)]
        site: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TargetArg {
    Host,
    #[value(name = "windows-x86_64")]
    WindowsX86_64,
    #[value(name = "linux-x86_64")]
    LinuxX86_64,
    #[value(name = "linux-aarch64")]
    LinuxAarch64,
    All,
}

/// One archive target.
#[derive(Debug, PartialEq, Eq)]
struct Spec {
    /// Archive suffix (`rustegon-<version>-<name>`).
    name: &'static str,
    /// Rust target triple (dependency graph of the license file).
    triple: &'static str,
    /// Executable suffix.
    exe: &'static str,
    /// `docker --platform` of the `rust:1-bookworm` build when not built on the host.
    docker: Option<&'static str>,
    /// DEB architecture (`rustegon-<version>-<deb>.deb`, also nfpm's `arch`); empty: no DEB/RPM.
    deb: &'static str,
    /// RPM architecture (`rustegon-<version>-<rpm>.rpm`).
    rpm: &'static str,
}

const WINDOWS_X86_64: Spec = Spec {
    name: "windows-x86_64",
    triple: "x86_64-pc-windows-msvc",
    exe: ".exe",
    docker: None,
    deb: "",
    rpm: "",
};
const LINUX_X86_64: Spec = Spec {
    name: "linux-x86_64",
    triple: "x86_64-unknown-linux-gnu",
    exe: "",
    docker: Some("linux/amd64"),
    deb: "amd64",
    rpm: "x86_64",
};
const LINUX_AARCH64: Spec = Spec {
    name: "linux-aarch64",
    triple: "aarch64-unknown-linux-gnu",
    exe: "",
    docker: Some("linux/arm64"),
    deb: "arm64",
    rpm: "aarch64",
};

fn host_spec() -> Option<&'static Spec> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some(&WINDOWS_X86_64),
        ("linux", "x86_64") => Some(&LINUX_X86_64),
        ("linux", "aarch64") => Some(&LINUX_AARCH64),
        _ => None,
    }
}

fn selected(args: &[TargetArg]) -> Result<Vec<&'static Spec>> {
    let host = host_spec();
    let mut out: Vec<&'static Spec> = Vec::new();
    let all = args.is_empty() || args.contains(&TargetArg::All);
    let wanted: Vec<TargetArg> = if all {
        vec![
            TargetArg::WindowsX86_64,
            TargetArg::LinuxX86_64,
            TargetArg::LinuxAarch64,
        ]
    } else {
        args.to_vec()
    };
    for arg in wanted {
        let spec = match arg {
            TargetArg::Host => host.ok_or("this host has no archive target")?,
            TargetArg::WindowsX86_64 => &WINDOWS_X86_64,
            TargetArg::LinuxX86_64 => &LINUX_X86_64,
            TargetArg::LinuxAarch64 => &LINUX_AARCH64,
            TargetArg::All => continue,
        };
        // Windows binaries are built natively only (no MSVC toolchain in a container).
        if spec.docker.is_none() && host != Some(spec) {
            if all {
                eprintln!(
                    "dist: skipping {} (built on a Windows host only)",
                    spec.name
                );
                continue;
            }
            return Err(format!("{} can only be built on a Windows host", spec.name));
        }
        if !out.contains(&spec) {
            out.push(spec);
        }
    }
    Ok(out)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Cmd::Dist {
            targets,
            packages,
            site,
        } => dist(&targets, packages, site),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}

fn io_err(what: impl std::fmt::Display) -> impl FnOnce(io::Error) -> String {
    move |e| format!("{what}: {e}")
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().map_err(io_err(format!("{cmd:?}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed ({status})"))
    }
}

fn capture(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().map_err(io_err(format!("{cmd:?}")))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("{cmd:?}: output is not UTF-8: {e}"))
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    Ok(capture(Command::new("git").current_dir(root).args(args))?
        .trim()
        .to_string())
}

/// The dev version of PD-147: `<workspace semver>-dev.<commits>+g<sha>[.dirty]`, commits counted
/// since the last `v*` tag or else since the root commit (PD-154).
fn dev_version(semver: &str, commits: u64, sha: &str, dirty: bool) -> String {
    let dirty = if dirty { ".dirty" } else { "" };
    format!("{semver}-dev.{commits}+g{sha}{dirty}")
}

fn version_of(root: &Path) -> Result<String> {
    // `git describe --long` prints `<tag>-<n>-g<sha>`; without a release tag count from the root.
    let commits = match git(
        root,
        &["describe", "--tags", "--long", "--match", "v[0-9]*"],
    ) {
        Ok(d) => d
            .rsplit('-')
            .nth(1)
            .and_then(|n| n.parse().ok())
            .ok_or(format!("unexpected `git describe` output {d:?}"))?,
        Err(_) => git(root, &["rev-list", "--count", "HEAD"])?
            .parse()
            .map_err(|e| format!("git rev-list --count: {e}"))?,
    };
    let sha = git(root, &["rev-parse", "--short", "HEAD"])?;
    let dirty = !git(root, &["status", "--porcelain"])?.is_empty();
    Ok(dev_version(env!("CARGO_PKG_VERSION"), commits, &sha, dirty))
}

/// Builds `gui/dist/` and makes the next `rustegond` build re-read it (PD-130).
fn build_gui(root: &Path) -> Result<()> {
    let gui = root.join("gui");
    // On Windows npm is `npm.cmd` or `npm.exe` depending on the installer: let cmd resolve it.
    let npm = |args: &[&str]| {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/C", "npm"]);
            c
        } else {
            Command::new("npm")
        };
        run(cmd.current_dir(&gui).args(args))
    };
    if !gui.join("node_modules").is_dir() {
        npm(&["ci", "--no-audit", "--no-fund"])?;
    }
    npm(&["run", "build"])?;
    if !gui.join("dist").join("index.html").is_file() {
        return Err("gui/dist/index.html missing after `npm run build`".into());
    }
    // cargo does not track files added to gui/dist/: bump the embedding module's mtime.
    let embed = root.join("bins/rustegond/src/gui.rs");
    fs::File::options()
        .append(true)
        .open(&embed)
        .and_then(|f| f.set_modified(SystemTime::now()))
        .map_err(io_err(embed.display()))
}

/// The environment of the builds and of `--print-config`, without an operator's RUSTEGON_*
/// settings (they would leak into the sample configuration).
fn clean_command(program: impl Into<OsString>) -> Command {
    let mut cmd = Command::new(program.into());
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_uppercase()
            .starts_with("RUSTEGON_")
        {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// Builds the two binaries for `spec`; returns the directory holding them and the
/// `rustegond --print-config` output of that build.
fn build_binaries(root: &Path, spec: &Spec, version: &str) -> Result<(PathBuf, String)> {
    let Some(platform) = spec.docker.filter(|_| host_spec() != Some(spec)) else {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        run(clean_command(cargo)
            .current_dir(root)
            .env("RUSTEGON_BUILD_VERSION", version)
            .args([
                "build",
                "--locked",
                "--release",
                "-p",
                "rustegond",
                "-p",
                "rustegon-cli",
            ]))?;
        let bin = root.join("target").join("release");
        let effective = capture(
            clean_command(bin.join(format!("rustegond{}", spec.exe))).arg("--print-config"),
        )?;
        return Ok((bin, effective));
    };
    // As scripts/ci-local.sh: the tree read-only in rust:1-bookworm, the toolchain of
    // rust-toolchain.toml; target and registry in named volumes so a rebuild is incremental.
    let out = root.join("dist").join("build").join(spec.name);
    fs::create_dir_all(&out).map_err(io_err(out.display()))?;
    let arch = platform.trim_start_matches("linux/");
    let mount =
        |src: &Path, dst: &str, ro: &str| format!("type=bind,src={},dst={dst}{ro}", src.display());
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--platform", platform])
        .args(["--mount", &mount(root, "/src", ",readonly")])
        .args(["--mount", &mount(&out, "/out", "")])
        .args(["-v", &format!("rustegon-dist-target-{arch}:/tmp/target")])
        .args([
            "-v",
            "rustegon-dist-cargo-registry:/usr/local/cargo/registry",
        ])
        .args(["-e", "CARGO_TARGET_DIR=/tmp/target"])
        .args(["-e", &format!("RUSTEGON_BUILD_VERSION={version}")]);
    if let Some(jobs) = std::env::var_os("CARGO_BUILD_JOBS") {
        cmd.args([
            "-e",
            &format!("CARGO_BUILD_JOBS={}", jobs.to_string_lossy()),
        ]);
    }
    run(cmd
        .args([
            "-w",
            "/src",
            "rust:1-bookworm",
            "bash",
            "-euo",
            "pipefail",
            "-c",
        ])
        .arg(
            "rustup toolchain install >/dev/null 2>&1
         cargo build --locked --release -p rustegond -p rustegon-cli
         cp /tmp/target/release/rustegond /tmp/target/release/rustegon /out/
         /out/rustegond --print-config > /out/print-config.toml",
        ))?;
    let effective = fs::read_to_string(out.join("print-config.toml"))
        .map_err(io_err(out.join("print-config.toml").display()))?;
    Ok((out, effective))
}

/// The sample `rustegon.toml`: every default of `rustegond --print-config` (secrets redacted
/// there), commented out (PD-155).
fn sample_config(effective: &str) -> String {
    let mut text = String::from(
        "# Sample rustegond configuration: every setting at its default, as printed by\n\
         # `rustegond --print-config` (generated by `cargo xtask dist`). A node uses the file\n\
         # that `rustegon init` writes into its data directory; copy settings from here into it.\n\
         # Never put secrets in a configuration file: use the `*_file` settings.\n\n",
    );
    for line in effective.lines() {
        if !line.is_empty() {
            text.push_str("# ");
            text.push_str(line);
        }
        text.push('\n');
    }
    text
}

/// One file of an archive.
struct Entry {
    name: String,
    data: Vec<u8>,
    mode: u32,
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(io_err(path.display()))
}

fn write_tar_gz(path: &Path, top: &str, entries: &[Entry]) -> Result<()> {
    let file = fs::File::create(path).map_err(io_err(path.display()))?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::best());
    let mut tar = tar::Builder::new(gz);
    let mtime = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    for e in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(e.data.len() as u64);
        // Explicit modes: files staged on Windows carry no executable bit.
        header.set_mode(e.mode);
        header.set_mtime(mtime);
        tar.append_data(&mut header, format!("{top}/{}", e.name), e.data.as_slice())
            .map_err(io_err(path.display()))?;
    }
    tar.into_inner()
        .and_then(flate2::write::GzEncoder::finish)
        .and_then(|mut f| f.flush())
        .map_err(io_err(path.display()))
}

fn write_zip(path: &Path, top: &str, entries: &[Entry]) -> Result<()> {
    let file = fs::File::create(path).map_err(io_err(path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    for e in entries {
        // Windows has no executable bit: the zip is only written for the Windows target.
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(format!("{top}/{}", e.name), options)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        zip.write_all(&e.data).map_err(io_err(path.display()))?;
    }
    zip.finish()
        .map(drop)
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// `sha256sum` format (`<hex>  <file>`) over `files`, sorted by name.
fn sha256sums(files: &[(String, Vec<u8>)]) -> String {
    let mut sorted: Vec<&(String, Vec<u8>)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted.iter().fold(String::new(), |mut out, (name, data)| {
        let _ = writeln!(out, "{}  {name}", sha256_hex(data));
        out
    })
}

fn build_archive(root: &Path, spec: &Spec, version: &str, packages: bool) -> Result<PathBuf> {
    eprintln!("dist: building {}", spec.name);
    let (bin, effective) = build_binaries(root, spec, version)?;
    let top = format!("rustegon-{version}-{}", spec.name);
    let mut entries = Vec::new();
    for name in ["rustegond", "rustegon"] {
        let file = format!("{name}{}", spec.exe);
        entries.push(Entry {
            data: read(&bin.join(&file))?,
            name: file,
            mode: 0o755,
        });
    }
    let text = |name: &str, data: Vec<u8>| Entry {
        name: name.into(),
        data,
        mode: 0o644,
    };
    entries.push(text(
        "README.md",
        read(&root.join("packaging/archive/README.md"))?,
    ));
    entries.push(text("LICENSE", read(&root.join("LICENSE"))?));
    entries.push(text("NOTICE", read(&root.join("NOTICE"))?));
    entries.push(text(
        "THIRD-PARTY-LICENSES.txt",
        licenses::third_party_file(root, spec.triple)?.into_bytes(),
    ));
    entries.push(text(
        "rustegon.toml",
        sample_config(&effective).into_bytes(),
    ));
    let dist = root.join("dist");
    let archive = if spec.exe.is_empty() {
        let path = dist.join(format!("{top}.tar.gz"));
        write_tar_gz(&path, &top, &entries)?;
        path
    } else {
        let path = dist.join(format!("{top}.zip"));
        write_zip(&path, &top, &entries)?;
        path
    };
    eprintln!("dist: wrote {}", archive.display());
    if packages {
        build_packages(root, spec, version, &entries)?;
    }
    Ok(archive)
}

/// The dev version ordered for DEB and RPM (PD-202): `-` starts a DEB revision and is not
/// allowed in an RPM version, while `~` sorts before the release in both
/// (`0.1.0~dev.412+g77e4fe9` < `0.1.0`).
fn package_version(version: &str) -> String {
    version.replacen('-', "~", 1)
}

/// The numeric MSI `ProductVersion` of a dev version (PD-202): `major.minor.patch.commits`
/// (`0.1.0-dev.412+g77e4fe9` -> `0.1.0.412`; a release `x.y.z` -> `x.y.z.0`). MSI limits the
/// fields to 255.255.65535.65535 and compares only the first three on upgrades.
fn msi_version(version: &str) -> Result<String> {
    let (semver, pre) = version.split_once('-').unwrap_or((version, ""));
    let fits = |s: &str, max: u32| s.parse::<u32>().is_ok_and(|n| n <= max);
    let commits = match pre.strip_prefix("dev.") {
        Some(rest) => rest.split(['+', '.']).next().unwrap_or_default(),
        None if pre.is_empty() => "0",
        None => return Err(format!("version {version:?}: no MSI mapping for {pre:?}")),
    };
    match semver.split('.').collect::<Vec<_>>().as_slice() {
        [a, b, c] if fits(a, 255) && fits(b, 255) && fits(c, 65535) && fits(commits, 65535) => {
            Ok(format!("{a}.{b}.{c}.{commits}"))
        }
        _ => Err(format!(
            "version {version:?} does not fit the MSI limits 255.255.65535.65535"
        )),
    }
}

/// Writes the archive entries (binaries and generated texts) into a fresh
/// `dist/build/<name>/pkg` for the package tools.
fn stage(root: &Path, spec: &Spec, entries: &[Entry]) -> Result<PathBuf> {
    let dir = root.join("dist").join("build").join(spec.name).join("pkg");
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(io_err(dir.display()))?;
    }
    fs::create_dir_all(&dir).map_err(io_err(dir.display()))?;
    for e in entries {
        let path = dir.join(&e.name);
        fs::write(&path, &e.data).map_err(io_err(path.display()))?;
    }
    Ok(dir)
}

fn build_packages(root: &Path, spec: &Spec, version: &str, entries: &[Entry]) -> Result<()> {
    let dir = stage(root, spec, entries)?;
    if spec.deb.is_empty() {
        return build_msi(root, &dir, version);
    }
    // nfpm in a pinned container (PD-201): the tree and the stage (`/stage`, the fixed path of
    // nfpm.yaml: nfpm does not expand variables in `src`) read-only, `dist/` writable.
    let dist = root.join("dist");
    let image_file = root.join("packaging/linux/nfpm-image.txt");
    let image = fs::read_to_string(&image_file).map_err(io_err(image_file.display()))?;
    let mount =
        |src: &Path, dst: &str, ro: &str| format!("type=bind,src={},dst={dst}{ro}", src.display());
    for (packager, arch) in [("deb", spec.deb), ("rpm", spec.rpm)] {
        let file = format!("rustegon-{version}-{arch}.{packager}");
        run(Command::new("docker")
            .args(["run", "--rm"])
            .args(["--mount", &mount(root, "/src", ",readonly")])
            .args(["--mount", &mount(&dir, "/stage", ",readonly")])
            .args(["--mount", &mount(&dist, "/dist", "")])
            .args(["-e", &format!("VERSION={}", package_version(version))])
            .args(["-e", &format!("ARCH={}", spec.deb)])
            .args(["-w", "/src", image.trim()])
            .args(["package", "--config", "packaging/linux/nfpm.yaml"])
            .args(["--packager", packager, "--target", &format!("/dist/{file}")]))?;
        eprintln!("dist: wrote {}", dist.join(file).display());
    }
    Ok(())
}

/// The `WiX` extensions, same version as the pinned tool: UI (license and exit dialogs) and
/// Util (service failure actions).
const WIX_EXTENSIONS: [&str; 2] = ["WixToolset.UI.wixext/5.0.2", "WixToolset.Util.wixext/5.0.2"];

/// The license text as the RTF the `WixUI` license dialog shows: monospaced, one paragraph per
/// line, RTF control characters escaped, non-ASCII as `\uN?`.
fn license_rtf(text: &str) -> String {
    let mut rtf = String::from(r"{\rtf1\ansi\deff0{\fonttbl{\f0\fmodern Consolas;}}\f0\fs16");
    rtf.push('\n');
    for line in text.lines() {
        for c in line.chars() {
            match c {
                '\\' | '{' | '}' => {
                    rtf.push('\\');
                    rtf.push(c);
                }
                c if c.is_ascii() => rtf.push(c),
                c => {
                    // `\uN` takes a signed 16-bit value; characters beyond the BMP become `?`.
                    let n = u16::try_from(u32::from(c)).map_or(-1, |u| i32::from(u.cast_signed()));
                    if n == -1 {
                        rtf.push('?');
                    } else {
                        let _ = write!(rtf, r"\u{n}?");
                    }
                }
            }
        }
        rtf.push_str("\\par\n");
    }
    rtf.push('}');
    rtf
}

/// The MSI, with the `WiX` tool pinned in `packaging/windows/dotnet-tools.json` (PD-200), the
/// extensions ([`WIX_EXTENSIONS`]) and the license as RTF.
fn build_msi(root: &Path, stage: &Path, version: &str) -> Result<()> {
    let wix_dir = root.join("packaging").join("windows");
    let readme = wix_dir.join("README.md");
    fs::copy(&readme, stage.join("README.md")).map_err(io_err(readme.display()))?;
    let license = String::from_utf8(read(&root.join("LICENSE"))?)
        .map_err(|e| format!("LICENSE is not UTF-8: {e}"))?;
    let rtf = stage.join("License.rtf");
    fs::write(&rtf, license_rtf(&license)).map_err(io_err(rtf.display()))?;
    let dotnet = || {
        let mut cmd = Command::new("dotnet");
        cmd.current_dir(&wix_dir);
        cmd
    };
    run(dotnet().args(["tool", "restore"]))?;
    // Into packaging/windows/.wix (git-ignored); a no-op once present.
    let mut extensions = Vec::new();
    for ext in WIX_EXTENSIONS {
        run(dotnet().args(["tool", "run", "wix", "--", "extension", "add", ext]))?;
        extensions.extend(["-ext", ext.split('/').next().unwrap_or(ext)]);
    }
    // Built inside the stage so that the `.wixpdb` written next to it stays out of `dist/`.
    let built = stage.join("rustegon.msi");
    run(dotnet()
        .args([
            "tool", "run", "wix", "--", "build", "-nologo", "-arch", "x64",
        ])
        .args(&extensions)
        .args(["-d", &format!("Version={version}")])
        .args(["-d", &format!("MsiVersion={}", msi_version(version)?)])
        .arg("-d")
        .arg(format!("StageDir={}", stage.display()))
        .arg("-o")
        .arg(&built)
        .arg("rustegon.wxs"))?;
    let out = root
        .join("dist")
        .join(format!("rustegon-{version}-windows-x86_64.msi"));
    fs::copy(&built, &out).map_err(io_err(out.display()))?;
    eprintln!("dist: wrote {}", out.display());
    Ok(())
}

/// Every release file of `version` in `dist/` (archives and packages; the build output is in
/// `dist/build/`), with its content, sorted by name.
fn version_files(dist: &Path, version: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let prefix = format!("rustegon-{version}-");
    let mut files = Vec::new();
    for entry in fs::read_dir(dist).map_err(io_err(dist.display()))? {
        let entry = entry.map_err(io_err(dist.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && entry.path().is_file() {
            files.push((name, read(&entry.path())?));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

/// `(os, arch, kind)` of a release file for the site manifest (PD-204), from the part of its
/// name after `rustegon-<version>-`; `None` for anything else.
fn classify(suffix: &str) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match suffix {
        "windows-x86_64.zip" => ("windows", "x86_64", "zip"),
        "windows-x86_64.msi" => ("windows", "x86_64", "msi"),
        "linux-x86_64.tar.gz" => ("linux", "x86_64", "tar.gz"),
        "linux-aarch64.tar.gz" => ("linux", "aarch64", "tar.gz"),
        "amd64.deb" => ("ubuntu", "x86_64", "deb"),
        "arm64.deb" => ("ubuntu", "aarch64", "deb"),
        "x86_64.rpm" => ("fedora", "x86_64", "rpm"),
        "aarch64.rpm" => ("fedora", "aarch64", "rpm"),
        _ => return None,
    })
}

/// The release files of `version` that the site lists (a known `classify` suffix).
fn site_files(files: Vec<(String, Vec<u8>)>, version: &str) -> Vec<(String, Vec<u8>)> {
    let prefix = format!("rustegon-{version}-");
    files
        .into_iter()
        .filter(|(name, _)| name.strip_prefix(&prefix).and_then(classify).is_some())
        .collect()
}

/// `site/downloads/manifest.js` over `files` (already filtered by `site_files`): a script
/// assignment, not JSON, so that the site also works from `file://` (PD-204).
fn site_manifest(version: &str, date: &str, files: &[(String, Vec<u8>)]) -> Result<String> {
    let prefix = format!("rustegon-{version}-");
    let entries: Vec<serde_json::Value> = files
        .iter()
        .filter_map(|(name, data)| {
            let (os, arch, kind) = classify(name.strip_prefix(&prefix)?)?;
            Some(serde_json::json!({
                "os": os, "arch": arch, "kind": kind, "file": name,
                "bytes": data.len(), "sha256": sha256_hex(data),
            }))
        })
        .collect();
    let manifest = serde_json::json!({
        "version": version, "date": date, "signed": false,
        "files": entries, "sha256sums": "SHA256SUMS",
    });
    let text = serde_json::to_string_pretty(&manifest).map_err(|e| format!("manifest: {e}"))?;
    Ok(format!(
        "// Generated by `cargo xtask dist --site` (PD-204); do not edit.\n\
         window.RUSTEGON_DOWNLOADS = {text};\n"
    ))
}

/// Replaces the content of `site/downloads/` (except its committed files) with the release
/// files of `version`, their `SHA256SUMS` and `manifest.js`.
fn publish_site(root: &Path, version: &str) -> Result<()> {
    const KEEP: [&str; 2] = ["README.md", "manifest.example.js"];
    let out = root.join("site").join("downloads");
    fs::create_dir_all(&out).map_err(io_err(out.display()))?;
    for entry in fs::read_dir(&out).map_err(io_err(out.display()))? {
        let entry = entry.map_err(io_err(out.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().is_file() && !KEEP.contains(&name.as_str()) {
            fs::remove_file(entry.path()).map_err(io_err(entry.path().display()))?;
        }
    }
    let files = site_files(version_files(&root.join("dist"), version)?, version);
    for (name, data) in &files {
        let path = out.join(name);
        fs::write(&path, data).map_err(io_err(path.display()))?;
    }
    let sums = out.join("SHA256SUMS");
    fs::write(&sums, sha256sums(&files)).map_err(io_err(sums.display()))?;
    let date = git(root, &["log", "-1", "--format=%cs"])?;
    let manifest = out.join("manifest.js");
    fs::write(&manifest, site_manifest(version, &date, &files)?)
        .map_err(io_err(manifest.display()))?;
    eprintln!(
        "dist: {} files of {version} in {}",
        files.len(),
        out.display()
    );
    Ok(())
}

fn dist(targets: &[TargetArg], packages: bool, site: bool) -> Result<()> {
    let root = workspace_root();
    let specs = selected(targets)?;
    let version = version_of(&root)?;
    eprintln!("dist: version {version}");
    build_gui(&root)?;
    let dist = root.join("dist");
    fs::create_dir_all(&dist).map_err(io_err(dist.display()))?;
    for spec in specs {
        build_archive(&root, spec, &version, packages)?;
    }
    // Every file of this version, also those of an earlier run.
    let sums = sha256sums(&version_files(&dist, &version)?);
    let path = dist.join("SHA256SUMS");
    fs::write(&path, &sums).map_err(io_err(path.display()))?;
    eprint!("dist: {}:\n{sums}", path.display());
    if site {
        publish_site(&root, &version)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    /// TC-INS-015: the MSI license dialog's RTF escapes RTF control characters and keeps one
    /// paragraph per line.
    #[test]
    fn tc_ins_015_license_rtf_escapes_and_keeps_lines() {
        let rtf = license_rtf("a {b} \\ c\nsecond é\n");
        assert!(rtf.starts_with(r"{\rtf1"), "{rtf}");
        assert!(rtf.contains(r"a \{b\} \\ c\par"), "{rtf}");
        assert!(rtf.contains(r"second \u233?\par"), "{rtf}");
        assert!(rtf.ends_with('}'));
        let real = license_rtf(
            &String::from_utf8(read(&workspace_root().join("LICENSE")).unwrap()).unwrap(),
        );
        assert!(real.contains("Apache License"));
    }

    #[test]
    fn fr_ins_003_dev_version_format() {
        assert_eq!(
            dev_version("0.1.0", 412, "77e4fe9", false),
            "0.1.0-dev.412+g77e4fe9"
        );
        assert_eq!(
            dev_version("0.1.0", 3, "abc1234", true),
            "0.1.0-dev.3+gabc1234.dirty"
        );
    }

    #[test]
    fn fr_ins_003_sample_config_is_fully_commented() {
        let sample = sample_config("[node]\ndata_dir = \"x\"\n\n[log]\nlevel = \"info\"\n");
        assert!(sample.lines().all(|l| l.is_empty() || l.starts_with('#')));
        assert!(sample.contains("# [node]\n# data_dir = \"x\"\n\n# [log]"));
    }

    #[test]
    fn fr_ins_003_sha256sums_format_and_order() {
        let sums = sha256sums(&[
            ("b.zip".into(), b"abc".to_vec()),
            ("a.tar.gz".into(), vec![]),
        ]);
        assert_eq!(
            sums,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  a.tar.gz\n\
             ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  b.zip\n"
        );
    }

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                name: "rustegond".into(),
                data: b"\x7fELF".to_vec(),
                mode: 0o755,
            },
            Entry {
                name: "README.md".into(),
                data: b"# hi\n".to_vec(),
                mode: 0o644,
            },
        ]
    }

    #[test]
    fn fr_ins_003_tar_gz_keeps_top_dir_and_executable_modes() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("a.tar.gz");
        write_tar_gz(&path, "rustegon-x", &entries())?;
        let file = fs::File::open(&path).map_err(|e| e.to_string())?;
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
        let mut seen = Vec::new();
        for entry in archive.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .path()
                .map_err(|e| e.to_string())?
                .display()
                .to_string();
            let mode = entry.header().mode().map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
            seen.push((name, mode, data));
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0],
            ("rustegon-x/rustegond".into(), 0o755, b"\x7fELF".to_vec())
        );
        assert_eq!(seen[1].0, "rustegon-x/README.md");
        assert_eq!(seen[1].1, 0o644);
        Ok(())
    }

    #[test]
    fn fr_ins_003_zip_keeps_top_dir_and_content() -> Result<()> {
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = dir.path().join("a.zip");
        write_zip(&path, "rustegon-x", &entries())?;
        let file = fs::File::open(&path).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        let mut readme = String::new();
        zip.by_name("rustegon-x/README.md")
            .map_err(|e| e.to_string())?
            .read_to_string(&mut readme)
            .map_err(|e| e.to_string())?;
        assert_eq!(readme, "# hi\n");
        assert_eq!(zip.len(), 2);
        Ok(())
    }

    #[test]
    fn fr_ins_002_package_version_orders_dev_builds_before_the_release() {
        assert_eq!(
            package_version("0.1.0-dev.412+g77e4fe9.dirty"),
            "0.1.0~dev.412+g77e4fe9.dirty"
        );
        assert_eq!(package_version("1.0.0"), "1.0.0");
    }

    #[test]
    fn fr_ins_001_msi_version_is_numeric_and_bounded() {
        assert_eq!(
            msi_version("0.1.0-dev.412+g77e4fe9").as_deref(),
            Ok("0.1.0.412")
        );
        assert_eq!(
            msi_version("0.1.0-dev.3+gabc1234.dirty").as_deref(),
            Ok("0.1.0.3")
        );
        assert_eq!(msi_version("1.2.3").as_deref(), Ok("1.2.3.0"));
        assert!(msi_version("256.0.0").is_err());
        assert!(msi_version("0.1.0-dev.65536+gabc").is_err());
        assert!(msi_version("0.1.0-rc.1").is_err());
        assert!(msi_version("0.1-dev.1+gabc").is_err());
    }

    #[test]
    fn tc_ins_012_site_manifest_lists_known_files_with_size_and_hash() -> Result<()> {
        let v = "0.1.0-dev.5+gabc1234";
        let files = site_files(
            vec![
                (format!("rustegon-{v}-amd64.deb"), b"deb".to_vec()),
                (format!("rustegon-{v}-linux-aarch64.tar.gz"), b"t".to_vec()),
                (format!("rustegon-{v}-windows-x86_64.msi"), vec![]),
                (format!("rustegon-{v}-unknown.bin"), b"x".to_vec()),
            ],
            v,
        );
        assert_eq!(files.len(), 3);
        let text = site_manifest(v, "2026-11-15", &files)?;
        let json = text
            .split_once("window.RUSTEGON_DOWNLOADS = ")
            .and_then(|(_, rest)| rest.trim_end().strip_suffix(';'))
            .ok_or("not a window.RUSTEGON_DOWNLOADS assignment")?;
        let m: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        assert_eq!(m["version"], v);
        assert_eq!(m["date"], "2026-11-15");
        assert_eq!(m["signed"], false);
        assert_eq!(m["sha256sums"], "SHA256SUMS");
        let deb = &m["files"][0];
        assert_eq!(
            (&deb["os"], &deb["arch"], &deb["kind"], &deb["bytes"]),
            (
                &serde_json::json!("ubuntu"),
                &serde_json::json!("x86_64"),
                &serde_json::json!("deb"),
                &serde_json::json!(3)
            )
        );
        assert_eq!(deb["file"], format!("rustegon-{v}-amd64.deb"));
        assert_eq!(deb["sha256"], sha256_hex(b"deb"));
        assert_eq!(m["files"][1]["os"], "linux");
        assert_eq!(m["files"][1]["arch"], "aarch64");
        assert_eq!(m["files"][2]["kind"], "msi");
        Ok(())
    }

    #[test]
    fn tc_ins_012_every_target_package_name_is_classified() {
        for spec in [&WINDOWS_X86_64, &LINUX_X86_64, &LINUX_AARCH64] {
            let archive = if spec.exe.is_empty() { "tar.gz" } else { "zip" };
            assert!(classify(&format!("{}.{archive}", spec.name)).is_some());
            if spec.deb.is_empty() {
                assert!(classify(&format!("{}.msi", spec.name)).is_some());
            } else {
                assert!(classify(&format!("{}.deb", spec.deb)).is_some());
                assert!(classify(&format!("{}.rpm", spec.rpm)).is_some());
            }
        }
    }

    #[test]
    fn fr_ins_003_windows_archive_only_on_a_windows_host() {
        let only_windows = selected(&[TargetArg::WindowsX86_64]);
        assert_eq!(only_windows.is_ok(), cfg!(windows));
        let all = selected(&[]).unwrap_or_default();
        assert!(all.contains(&&LINUX_X86_64) && all.contains(&&LINUX_AARCH64));
        assert_eq!(all.contains(&&WINDOWS_X86_64), cfg!(windows));
    }
}
