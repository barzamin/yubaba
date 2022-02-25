use std::env;
use std::path::PathBuf;
use std::process::Command;
use color_eyre::eyre::{ensure, Result, WrapErr, eyre};
use exe::PEImage;

fn main() -> Result<()> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let redsus_out_dir = out_dir.join("redsus");
    std::fs::create_dir_all(&redsus_out_dir)?;

    let out = Command::new("rustc")
        .arg("--crate-name").arg("redsus")
        .arg("--edition=2021")
        .arg("src\\redsus\\main.rs")
        .arg("--crate-type").arg("bin")
        .arg("--emit=dep-info,link")
        .arg("-C").arg("opt-level=z")
        .arg("-C").arg("panic=abort")
        .arg("-C").arg("lto")
        .arg("--out-dir").arg(&redsus_out_dir)
        .arg("--target").arg("i686-pc-windows-msvc")
        .arg("-C").arg("link-arg=/ENTRY:_shellcode")
        .arg("-C").arg("link-arg=/MERGE:.edata=.rdata")
        .arg("-C").arg("link-arg=/MERGE:.rustc=.data")
        .arg("-C").arg("link-arg=/MERGE:.rdata=.text")
        .arg("-C").arg("link-arg=/MERGE:.pdata=.text")
        .arg("-C").arg("link-arg=/DEBUG:NONE")
        .arg("-C").arg("link-arg=/EMITPOGOPHASEINFO")
        .arg("-C").arg("link-arg=/SUBSYSTEM:WINDOWS")
        .arg("-C").arg("target-feature=-mmx,-sse,+soft-float")
        .arg("--emit").arg("asm")
        .status()
        .context("running rustc")?;
    
    ensure!(
        out.success(),
        "cant run rustc: {:?}",
        out.code(),
    );

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/redsus/main.rs");
    println!("cargo:rerun-if-changed=src/redsus/win32.rs");

    let image = PEImage::from_disk_file(redsus_out_dir.join("redsus.exe"))?;
    let text_section = image.pe.get_section_by_name(".text".to_string()).map_err(|e|eyre!("{:?}",e))?;
    let data = text_section.read(&image.pe).map_err(|e|eyre!("{:?}",e))?;
    std::fs::write(redsus_out_dir.join("redsus.bin"), data)?;

    Ok(())
}