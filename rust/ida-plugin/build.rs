//! link to IDA's libraries: those of the IDA installation (`$IDADIR`, or else IDA's default
//! installation directory), or else the stub libraries of the IDA SDK.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (install_path, idalib_path, ida_path) = idalib_build::idalib_install_paths_with(false);
    if idalib_path.exists() && ida_path.exists() {
        idalib_build::configure_linkage()?;
    } else {
        idalib_build::configure_idasdk_linkage();
    }

    // for the tests, which run the plugin in this IDA.
    println!("cargo::rerun-if-env-changed=IDADIR");
    println!("cargo::rustc-env=IDADIR={}", install_path.display());
    Ok(())
}
