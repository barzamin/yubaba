#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(parse(from_os_str))]
    dll: PathBuf,
}

fn main() {
}
