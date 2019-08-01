use ferris_says::say;
use std::io::{stdout, BufWriter};
use conf::Opt;
use structopt::StructOpt;

pub mod conf;

fn main() {
    let opt = Opt::from_args(); // from_config() option
    println!("{:?}", opt);

    // json-rpc interation with network?

    let stdout = stdout();
    let mut writer = BufWriter::new(stdout.lock());
    say(b"Hello fellow kids", 17, &mut writer).unwrap();
}


#[cfg(test)]
mod tests {
    #[test] fn test_sail() {  assert_eq!(1, 1) }
}
