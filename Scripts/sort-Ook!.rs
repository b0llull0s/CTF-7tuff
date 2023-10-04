use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [infile] [outfile]", args[0]);
        std::process::exit(1);
    }

    let input_file = &args[1];
    let output_file = &args[2];

    match fs::read_to_string(input_file) {
        Ok(contents) => {
            let modified_contents = contents
                .replace(".", "Ook. ")
                .replace("?", "Ook? ")
                .replace("!", "Ook! ");

            match fs::write(output_file, modified_contents) {
                Ok(_) => println!("Conversion successful. Output saved in {}", output_file),
                Err(e) => eprintln!("Error writing to {}: {}", output_file, e),
            }
        }
        Err(e) => eprintln!("Error reading from {}: {}", input_file, e),
    }
}