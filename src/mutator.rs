//!
//!Options for ``ecfuzz --mutate-stdin``
//!```text
//!Mutate input from stdin, and return the result to stdout
//!
//!Options:
//!
//!  -d, --dictionary-path <file>  Optionally supply a dictionary to enable random
//!                                dictionary value insertion, and tokenized
//!                                dictionary replacement
//!
//!  -s, --seed <seed>             Optionally seed the mutation
//!
//!Example:
//!
//!  echo 'Hello world!' | ecfuzz --mutate-stdin
//!  echo 'Hello world!' | ecfuzz --mutate-stdin --dictionary-path input/sample.dict --seed 000
//!```

use std::collections::btree_map::Entry::Vacant;
use std::collections::BTreeMap;
use std::fs::read;
use std::hash::Hasher;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use xxhash_rust::xxh3::Xxh3;

const MUTATIONS: f64 = 0.01;

const HELP: &str = r#"
Mutate input from stdin, and return the result to stdout

Options:

  -d, --dictionary-path <file>  Optionally supply a dictionary to enable random
                                dictionary value insertion, and tokenized
                                dictionary replacement

  -s, --seed <seed>             Optionally seed the mutation

Example:

  echo 'Hello world!' | ecfuzz --mutate-stdin
  echo 'Hello world!' | ecfuzz --mutate-stdin --dictionary-path input/sample.dict --seed 000

"#;

pub struct Mutation {
    pub data: Vec<u8>,
    pub dict: Option<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>,
    hasher: Xxh3,
    hash_seed: [u8; 4],
    mutators: Vec<for<'r> fn(&'r mut Mutation)>,
}

/// Magic values consist of a tuple with byte size and a bytestring.
/// Variants can be 1, 2, or 4 bytes length.
#[derive(Copy, Clone)]
enum Magic {
    A((u8, [u8; 1])),
    B((u8, [u8; 2])),
    C((u8, [u8; 4])),
}

/// find all indices of matching substring in a raw binary vector
fn byte_index(key: &Vec<u8>, bytes: &Vec<u8>) -> Vec<usize> {
    assert!(key.len() <= bytes.len());

    let mut indices: Vec<usize> = vec![];

    for i in 0..(bytes.len() - key.len()) + 1 {
        if &bytes[i..i + key.len()] == key {
            indices.push(i);
        }
    }
    indices
}

pub fn load_dictionary(dict_path: PathBuf) -> BTreeMap<Vec<u8>, Vec<Vec<u8>>> {
    let mut dict: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();

    let lines = read(&dict_path)
        .unwrap_or_else(|_| panic!("could not load dictionary from file! {:?}", dict_path))
        .split(|x| x == &b'\n')
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let key: Vec<u8>;
        let val: Vec<u8>;
        let keypair = line
            .splitn(2, |kv| kv == &b'=')
            .map(|kv| kv.to_vec())
            .collect::<Vec<Vec<u8>>>();

        if keypair.len() == 2 {
            key = keypair[0].to_owned();
            val = keypair[1].to_owned();
            #[cfg(debug_assertions)]
            println!(
                "token {:?} {:?}",
                String::from_utf8_lossy(&key),
                String::from_utf8_lossy(&val)
            );
        } else {
            key = b"".to_vec();
            val = keypair[0].to_owned();
        }

        if let Vacant(_e) = dict.entry(key.clone()) {
            dict.insert(key, vec![val]);
        } else {
            dict.get_mut(&key).unwrap().push(val);
        };
    }
    println!(
        "loaded dictionary: {}",
        dict_path.as_os_str().to_str().unwrap()
    );
    dict
}

impl Mutation {
    /// new mutation engine
    pub fn new(dict_path: Option<PathBuf>) -> Self {
        let mut mutators = [
            Mutation::mutate_magic,
            Mutation::mutate_bits,
            Mutation::mutate_bytes,
        ]
        .to_vec();

        let dict = dict_path.map(load_dictionary);

        if dict.is_some() {
            if dict.as_ref().unwrap().contains_key(&b"".to_vec()) {
                mutators.push(Mutation::mutate_dictionary);
            }

            let count = dict
                .as_ref()
                .unwrap()
                .keys()
                .filter(|k| !k.is_empty())
                .count();

            if count >= 2 || !dict.as_ref().unwrap().contains_key(&b"".to_vec()) {
                mutators.push(Mutation::mutate_dictionary_replacement);
            }
        }

        {
            Mutation {
                data: vec![],
                dict,
                hasher: Xxh3::with_seed(0),
                hash_seed: [0x0_u8, 0x0_u8, 0x0_u8, 0x0_u8],
                mutators,
            }
        }
    }

    pub fn with_seed(path: Option<PathBuf>, seed: Vec<u8>) -> Self {
        let mut m = Mutation::new(path);
        let _ = &m.hasher.write(&seed);
        m
    }

    /// Hash number generator
    pub fn hashfunc(&mut self) -> usize {
        self.hash_seed[3] += 0x1_u8;
        for idx in 0..self.hash_seed.len() - 1 {
            if self.hash_seed[idx + 1 % self.hash_seed.len()] == std::u8::MAX {
                self.hash_seed[idx + 1 % self.hash_seed.len()] = std::u8::MIN;
                self.hash_seed[idx] += 0x1_u8;
            }
        }
        self.hasher.write(&self.hash_seed);
        self.hasher.digest() as usize
        //self.hasher.finish() as usize
    }

    /// Magic values.
    /// Each tuple consists of a byte length, and a bytestring of matching length
    fn magic_char(&mut self) -> (usize, Vec<u8>) {
        let nums: Vec<Magic> = vec![
            Magic::A((1, *b"\xff")),
            Magic::A((1, *b"\x7f")),
            Magic::A((1, *b"\x00")),
            Magic::B((2, *b"\xff\xff")),
            Magic::B((2, *b"\x00\x00")),
            Magic::C((4, *b"\xff\xff\xff\xff")),
            Magic::C((4, *b"\x00\x00\x00\x00")),
            Magic::C((4, *b"\x00\x00\x00\x40")),
            Magic::C((4, *b"\x00\x00\x00\x80")),
            Magic::C((4, *b"\xff\xff\xff\x7f")),
        ];

        match nums[self.hashfunc() % nums.len()] {
            Magic::A(a) => (a.0 as usize, a.1.to_vec()),
            Magic::B(b) => (b.0 as usize, b.1.to_vec()),
            Magic::C(c) => (c.0 as usize, c.1.to_vec()),
        }
    }

    /// magic number mutation
    /// splices data with random magic value
    pub fn mutate_magic(&mut self) {
        let mut count = (self.data.len() as f64 * MUTATIONS) as usize;

        if count == 0 {
            count = 1;
        };

        #[cfg(debug_assertions)]
        assert!(count > 0);

        for _ in 0..count {
            let (mut n_size, n) = self.magic_char();
            if n_size > self.data.len() {
                n_size = self.data.len();
            }
            let mut sz = self.data.len() as usize - n_size as usize;
            if sz == 0 {
                sz = 1
            }
            #[cfg(debug_assertions)]
            assert!(sz > 0);
            let idx = self.hashfunc() % sz;
            self.data.splice(idx..idx + n_size, n);
        }
    }

    /// XOR mutation and bitshift
    pub fn mutate_bits(&mut self) {
        let mut count = (self.data.len() as f64 * 8.0 * MUTATIONS) as usize;

        if count == 0 {
            count = 1;
        };

        let maxidx = self.data.len();

        #[cfg(debug_assertions)]
        assert!(count > 0);
        #[cfg(debug_assertions)]
        assert!(maxidx > 0);

        for _ in 0..count {
            let bit = self.hashfunc() % (maxidx * 8);
            let idx_bit: usize = (bit % 8) as usize;
            let idx_byte: usize = (bit / 8) as usize;
            self.data[idx_byte] ^= 1 << idx_bit;
        }
    }

    /// replace randomly selected bytes with random data of equivalent length
    pub fn mutate_bytes(&mut self) {
        let mut count = (self.data.len() as f64 * MUTATIONS) as usize;

        if count == 0 {
            count = 1;
        };
        let maxidx = self.data.len() as usize;

        #[cfg(debug_assertions)]
        assert!(count > 0);
        #[cfg(debug_assertions)]
        assert!(maxidx > 0);

        let dataidx = self.hashfunc() % maxidx;
        for _ in 0..count {
            self.data[dataidx] = (self.hashfunc() % 256) as u8;
        }
    }

    /// random dictionary insertion
    pub fn mutate_dictionary(&mut self) {
        let hash = self.hashfunc();
        let validx = hash
            % self
                .dict
                .as_ref()
                .unwrap()
                .get(&b"".to_vec())
                .unwrap()
                .len();
        let val: Vec<u8> = self.dict.as_ref().unwrap().get(&b"".to_vec()).unwrap()[validx].to_vec();
        //let idx = self.hashfunc() % ((self.data.len() - val.len()) - 1);
        if self.data.len() > val.len() {
            let idx = self.hashfunc() % (self.data.len() - val.len());
            self.data.splice(idx..idx + val.len(), val);
        } else {
            self.data = val;
        }
    }

    /// tokenized dictionary replacement
    pub fn mutate_dictionary_replacement(&mut self) {
        let mut keys = self
            .dict
            .as_ref()
            .unwrap()
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect::<Vec<Vec<u8>>>();
        keys.sort();
        for key in keys {
            let keyidx = self.hashfunc() % self.dict.as_ref().unwrap().get(&key).unwrap().len();
            let val: Vec<u8> = self.dict.as_ref().unwrap().get(&key).unwrap()[keyidx].to_vec();
            let indices: Vec<usize> = byte_index(&key.to_vec(), &self.data.to_vec());
            if indices.is_empty() {
                continue;
            }
            let idx = indices[self.hashfunc() % indices.len()];
            self.data.splice(idx..(idx + key.len()), val);
            return;
        }
        panic!(
            "no matching tokens in corpus for {}",
            String::from_utf8_lossy(&self.data)
        );
    }

    /// applies a random mutator to input
    pub fn mutate(&mut self) {
        let hash: usize = self.hashfunc() % self.mutators.len();
        self.mutators[hash](self);
    }
}

/// mutate bytes from stdin
pub fn main() -> Result<(), std::io::Error> {
    let mut args: Vec<String> = vec![];
    for arg in std::env::args() {
        for a in arg.splitn(2, '=') {
            args.push(a.to_string());
        }
    }

    // print help msg
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("{}", HELP);
        std::process::exit(0);
    }

    // parse dictionary path
    let mut dictpath = None;
    if args.contains(&"-d".to_string()) || args.contains(&"--dictionary-path".to_string()) {
        let mut stop = false;
        for arg in &args {
            if arg == "-d" || arg == "--dictionary-path" {
                stop = true;
            } else if stop {
                dictpath = Some(PathBuf::from(arg));
                break;
            }
        }
    }

    // read input from stdin
    let stdin = io::stdin();
    let mut writer = BufWriter::new(io::stdout());
    let mut input: Vec<u8> = vec![];
    stdin.lock().read_to_end(&mut input)?;

    // parse seed value (or clone input from stdin)
    let mut seed: Vec<u8> = vec![];
    if args.contains(&"-s".to_string()) || args.contains(&"--seed".to_string()) {
        let mut stop = false;
        for arg in &args {
            if arg == "-s" || arg == "--seed" {
                stop = true
            } else if stop {
                seed = arg.as_bytes().to_vec();
                break;
            }
        }
    }

    let mut mutation = Mutation::with_seed(dictpath, seed);
    mutation.data = input;
    mutation.mutate();
    let _w = writer.write(&mutation.data).unwrap();
    writer.flush().unwrap();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Write;

    pub fn vec2string(data: Vec<u8>) -> String {
        String::from_utf8_lossy(&data).to_string()
    }

    #[test]
    fn test_mutations() {
        let test: Vec<u8> = b"The quick brown fox jumped over the lazy dog".to_vec();

        let mut mutation = Mutation::new(None);
        mutation.data = test;

        mutation.mutate_magic();
        let magicmutated = mutation.data.clone();
        mutation.mutate_bits();
        let bitmutated = mutation.data.clone();
        mutation.mutate_bytes();
        let randommutated = mutation.data.clone();
        mutation.mutate();
        let anymutated = mutation.data.clone();
        mutation.mutate();
        let anymutated1 = mutation.data.clone();
        mutation.mutate();
        let anymutated2 = mutation.data.clone();
        mutation.mutate();
        let anymutated3 = mutation.data.clone();

        println!(
            "magic:\t\t{}\nxor + bitshift:\t{}\nbyte replace:\t{}\nrandom:\t\t{}\n\t\t{}\n\t\t{}\n\t\t{}",
            vec2string(magicmutated.clone()),
            vec2string(bitmutated.clone()),
            vec2string(randommutated.clone()),
            vec2string(anymutated.clone()),
            vec2string(anymutated1.clone()),
            vec2string(anymutated2.clone()),
            vec2string(anymutated3.clone()),
            );

        let mut f = File::create("output.txt").unwrap();
        f.write_all(&magicmutated).unwrap();
        f.write_all(&bitmutated).unwrap();
        f.write_all(&randommutated).unwrap();
        f.write_all(&anymutated).unwrap();
    }

    #[test]
    fn test_byte_index() {
        let bytes = b"0000A0000AAA".to_vec();
        let byteidx = byte_index(&b"A".to_vec(), &bytes);
        assert!(byteidx == vec![4, 9, 10, 11]);

        let byteidx2 = byte_index(&b"AA".to_vec(), &bytes);
        assert!(byteidx2 == vec![9, 10]);
    }

    #[test]
    fn test_dict() {
        let dictpath = PathBuf::from("tests/sample.dict");
        let mut mutation = Mutation::new(Some(dictpath));

        let test: Vec<u8> = b"The quick brown fox jumped over the lazy dog".to_vec();
        mutation.data = test.clone();

        mutation.mutate_dictionary_replacement();
        mutation.mutate_dictionary_replacement();

        println!("tokenized:\t{}", String::from_utf8_lossy(&mutation.data))
    }
}
