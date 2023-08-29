//! Mutation engine can be run in 'single shot' mode to mutate data from stdin
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
//!  -s, --seed <seed>             Optionally seed the mutation engine with a given value
//!
//!  -m, --multiplier <N>          Mutations per byte. Default 0.01
//!
//!Example:
//!
//!  echo 'Hello world!' | ecfuzz --mutate-stdin --seed 0
//!
//!```

use std::cell::RefCell;
use std::cmp::max;
use std::collections::btree_map::Entry::Vacant;
use std::collections::BTreeMap;
use std::fs::read;
use std::hash::Hasher;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use xxhash_rust::xxh3::Xxh3;

const HELP: &str = r#"
Mutate input from stdin, and return the result to stdout

Options:

  -d, --dictionary-path <file>  Optionally supply a dictionary to enable random
                                dictionary value insertion, and tokenized
                                dictionary replacement

  -s, --seed <seed>             Optionally seed the mutation engine with a given value

  -m, --multiplier <N>          Mutations per byte. Default 0.01


Example:

  echo 'Hello world!' | ecfuzz --mutate-stdin
  echo 'Hello world!' | ecfuzz --mutate-stdin --dictionary-path input/sample.dict --seed 000

"#;

type Mutators = Vec<for<'r> fn(&'r mut Mutation) -> Result<(), MutationError>>;

/// Mutation engine.
/// input to be mutated is stored in data.
/// If a dictionary map is given, dict keys will be inserted if the values
/// are empty, otherwise values will be used for tokenized key replacement.
/// Can be iinitialized with a different hashing seed and multiplier
pub struct Mutation {
    pub data: RefCell<Vec<u8>>,
    pub dict: Option<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>,
    hasher: Xxh3,
    hash_seed: [u8; 4],
    mutators: Mutators,
    multiplier: f64,
}

#[derive(Debug)]
pub struct MutationError;

impl std::fmt::Display for MutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid mutation")
    }
}

impl std::error::Error for MutationError {}

/// Magic values consist of a tuple with byte size and a bytestring.
/// Variants can be 1, 2, or 4 bytes length.
enum Magic {
    A((u8, [u8; 1])),
    B((u8, [u8; 2])),
    C((u8, [u8; 4])),
}

const MAGIC_VALUES: &[&Magic; 10] = &[
    &Magic::A((1, *b"\xff")),
    &Magic::A((1, *b"\x7f")),
    &Magic::A((1, *b"\x00")),
    &Magic::B((2, *b"\xff\xff")),
    &Magic::B((2, *b"\x00\x00")),
    &Magic::C((4, *b"\xff\xff\xff\xff")),
    &Magic::C((4, *b"\x00\x00\x00\x00")),
    &Magic::C((4, *b"\x00\x00\x00\x40")),
    &Magic::C((4, *b"\x00\x00\x00\x80")),
    &Magic::C((4, *b"\xff\xff\xff\x7f")),
];

/// find all indices of matching substring in a raw binary vector
pub fn byte_index(key: &Vec<u8>, bytes: &Vec<u8>) -> Vec<usize> {
    assert!(key.len() <= bytes.len());

    let mut indices: Vec<usize> = vec![];

    for i in 0..(bytes.len() - key.len()) + 1 {
        if &bytes[i..i + key.len()] == key {
            indices.push(i);
        }
    }
    indices
}

/// Load a fuzzing dictionary from a file.
/// dictionary entries are defined one per line: either as a single "key" or as
/// "key=value" pair. Each key may be defined multiple times.
/// Returns a byte vector map.
pub fn load_dictionary(dict_path: PathBuf) -> BTreeMap<Vec<u8>, Vec<Vec<u8>>> {
    let mut dict: BTreeMap<Vec<u8>, Vec<Vec<u8>>> = BTreeMap::new();

    let lines = read(&dict_path)
        .unwrap_or_else(|_| panic!("could not load dictionary from file! {:?}", dict_path))
        .split(|x| x == &b'\n')
        .filter(|x| !x.is_empty() && x[0] != b'#')
        .map(|x| x.to_vec())
        .collect::<Vec<Vec<u8>>>();

    for line in lines {
        #[cfg(debug_assertions)]
        assert!(!line.is_empty());
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
                "  token replace {:?} {:?}",
                String::from_utf8_lossy(&key),
                String::from_utf8_lossy(&val)
            );
        } else {
            key = b"".to_vec();
            val = keypair[0].to_owned();
            #[cfg(debug_assertions)]
            println!("  splice: {:?}", String::from_utf8_lossy(&val));
        }

        if let Vacant(_e) = dict.entry(key.clone()) {
            dict.insert(key, vec![val]);
        } else {
            dict.get_mut(&key).unwrap().push(val);
        };
    }
    println!(
        "loaded dictionary: {}",
        dict_path.as_os_str().to_str().unwrap(),
    );
    dict
}

impl Mutation {
    /// Initialize Mutation engine with an empty seed value.
    /// Multiplier specifies mutations per byte, some float ranging from 0 to 1.
    /// If multiplier is None, a value of 0.01 will be used for one mutation
    /// per 100 bytes

    pub fn new(dict_path: Option<PathBuf>, multiplier: Option<f64>) -> Self {
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
                data: RefCell::new(Vec::new()),
                dict,
                hasher: Xxh3::with_seed(0),
                hash_seed: [0x0_u8, 0x0_u8, 0x0_u8, 0x0_u8],
                mutators,
                multiplier: multiplier.unwrap_or(0.01),
            }
        }
    }

    /// initialize new Mutation seeded by a string of bytes.
    /// Multiplier specifies mutations per byte, a float ranging from 0 to 1.
    /// If multiplier is None, a value of 0.01 will be used for one mutation
    /// per 100 bytes
    pub fn with_seed(path: Option<PathBuf>, seed: Vec<u8>, multiplier: Option<f64>) -> Self {
        let mut m = Mutation::new(path, multiplier);
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
        match MAGIC_VALUES[self.hashfunc() % MAGIC_VALUES.len()] {
            Magic::A(a) => (a.0 as usize, a.1.to_vec()),
            Magic::B(b) => (b.0 as usize, b.1.to_vec()),
            Magic::C(c) => (c.0 as usize, c.1.to_vec()),
        }
    }

    /// magic number mutation
    /// splices data with random magic value
    pub fn mutate_magic(&mut self) -> Result<(), MutationError> {
        let (mut n_size, n) = self.magic_char();
        if n_size > self.data.borrow().len() {
            n_size = self.data.borrow().len();
        }
        let mut sz: usize = self.data.borrow().len() - n_size;
        if sz == 0 {
            sz = 1
        }
        #[cfg(debug_assertions)]
        assert!(sz > 0);
        let idx = self.hashfunc() % sz;
        self.data.borrow_mut().splice(idx..idx + n_size, n);
        Ok(())
    }

    /// XOR mutation and bitshift
    pub fn mutate_bits(&mut self) -> Result<(), MutationError> {
        let bit = self.hashfunc() % (self.data.borrow().len() * 8);
        let idx_bit: usize = bit % 8;
        let idx_byte: usize = bit / 8;
        self.data.borrow_mut()[idx_byte] ^= 1 << idx_bit;
        Ok(())
    }

    /// replace randomly selected bytes with random data of equivalent length
    pub fn mutate_bytes(&mut self) -> Result<(), MutationError> {
        let dataidx = self.hashfunc() % self.data.borrow().len();
        self.data.borrow_mut()[dataidx] = (self.hashfunc() % 256) as u8;
        Ok(())
    }

    /// random dictionary insertion
    pub fn mutate_dictionary(&mut self) -> Result<(), MutationError> {
        let val_idx = self.hashfunc()
            % self
                .dict
                .as_ref()
                .unwrap()
                .get(&b"".to_vec())
                .unwrap()
                .len();
        let val: Vec<u8> =
            self.dict.as_ref().unwrap().get(&b"".to_vec()).unwrap()[val_idx].to_vec();
        //let idx = self.hashfunc() % ((self.data.len() - val.len()) - 1);
        if self.data.borrow().len() > val.len() {
            let idx = self.hashfunc() % (self.data.borrow().len() - val.len());
            self.data.borrow_mut().splice(idx..idx + val.len(), val);
        } else {
            self.data = RefCell::from(val);
        };
        Ok(())
    }

    /// tokenized dictionary replacement
    pub fn mutate_dictionary_replacement(&mut self) -> Result<(), MutationError> {
        let mut keys = self
            .dict
            .as_ref()
            .unwrap()
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect::<Vec<Vec<u8>>>();
        keys.sort();
        let split_idx = self.hashfunc() % keys.len();
        keys = [&keys[split_idx..keys.len()], &keys[0..split_idx]].concat();
        for key in keys {
            let keyidx = self.hashfunc() % self.dict.as_ref().unwrap().get(&key).unwrap().len();
            let val: Vec<u8> = self.dict.as_ref().unwrap().get(&key).unwrap()[keyidx].to_vec();
            let indices: Vec<usize> = byte_index(&key.to_vec(), &self.data.borrow());
            if indices.is_empty() {
                continue;
            }
            let idx = indices[self.hashfunc() % indices.len()];
            self.data.borrow_mut().splice(idx..(idx + key.len()), val);
            return Ok(());
        }
        #[cfg(debug_assertions)]
        eprintln!(
            "no matching tokens in corpus for {}! skipping...",
            String::from_utf8_lossy(&self.data.borrow()),
        );
        Err(MutationError)
    }

    /// applies a random mutator to input
    pub fn mutate(&mut self) {
        let data_len = self.data.borrow().len();
        for _mutate in 0..max(1, (data_len as f64 * self.multiplier) as usize) {
            let mut hash: usize = self.hashfunc() % self.mutators.len();
            while self.mutators[hash](self).is_err() {
                hash = self.hashfunc() % self.mutators.len();
            }
        }
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
    let mut multiplier: Option<f64> = None;
    if args.contains(&"-m".to_string()) || args.contains(&"--multiplier".to_string()) {
        let mut stop = false;
        for arg in &args {
            if arg == "-m" || arg == "--multiplier" {
                stop = true
            } else if stop {
                multiplier = Some(arg.parse().unwrap());
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

    let mut mutation = Mutation::with_seed(dictpath, seed, multiplier);
    mutation.data = RefCell::new(input);
    mutation.mutate();
    let _w = writer.write(&mutation.data.borrow()).unwrap();
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
    fn test_mutations() -> Result<(), MutationError> {
        let test: Vec<u8> = b"The quick brown fox jumped over the lazy dog".to_vec();

        let mut mutation = Mutation::new(None, None);
        mutation.data = RefCell::new(test);

        mutation.mutate_magic()?;
        let magicmutated = mutation.data.clone();
        mutation.mutate_bits()?;
        let bitmutated = mutation.data.clone();
        mutation.mutate_bytes()?;
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
            vec2string(magicmutated.borrow().to_vec()),
            vec2string(bitmutated.borrow().to_vec()),
            vec2string(randommutated.borrow().to_vec()),
            vec2string(anymutated.borrow().to_vec()),
            vec2string(anymutated1.borrow().to_vec()),
            vec2string(anymutated2.borrow().to_vec()),
            vec2string(anymutated3.borrow().to_vec()),
            );

        let mut f = File::create("output.txt").unwrap();
        f.write_all(&magicmutated.borrow()).unwrap();
        f.write_all(&bitmutated.borrow()).unwrap();
        f.write_all(&randommutated.borrow()).unwrap();
        f.write_all(&anymutated.borrow()).unwrap();

        Ok(())
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
        let mut mutation = Mutation::new(Some(dictpath), None);

        let test: Vec<u8> = b"The quick brown fox jumped over the lazy dog".to_vec();
        mutation.data = RefCell::new(test);

        mutation.mutate_dictionary_replacement().unwrap();
        mutation.mutate_dictionary_replacement().unwrap();

        println!(
            "tokenized:\t{}",
            String::from_utf8_lossy(&mutation.data.borrow())
        );
    }
}
