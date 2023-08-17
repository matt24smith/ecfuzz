#![doc = include_str!("../readme.md")]

pub mod config;

pub mod corpus;

pub mod execute;

pub mod mutator;

use std::ffi::{c_int, c_uchar, CStr};

#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: &CStr, size_t: c_int) -> c_int {
    //let c = data.to_bytes()[0] == 'a' as c_uchar;
    let data = data.to_bytes();
    assert!(data.len() as i32 == size_t);
    if data[0] == 'A' as c_uchar {
        if data[1] == 'B' as c_uchar {
            if data[2] == 'C' as c_uchar {
                if data[3] == 'D' as c_uchar {
                    if data[4] == 'E' as c_uchar {
                        if data[5] == 'F' as c_uchar {
                            //fprintf(stderr, "crashing path A...\n");
                            eprintln!("crashing path A...");
                            //char * crash = 0;
                            //crash[0] = 'X';
                            panic!();
                        }
                    }
                }
            }
        }
    } else if data[0] == 'G' as c_uchar {
        if data[1] == 'H' as c_uchar {
            if data[2] == 'I' as c_uchar {
                if data[3] == 'J' as c_uchar {
                    if data[4] == 'K' as c_uchar {
                        if data[5] == 'L' as c_uchar {
                            //fprintf(stderr, "crashing path B...\n");
                            eprintln!("crashing path A...");
                            //char * crash = 0;
                            //crash[0] = 'X';
                            panic!();
                        }
                    }
                }
            }
        }
    }
    return 0;
}
