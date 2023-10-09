//! A byte map can be supplied to specify a grammar syntax tree.
//! Each line (seperated by '\n') defines a node, with `key=value` separated by the first `=` symbol.
//! Parent nodes must be defined before child nodes.
//! Mutations will be generated from a depth-first walk through the resulting tree, with node navigations selected by hash.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::PathBuf;

use crate::mutator::{byte_index, Mutation};

/// Bytemap containing 'key=value' pairs with any number of children
#[derive(Clone)]
pub struct GrammarNode {
    pub key: Vec<u8>,
    pub val: Vec<u8>,
    pub children: BTreeMap<Vec<u8>, Vec<GrammarNode>>,
}

/// GrammarNode wrapper with single-point crossover function
#[derive(Clone)]
pub struct GrammarTree {
    pub root: GrammarNode,
    leaf_values: BTreeSet<Vec<u8>>,
}

impl fmt::Debug for GrammarNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrammarNode")
            .field("key", &String::from_utf8_lossy(&self.key))
            .field("val", &String::from_utf8_lossy(&self.val))
            .field("children", &self.children.values())
            .finish()
    }
}

/// root node for grammar-based input constructions
impl GrammarNode {
    /// add a new node to the GrammarTree by traversing all leaf nodes
    fn insert_node(&mut self, new: GrammarNode) {
        // traverse tree by updating children recursively
        for child_vec in self.children.values_mut() {
            for child in child_vec {
                child.insert_node(new.clone());
            }
        }
        // if the new key is contained in the current value, add new as a child of self
        if !byte_index(&new.key, &self.val).is_empty() {
            if self.children.contains_key(&new.key) {
                let child_vec = self.children.get_mut(&new.key).unwrap();
                child_vec.push(new);
            } else {
                self.children.insert(new.key.to_vec(), vec![new]);
            }
        }
    }

    /// Derive a grammar tree from a byte vector.
    /// Grammar tree nodes are newline-separated.
    /// Parent nodes must be defined before child nodes.
    /// Each node line is defined as a key and value separated by '=', e.g.
    /// `key1=val`.
    ///
    /// Example: phone number grammar input
    ///```text
    #[doc = include_str!("../tests/phone_number.grammar")]
    ///```
    pub fn from(s: &[u8]) -> GrammarNode {
        let mut lines = s.split(|b| b == &b'\n').peekable();

        let mut root_line = lines.peek().unwrap().to_vec();
        while root_line == b"".to_vec() {
            lines.next();
            root_line = lines.peek().unwrap().to_vec();
        }
        let mut root_node = root_line.splitn(2, |b| b == &b'=');
        let mut root = GrammarNode {
            key: root_node.next().unwrap().to_vec(),
            val: root_node.next().unwrap_or(&[]).to_vec(),
            children: BTreeMap::new(),
        };

        for leaf_node_line in lines {
            if leaf_node_line.is_empty() {
                continue;
            }
            let mut leaf_node = leaf_node_line.splitn(2, |b| b == &b'=');
            let node_definition = leaf_node.next().unwrap();
            let node_mapping = leaf_node.next().unwrap_or(&[]);

            let new_node = GrammarNode {
                key: node_definition.to_vec(),
                val: node_mapping.to_vec(),
                children: BTreeMap::new(),
            };
            root.insert_node(new_node);
        }

        root
    }

    /// wrapper for GrammarNode::from() to load bytes from a grammar file
    pub fn from_file(p: &PathBuf) -> GrammarNode {
        let mut buf = Vec::new();
        let mut f = std::fs::File::open(p).unwrap();
        f.read_to_end(&mut buf).unwrap();
        GrammarNode::from(&buf)
    }

    /// Generate a new permutation from syntax tree.
    /// Resulting mutations with values surrounded by ECFUZZ_START_MUTATION.
    /// ECFUZZ_END_MUTATION will be byte-mutated using ecfuzz::mutator
    pub fn grammar_permutation(&self, engine: &mut Mutation) -> Vec<u8> {
        let mut permutation: Vec<u8> = self.val.clone();
        for key in self.children.keys() {
            let mut indices = byte_index(key, &permutation);
            while !indices.is_empty() {
                let nodeselect = self.children.get(key).unwrap();
                let hash: usize = engine.hashfunc() % nodeselect.len();
                let payload = nodeselect[hash].grammar_permutation(engine);
                let idx = indices[engine.hashfunc() % indices.len()];
                permutation.splice(idx..idx + key.len(), payload);
                indices = byte_index(key, &permutation);
            }
        }
        static FUZZ_START_TAG: &[u8; 21] = b"ECFUZZ_START_MUTATION";
        static FUZZ_END_TAG: &[u8; 19] = b"ECFUZZ_END_MUTATION";

        while !byte_index(&FUZZ_START_TAG.to_vec(), &permutation).is_empty() {
            let b1: Vec<usize> = byte_index(&FUZZ_START_TAG.to_vec(), &permutation);
            let b2: Vec<usize> = byte_index(&FUZZ_END_TAG.to_vec(), &permutation);
            for (idx1, idx2) in b1.iter().zip(b2.iter()).rev() {
                let _removed: Vec<u8> = permutation
                    .splice(idx2..&(idx2 + FUZZ_END_TAG.len()), b"".to_vec())
                    .collect();
                #[cfg(debug_assertions)]
                assert_eq!(_removed, FUZZ_END_TAG);

                let _removed2: Vec<u8> = permutation
                    .splice(idx1..&(idx1 + FUZZ_START_TAG.len()), b"".to_vec())
                    .collect();
                #[cfg(debug_assertions)]
                assert_eq!(_removed2, FUZZ_START_TAG);

                engine.data = permutation[idx1 + FUZZ_START_TAG.len()..*idx2].to_vec();
                engine.mutate();

                let _replaced =
                    permutation.splice(idx1..&(idx2 - FUZZ_START_TAG.len()), engine.data.clone());
            }

            engine.data = permutation[..].to_vec();
        }

        permutation
    }

    /// Enumerate tree nodes as a string value
    pub fn display(&self, spaces: Option<usize>) -> String {
        let spaces = if let Some(s) = spaces { s + 4 } else { 0 };
        let mut tree_string = String::new();
        if spaces == 0 {
            tree_string.push_str("ROOT=");
            tree_string.push_str(String::from_utf8_lossy(&self.key.to_vec()).as_ref());
            tree_string.push('\n');
        } else {
            for _ in 0..spaces - 2 {
                tree_string.push(' ');
            }
        }

        tree_string.push_str("- ");
        tree_string.push_str(String::from_utf8_lossy(&self.key).as_ref());
        tree_string.push_str(": ");
        tree_string.push_str(String::from_utf8_lossy(&self.val).as_ref());
        tree_string.push('\n');

        for child in self.children.values() {
            for mapping in child {
                tree_string.push_str(&mapping.display(Some(spaces)));
            }
        }

        tree_string
    }

    fn traverse_leaves(&self) -> BTreeSet<Vec<u8>> {
        let mut leaf_vals: BTreeSet<Vec<u8>> = BTreeSet::new();
        for child in self.children.values() {
            for mapping in child {
                if mapping.children.is_empty() && !mapping.val.is_empty() {
                    leaf_vals.insert(mapping.val.clone());
                } else {
                    leaf_vals.extend(mapping.traverse_leaves());
                }
            }
        }
        leaf_vals
    }
}

impl GrammarTree {
    /// Derive a grammar tree from a byte vector.
    /// Grammar tree nodes are newline-separated.
    /// Parent nodes must be defined before child nodes.
    /// Each node line is defined as a key and value separated by '=', e.g.
    /// `key1=val`.
    ///
    /// Example: phone number grammar input
    ///```text
    #[doc = include_str!("../tests/phone_number.grammar")]
    ///```
    pub fn from(s: &[u8]) -> GrammarTree {
        let root = GrammarNode::from(s);
        let leaf_values = root.traverse_leaves();
        GrammarTree { root, leaf_values }
    }

    /// wrapper for GrammarNode::from() to load bytemap from a grammar file
    pub fn from_file(p: &PathBuf) -> GrammarTree {
        let root = GrammarNode::from_file(p);
        let leaf_values = root.traverse_leaves();
        GrammarTree { root, leaf_values }
    }

    /// Generate a new permutation from syntax tree.
    /// Resulting mutations with values surrounded by ECFUZZ_START_MUTATION.
    /// ECFUZZ_END_MUTATION will be byte-mutated using ecfuzz::mutator
    pub fn grammar_permutation(&self, engine: &mut Mutation) -> Vec<u8> {
        self.root.grammar_permutation(engine)
    }

    /// single-point crossover mutation for two permutations from this tree
    pub fn crossover(
        &self,
        p1: &Vec<u8>,
        p2: &Vec<u8>,
        engine: &mut Mutation,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut splits_p1: Vec<usize> = Vec::new();
        let mut splits_p2: Vec<usize> = Vec::new();

        for leaf in &self.leaf_values {
            splits_p1.append(&mut byte_index(leaf, p1));
            splits_p2.append(&mut byte_index(leaf, p2));
            //println!("LEAF VAL {}", String::from_utf8_lossy(&leaf));
        }
        splits_p1.sort();
        splits_p2.sort();
        //println!("SPLIT P1 {:?}", splits_p1);
        //println!("SPLIT P2 {:?}", splits_p2);

        //let splitdex = engine.hashfunc() % std::cmp::min(splits_p1.len(), splits_p2.len());
        let splitidx_p1 = splits_p1[engine.hashfunc() % splits_p1.len()];
        let splitidx_p2 = splits_p2[engine.hashfunc() % splits_p2.len()];

        let mut m1: Vec<u8> = Vec::new();
        let mut m2: Vec<u8> = Vec::new();

        m1.extend_from_slice(&p1[0..splitidx_p1]);
        m1.extend_from_slice(&p2[splitidx_p2..]);

        m2.extend_from_slice(&p2[0..splitidx_p2]);
        m2.extend_from_slice(&p1[splitidx_p1..]);

        (m1, m2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grammar() {
        let tree = GrammarNode::from_file(&PathBuf::from("./tests/phone_number.grammar"));
        let tree2 = GrammarNode::from_file(&PathBuf::from("./tests/sqlite.grammar"));

        let mut engine = Mutation::with_seed(None, b"test seed value".to_vec(), None);

        println!("\n\n{}", tree.display(None));
        for _ in 0..10 {
            let permute = tree.grammar_permutation(&mut engine);
            let display = String::from_utf8_lossy(&permute);
            println!("{}", display);
        }

        println!("\n\n{}", tree2.display(None));
        for _ in 0..10 {
            let permute = tree2.grammar_permutation(&mut engine);
            let display = String::from_utf8_lossy(&permute);
            println!("{}", display);
        }
    }

    #[test]
    fn test_recombination() {
        let mut engine = Mutation::with_seed(None, b"4".to_vec(), None);

        for filepath in ["./tests/phone_number.grammar", "./tests/sqlite.grammar"] {
            let tree = GrammarTree::from_file(&PathBuf::from(filepath));
            let p1 = tree.grammar_permutation(&mut engine);
            let p2 = tree.grammar_permutation(&mut engine);

            println!(
                "PARENT1: {}                  PARENT2: {}",
                String::from_utf8_lossy(&p1),
                String::from_utf8_lossy(&p2),
            );

            for _ in 0..64 {
                let (c1, c2) = tree.crossover(&p1, &p2, &mut engine);
                let mut spaces = b"".to_vec();
                for _ in 0..[p1.len(), p2.len(), c1.len()]
                    .iter()
                    .reduce(std::cmp::max)
                    .unwrap()
                    - c1.len()
                {
                    spaces.push(b' ');
                }
                println!(
                    "{}{}{}",
                    String::from_utf8_lossy(&c1),
                    String::from_utf8_lossy(&spaces),
                    String::from_utf8_lossy(&c2),
                );
            }
        }
    }
}
