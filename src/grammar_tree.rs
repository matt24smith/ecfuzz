use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::PathBuf;

use crate::mutator::{byte_index, Mutation};

#[derive(Clone)]
/// tree-based grammar data format
pub struct GrammarNode {
    pub key: Vec<u8>,
    pub val: Vec<u8>,
    pub children: BTreeMap<Vec<u8>, Vec<GrammarNode>>,
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

    /// generate a new mutation based on the defined grammar
    pub fn grammar_permutation(&self, mutation: &mut Mutation) -> Vec<u8> {
        let mut permutation: Vec<u8> = self.val.clone();
        for key in self.children.keys() {
            let mut indices = byte_index(key, &permutation);
            while !indices.is_empty() {
                let nodeselect = self.children.get(key).unwrap();
                let hash: usize = mutation.hashfunc() % nodeselect.len();
                let payload = nodeselect[hash].grammar_permutation(mutation);
                let idx = indices[mutation.hashfunc() % indices.len()];
                permutation.splice(idx..idx + key.len(), payload);
                indices = byte_index(key, &permutation);
            }
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
}
