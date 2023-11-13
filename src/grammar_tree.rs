//! A byte map can be supplied to specify a grammar syntax tree.
//! Each line (seperated by '\n') defines a node, with `key=value` separated by the first `=` symbol.
//! Parent nodes must be defined before child nodes.
//! Mutations will be generated from a depth-first walk through the resulting tree, with node navigations selected by hash.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

use crate::mutator::Mutation;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::NodeIndexable;

#[derive(Clone)]
pub struct GraphTree {
    pub graph: DiGraph<GraphNode, ()>,
}

#[derive(Ord, Hash, Eq, PartialEq, PartialOrd, Clone, Default)]
pub struct GraphNode {
    pub key: Vec<u8>,
    pub val: Vec<u8>,
}

impl Ord for GraphTree {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.graph.node_count(), self.graph.edge_count())
            .cmp(&(other.graph.node_count(), other.graph.edge_count()))
    }
}
impl PartialOrd for GraphTree {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for GraphTree {
    fn eq(&self, other: &Self) -> bool {
        (self.graph.node_count(), self.graph.edge_count())
            == (other.graph.node_count(), other.graph.edge_count())
    }
}
impl Eq for GraphTree {}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct GraphMutation {
    pub encoding: Vec<(NodeIndex, NodeIndex)>,
}
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct GraphMutationTest<'a> {
    pub encoding: Vec<(NodeIndex, NodeIndex)>,
    parent: &'a GraphTree,
}

impl fmt::Debug for GraphMutationTest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let m = GraphMutation {
            encoding: self.encoding.clone(),
        };
        write!(f, "{}", String::from_utf8_lossy(&self.parent.decode(&m)))
    }
}

impl GraphTree {
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
    pub fn from(s: &[u8]) -> GraphTree {
        //let mut nodes: Vec<GraphNode> = Vec::new();
        //let mut edges: Vec<(GraphNode, GraphNode)> = Vec::new();
        let mut graph: DiGraph<GraphNode, ()> = DiGraph::new();

        let lines = s.split(|b| b == &b'\n');

        for leaf_node_line in lines {
            if leaf_node_line.is_empty() {
                continue;
            }
            let mut leaf_node = leaf_node_line.splitn(2, |b| b == &b'=');

            let key = leaf_node.next().unwrap();
            assert_ne!(key, b"");
            let val = leaf_node.next().unwrap_or(&[]);
            let n1 = GraphNode {
                key: key.to_vec(),
                val: val.to_vec(),
            };
            let n1_node_index = graph.add_node(n1);
            let mut dfs = petgraph::visit::Dfs::new(&graph, 0.into());
            while let Some(node_index) = dfs.next(&graph) {
                //let node = graph[node_index];
                if graph[node_index]
                    .val
                    .windows(graph[n1_node_index].key.len())
                    .any(|w| w == graph[n1_node_index].key)
                {
                    //edges.insert(node, &n1);
                    //edges.push((node.clone(), n1));
                    graph.add_edge(node_index, n1_node_index, ());
                }
            }
            //nodes.push(n1);
        }

        //let graph: DiGraph<_, ()> = DiGraph::from_iter(edges.iter());
        //let graph: DiGraph<GraphNode, ()> = DiGraph::from(edges);
        //graph.extend_with_edges(edges.iter());

        GraphTree { graph }
    }

    /// wrapper for GrammarNode::from() to load bytemap from a grammar file
    pub fn from_file(p: &PathBuf) -> GraphTree {
        let mut buf = Vec::new();
        let mut f = std::fs::File::open(p).unwrap();
        f.read_to_end(&mut buf).unwrap();
        GraphTree::from(&buf)
    }

    /// splice child values into node substring keys
    fn splice_child_val(&self, child: NodeIndex, mut output_slices: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        // check index of matching subslice in a flat mapping
        let mut slices_concat = Vec::new();
        for slice in &output_slices {
            slices_concat.extend_from_slice(slice);
        }

        let slice_idx = slices_concat
            .windows(self.graph[child].key.len())
            .position(|w| w == self.graph[child].key);
        if slice_idx.is_none() {
            return output_slices;
        }

        // check jagged array index
        let mut cursor = 0;
        let mut cursor_byteidx = 0;
        for slice in output_slices.iter() {
            if cursor_byteidx + slice.len() <= slice_idx.unwrap() {
                cursor += 1;
                cursor_byteidx += slice.len();
            } else {
                break;
            }
        }

        // remove selected slice from output
        let subslice = output_slices.remove(cursor);

        // find index of slice
        let splice_start = subslice
            .windows(self.graph[child].key.len())
            .position(|w| w == self.graph[child].key);
        if splice_start.is_none() {
            panic!("{:?} NOT IN {}", child, String::from_utf8_lossy(&subslice));
        }
        let splice_start = splice_start.unwrap();

        // subsitute slices
        let mut replacements: Vec<&[u8]> = Vec::new();
        if splice_start > 0 {
            replacements.push(&subslice[0..splice_start]);
        }
        if !self.graph[child].val.is_empty() {
            replacements.push(&self.graph[child].val);
        }
        if splice_start + self.graph[child].key.len() < subslice.len() {
            replacements.push(&subslice[splice_start + self.graph[child].key.len()..]);
        }

        while let Some(r) = replacements.pop() {
            output_slices.insert(cursor, r.to_vec());
        }
        output_slices
    }

    /// decode graph edges as slices of a bytemap into a newly allocated byte vector
    pub fn decode(&self, permutation: &GraphMutation) -> Vec<u8> {
        if permutation.encoding.is_empty() {
            return [].to_vec();
        }
        let mut output_slices: Vec<Vec<u8>> =
            vec![self.graph[permutation.encoding[0].0].val.clone()];
        for (_parent, child) in &permutation.encoding {
            output_slices = self.splice_child_val(*child, output_slices);
        }
        let mut out = Vec::new();
        for slice in &output_slices {
            out.extend_from_slice(slice);
        }
        //output_slices.concat()
        out
    }

    pub fn grammar_permutation(&self, engine: &mut Mutation) -> GraphMutation {
        let mut edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();

        if self.graph.node_count() == 0 {
            return GraphMutation {
                encoding: edges,
                //parent: &self,
            };
        }

        let mut stack: Vec<NodeIndex> = Vec::new();

        //let root = self.graph.nodes().next().unwrap();
        let root: NodeIndex = 0.into();
        let mut root_val: Vec<u8> = self.graph[root].val.to_vec();
        stack.push(root);

        while !stack.is_empty() {
            let children_unique_keys = BTreeSet::from_iter(
                self.graph
                    .neighbors(*stack.last().unwrap())
                    .map(|c| &self.graph[c].key),
            );

            let mut was_replaced = false;
            for key in children_unique_keys {
                while let Some(idx) = root_val.windows(key.len()).position(|v| v == key) {
                    let nodeselect_idx: Vec<usize> = self
                        .graph
                        .neighbors(*stack.last().unwrap())
                        .enumerate()
                        .filter_map(|(i, c)| {
                            if &self.graph[c].key == key {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if nodeselect_idx.is_empty() {
                        break;
                    }
                    let hash = nodeselect_idx[engine.hashfunc() % nodeselect_idx.len()];
                    let next_node = self
                        .graph
                        .neighbors(*stack.last().unwrap())
                        .collect::<Vec<NodeIndex>>()[hash];
                    edges.push((*stack.last().unwrap(), next_node));
                    root_val.splice(
                        idx..idx + self.graph[next_node].key.len(),
                        self.graph[next_node].val.to_vec(),
                    );
                    stack.push(next_node);
                    was_replaced = true;
                }
            }
            if !was_replaced {
                stack.pop().unwrap();
            }
        }

        GraphMutation {
            encoding: edges,
            //parent: &self,
        }

        /*
        let permutation = GraphMutation { encoding: edges };
        static FUZZ_START_TAG: &[u8; 21] = b"ECFUZZ_START_MUTATION";
        static FUZZ_END_TAG: &[u8; 19] = b"ECFUZZ_END_MUTATION";

        let mut b1: Vec<usize> = byte_index(&FUZZ_START_TAG.to_vec(), &current_tree.permutation);
        while !b1.is_empty() {
        let b2: Vec<usize> = byte_index(&FUZZ_END_TAG.to_vec(), &current_tree.permutation);
        for (idx1, idx2) in b1.iter().zip(b2.iter()).rev() {
        let _removed: Vec<u8> = current_tree
        .permutation
        .splice(idx2..&(idx2 + FUZZ_END_TAG.len()), b"".to_vec())
        .collect();
        #[cfg(debug_assertions)]
        assert_eq!(_removed, FUZZ_END_TAG);

        let _removed2: Vec<u8> = current_tree
        .permutation
        .splice(idx1..&(idx1 + FUZZ_START_TAG.len()), b"".to_vec())
        .collect();
        #[cfg(debug_assertions)]
        assert_eq!(_removed2, FUZZ_START_TAG);

        engine.data = current_tree.permutation[idx1 + FUZZ_START_TAG.len()..*idx2].to_vec();
        engine.mutate();

        let _replaced = current_tree
        .permutation
        .splice(idx1..&(idx2 - FUZZ_START_TAG.len()), engine.data.clone());
        }

        engine.data = current_tree.permutation[..].to_vec();
        b1 = byte_index(&FUZZ_START_TAG.to_vec(), &current_tree.permutation);
        }
        */

        //permutation.permutation = permutation.reconstruct();
        //permutation.reconstruct();
    }

    /// returns true if node B is contained in the descendants of node A within this graph
    pub fn is_parent_of(&self, a: NodeIndex, b: NodeIndex) -> bool {
        let mut nodelist = petgraph::visit::Dfs::new(&self.graph, a);
        while let Some(n) = nodelist.next(&self.graph) {
            if b == n {
                return true;
            }
        }
        false
    }

    /*
           #[inline]
           pub fn cross_with(
           &self,
           mut parent1: GraphMutation,
           mut parent2: GraphMutation,
           engine: &mut Mutation,
           ) -> (GraphMutation, GraphMutation) {
        // get subset of matching node key/vals
        // parent val -> child key
        let parent1_keys = BTreeSet::from_iter(
        parent1
        .encoding
        .iter()
        .skip(1)
        .map(|g| self.graph[g.0].key.clone()),
        );
        let parent2_keys = BTreeSet::from_iter(
        parent2
        .encoding
        .iter()
        .skip(1)
        .map(|g| self.graph[g.0].key.clone()),
        );
        let mut matching_keys: BTreeSet<&[u8]> =
        BTreeSet::from_iter(parent1_keys.intersection(&parent2_keys));
        // remove root to avoid replacing entire tree
        matching_keys.remove(&self.graph[parent1.encoding[0].0].key);
        //matching_keys.remove(&parent1.encoding[0].0.val);

        assert!(!matching_keys.is_empty());
        let key_select = matching_keys.iter().map(|v| **v).collect::<Vec<Vec<u8>>>()
        [engine.hashfunc() % matching_keys.len()];

        //println!("SELECT KEY: {}", String::from_utf8_lossy(&key_select));

        // select removal index and remove child nodes from donor
        let donor_matching_key_idx: Vec<usize> = parent2
        .encoding
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
        if self.graph[e.0].key == key_select {
        //eprintln!("{}: {}", i, String::from_utf8_lossy(&e.0.key));
        Some(i)
        } else {
        None
        }
        })
        .collect();
        let donor_idx = donor_matching_key_idx[0];

        let mut donor_matching_key_idx: Vec<usize> = Vec::from([donor_idx]);
        for i in donor_idx + 1..parent2.encoding.len() {
        if self.is_parent_of(parent2.encoding[donor_idx].0, parent2.encoding[i].1)
        //|| self.is_parent_of(parent2.encoding[donor_idx].0, parent2.encoding[i].0)
        {
        donor_matching_key_idx.push(i);
        } else {
        eprintln!(
        "Not a child:  {}={}",
        String::from_utf8_lossy(&self.graph[parent2.encoding[i].1].key),
        String::from_utf8_lossy(&self.graph[parent2.encoding[i].1].val),
        );
        break;
        }
        }

        assert!(!donor_matching_key_idx.is_empty());

        // remove keys from B
        let mut donor_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();

        for donor_idx in donor_matching_key_idx.iter().rev() {
            donor_edges.insert(0, parent2.encoding.remove(*donor_idx));
        }
        let matching_key_idx: Vec<usize> = parent1
            .encoding
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if self.graph[e.0].key == key_select {
                    Some(i)
                } else {
                    None
                }
            })
        .collect();
        let host_idx = matching_key_idx[0];
        let mut matching_key_idx: Vec<usize> = Vec::from([host_idx]);

        for i in host_idx + 1..parent1.encoding.len() {
            if self.is_parent_of(parent1.encoding[host_idx].0, parent1.encoding[i].1) {
                matching_key_idx.push(i);
            } else {
                break;
            }
        }

        // remove keys from A
        let mut replaced_edges: Vec<(NodeIndex, NodeIndex)> = Vec::new();
        for replace_idx in matching_key_idx.iter().rev() {
            replaced_edges.insert(0, parent1.encoding.remove(*replace_idx));
        }

        // inject donor nodes into host
        for replace_idx in &matching_key_idx {
            while let Some(edge) = donor_edges.pop() {
                parent1.encoding.insert(*replace_idx, edge);
            }
        }

        // inject host nodes into donor
        for donor_idx in &donor_matching_key_idx {
            while let Some(edge) = replaced_edges.pop() {
                parent2.encoding.insert(*donor_idx, edge);
            }
        }

        // construct byte representation
        let cross_1 = GraphMutation {
            /*
               permutation: if parent1.encoding.is_empty() {
               parent1.permutation.to_vec()
               } else {
               let mut output_slices: Vec<Box<&[u8]>> = vec![Box::new(parent1.encoding[0].0.val)];
               for (_parent, child) in parent1.encoding.clone() {
               output_slices = parent1.splice_child_val(*child, output_slices);
               }
               output_slices
               },
               */
            encoding: parent1.encoding,
        };
        //cross_1.permutation = cross_1.reconstruct();

        let cross_2 = GraphMutation {
            /*
               permutation: if parent2.encoding.is_empty() {
               parent2.permutation.to_vec()
               } else {
               let mut output_slices: Vec<Box<&[u8]>> = vec![Box::new(parent2.encoding[0].0.val)];
               for (_parent, child) in parent2.encoding.clone() {
               output_slices = parent2.splice_child_val(*child, output_slices);
               }
               output_slices
               },
               */
            encoding: parent2.encoding,
        };
        //cross_2.permutation = cross_2.reconstruct();

        (cross_1, cross_2)
    }
    */

    //#[inline]
    pub fn swap_nodes(
        &self,
        parent1: GraphMutation,
        parent2: GraphMutation,
        engine: &mut Mutation,
    ) -> (GraphMutation, GraphMutation) {
        let mut child1: Vec<(NodeIndex, NodeIndex)> = Vec::with_capacity(parent2.encoding.len());
        let mut child2: Vec<(NodeIndex, NodeIndex)> = Vec::with_capacity(parent1.encoding.len());
        let key_select =
            engine.hashfunc() % std::cmp::min(parent1.encoding.len(), parent2.encoding.len());

        for (i, (p1_edge, p2_edge)) in parent1
            .encoding
            .iter()
            .zip(parent2.encoding.iter())
            .enumerate()
        {
            if i <= key_select {
                child1.push(*p1_edge);
                child2.push(*p2_edge);
            } else {
                child1.push(*p2_edge);
                child2.push(*p1_edge);
            }
        }

        // construct byte representation
        let mut cross_1 = GraphMutation {
            encoding: child1,
            //parent: &self,
        };

        let mut cross_2 = GraphMutation {
            encoding: child2,
            //parent: &self,
        };

        let mut random_walk = self
            .graph
            .node_indices()
            .map(|n| (engine.hashfunc(), n))
            .collect::<Vec<(usize, NodeIndex)>>();
        random_walk.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        // fill in missing data via edge walk
        for (_hash, node) in random_walk {
            for current_tree in [&mut cross_1, &mut cross_2] {
                while let Some(_idx) = self
                    .decode(current_tree)
                    .windows(self.graph[node].key.len())
                    .position(|v| v == self.graph[node].key)
                {
                    //let idx = indices[indices.len() - 1];
                    //current_tree.permutation = current_tree.splice_child_val(node, current_tree.permutation);
                    /*
                    current_tree
                    .permutation
                    .splice(idx..idx + node.key.len(), node.val.to_vec());
                    */
                    let cur_parent = self
                        .graph
                        .neighbors_directed(node, petgraph::Direction::Incoming)
                        .next()
                        .expect("getting parent node");
                    current_tree.encoding.push((cur_parent, node));
                }
            }
        }

        (cross_1, cross_2)
    }

    /// Export the current graph using the DOT graphviz file format
    pub fn export_dot(&self) -> String {
        use petgraph::dot::{Config, Dot};
        let mut dotgraph = format!(
            "{:?}",
            Dot::with_config(&self.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        );

        // add more vertical height between layers if nodes have many children
        let max_width: usize = self
            .graph
            .node_indices()
            .map(|n| self.graph.neighbors(n).collect::<Vec<NodeIndex>>().len())
            .reduce(std::cmp::max)
            .unwrap();
        let depths = petgraph::algo::dijkstra::dijkstra(
            &self.graph,
            self.graph.node_indices().next().unwrap(),
            None,
            |_| 1,
        );
        let max_depth = depths.values().reduce(std::cmp::max).unwrap() + 1;

        let mut graph_opts = "digraph {\n".to_owned();
        for opt in [
            "label=\"Fuzzing Grammar Tree\"",
            "labelloc=t",
            "layout=dot",
            "ordering=out",
            format!("ranksep={}", max_width / max_depth).as_str(),
            "splines=line",
            "node [nojustify=true style=rounded shape=none]",
            "edge [minlen=1]",
        ] {
            graph_opts += opt;
            graph_opts += "\n";
        }
        dotgraph = dotgraph.replace("digraph {", &graph_opts);

        for (i, node) in self.graph.node_indices().enumerate() {
            let mut keytext: String = String::from_utf8_lossy(&self.graph[node].key).to_string();
            let mut valtext: String = String::from_utf8_lossy(&self.graph[node].val).to_string();
            for (find, replace) in [
                ("<", "&#60;"),
                (">", "&#62;"),
                ("[", "&#91;"),
                ("]", "&#93;"),
                ("{", "&#123;"),
                ("|", "&#124;"),
                ("}", "&#125;"),
            ] {
                keytext = keytext.replace(find, replace);
                valtext = valtext.replace(find, replace);
            }
            let find = format!("label = \"{}\"", i);
            let replace = format!(
                r#"label=<<TABLE border="0" cellborder="1">
                    <TR><td style="rounded" height="24">{}</td></TR>
                    <TR><td style="rounded" height="24">{}</td></TR>
                    </TABLE>
                    >"#,
                keytext, valtext
            );
            dotgraph = dotgraph.replace(&find, &replace);
        }

        dotgraph
    }

    /// Export the current graph using the DOT graphviz file format.
    /// The input permutation will be highlighted as a numbered tree walk.
    pub fn export_dot_highlighted(&self, permutation: &GraphMutation) -> String {
        let mut dotgraph = self.export_dot();
        dotgraph = dotgraph.replace(
            "Fuzzing Grammar Tree",
            format!(
                "Permutation: {}",
                String::from_utf8_lossy(&self.decode(permutation))
            )
            .as_str(),
        );

        for (i, edge) in permutation.encoding.iter().enumerate() {
            let p = self.graph.to_index(edge.0);
            let c = self.graph.to_index(edge.1);
            let find = format!("{} -> {} [ ]", p, c);
            let replace = format!(
                "{} -> {} [ xlabel={} color=red fontcolor=red decorate=false ]",
                p, c, i
            );
            dotgraph = dotgraph.replace(&find, &replace);
        }

        #[cfg(debug_assertions)]
        println!("{}", dotgraph);
        dotgraph
    }

    /// render the current graph as an SVG image.
    /// if preview is true, the image will be opened with the default application for SVG files.
    /// graphviz 'dot' executable must be installed in $PATH for this to work.
    pub fn export_svg(&self, dot_string: String, output_svg: PathBuf, preview: bool) {
        let mut graphviz = Command::new("dot")
            .stdin(std::process::Stdio::piped())
            .arg("-Tsvg")
            //.arg(&dotpath)
            .arg("-o")
            .arg(&output_svg)
            .spawn()
            .unwrap();
        let mut input = graphviz.stdin.take().expect("Failed to open stdin");
        input
            .write_all(dot_string.as_bytes())
            .expect("sending input to graphviz");
        input.flush().expect("flush target stdin");
        std::mem::drop(input);
        graphviz.wait().expect("waiting for graphviz");

        if preview {
            #[cfg(target_os = "linux")]
            let opener = "xdg-open";
            #[cfg(target_os = "macos")]
            let opener = "open";
            #[cfg(target_os = "windows")]
            let opener = "start";

            Command::new(opener)
                .arg(output_svg)
                .spawn()
                .unwrap()
                .wait()
                .unwrap();
        }
    }
}

impl fmt::Debug for GraphNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("GraphNode")
            .field("key", &String::from_utf8_lossy(&self.key))
            .field("val", &String::from_utf8_lossy(&self.val))
            .finish()
    }
}

/*
impl fmt::Debug for GraphMutation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.parent.decode(&self)))
    }
}

impl fmt::Display for GraphMutation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(self.parent.decode(&self))
                .expect("converting mutation bytemap to string")
        )
    }
}
*/

/*
       impl fmt::Debug for GraphTree {
       fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       for (i, node) in self.graph.node_indices().enumerate() {
       writeln!(
       f,
       "{}:\t{}",
       i,
       String::from_utf8_lossy(&self.graph[node].key)
       )?;
       }
    /*
    for edge in self.graph.edges() {
    writeln!(
    f,
    "{} -> {}",
    String::from_utf8_lossy(&edge.0.key),
    String::from_utf8_lossy(&edge.1.key)
    )?;
    }
    */
    Ok(())
}
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn encode_permutation() {
        let mut engine = Mutation::with_seed(None, b"1".to_vec(), None);

        let filepath = "./tests/phone_number.grammar";
        let mut buf: Vec<u8> = Vec::new();
        let mut f = std::fs::File::open(PathBuf::from(filepath)).unwrap();
        let tree: GraphTree;
        f.read_to_end(&mut buf).unwrap();
        tree = GraphTree::from(&buf);

        for _ in 0..25 {
            let p1 = tree.grammar_permutation(&mut engine);
            let result = tree.decode(&p1);
            println!("Permutation    \t{:?}", String::from_utf8_lossy(&result));
        }
    }

    #[test]
    fn crossover() {
        let mut engine = Mutation::with_seed(None, b"1".to_vec(), None);

        let crossovers: u32 = 32;

        for filepath in ["./tests/phone_number.grammar", "./tests/sqlite.grammar"] {
            let mut buf: Vec<u8> = Vec::new();
            let mut f = std::fs::File::open(PathBuf::from(filepath)).unwrap();
            let tree: GraphTree;
            f.read_to_end(&mut buf).unwrap();
            tree = GraphTree::from(&buf);
            let p1 = tree.grammar_permutation(&mut engine);
            let p2 = tree.grammar_permutation(&mut engine);

            /*
            let copy1 = GraphMutationTest {
                encoding: p1.encoding.clone(),
                parent: &tree,
            };
            let copy2 = GraphMutationTest {
                encoding: p2.encoding.clone(),
                parent: &tree,
            };

            println!("PARENT1:\t{:?}          PARENT2:\t{:?}\n", copy1, copy2,);
            */

            for _ in 0..crossovers {
                let (child1, child2) = tree.swap_nodes(p1.clone(), p2.clone(), &mut engine);
                /*
                let copy1 = GraphMutationTest {
                    encoding: child1.encoding.clone(),
                    parent: &tree,
                };
                let copy2 = GraphMutationTest {
                    encoding: child2.encoding.clone(),
                    parent: &tree,
                };
                println!("CHILD 1:\t{:?}\t\tCHILD 2:\t{:?}", copy1, copy2,);
                */
                assert!(!child1.encoding.is_empty());
                assert!(!child2.encoding.is_empty());
            }
        }
    }

    #[test]
    fn display_graph() {
        let mut buf: Vec<u8> = Vec::new();
        let mut f = std::fs::File::open(PathBuf::from("./tests/phone_number.grammar")).unwrap();
        //let mut f = std::fs::File::open(PathBuf::from("./tests/sqlite.grammar")).unwrap();

        let g: GraphTree;
        f.read_to_end(&mut buf).unwrap();
        g = GraphTree::from(&buf);

        g.export_svg(g.export_dot(), PathBuf::from("tree.svg"), false);

        let mut engine = Mutation::with_seed(None, b"0".to_vec(), None);
        let p1 = g.grammar_permutation(&mut engine);
        let p1_dotgraph = g.export_dot_highlighted(&p1);
        g.export_svg(p1_dotgraph, PathBuf::from("permutation.svg"), true);
    }
}
