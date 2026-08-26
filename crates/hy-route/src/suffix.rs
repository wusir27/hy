//! Domain-label suffix trie. Lookup is O(labels), not a linear scan of 50k suffixes.

use crate::action::Action;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub(crate) struct SuffixTrie {
    root: Node,
}

#[derive(Debug, Default)]
struct Node {
    children: HashMap<String, Node>,
    /// First file-order hit for this exact suffix.
    hit: Option<(usize, Action)>,
}

impl SuffixTrie {
    pub(crate) fn insert(&mut self, domain: &str, idx: usize, action: Action) {
        let labels = rev_labels(domain);
        insert_node(&mut self.root, &labels, idx, action);
    }

    /// Every matching suffix along the walk (TLD → more specific).
    pub(crate) fn lookup(&self, host: &str) -> Vec<(usize, Action)> {
        let labels = rev_labels(host);
        let mut out = Vec::new();
        lookup_node(&self.root, &labels, &mut out);
        out
    }
}

fn rev_labels(host: &str) -> Vec<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h.split('.')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .rev()
        .collect()
}

fn insert_node(node: &mut Node, labels: &[String], idx: usize, action: Action) {
    if labels.is_empty() {
        if node.hit.is_none() {
            node.hit = Some((idx, action));
        }
        return;
    }
    insert_node(
        node.children.entry(labels[0].clone()).or_default(),
        &labels[1..],
        idx,
        action,
    );
}

fn lookup_node(node: &Node, labels: &[String], out: &mut Vec<(usize, Action)>) {
    if let Some(h) = node.hit {
        out.push(h);
    }
    if labels.is_empty() {
        return;
    }
    if let Some(ch) = node.children.get(&labels[0]) {
        lookup_node(ch, &labels[1..], out);
    }
}
