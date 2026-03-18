use crate::detector::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_FILE: &str = ".capsec-baseline.json";

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug)]
pub struct BaselineEntry {
    pub crate_name: String,
    pub crate_version: String,
    pub file: String,
    pub function: String,
    pub call_text: String,
    pub category: String,
}

impl From<&Finding> for BaselineEntry {
    fn from(f: &Finding) -> Self {
        Self {
            crate_name: f.crate_name.clone(),
            crate_version: f.crate_version.clone(),
            file: f.file.clone(),
            function: f.function.clone(),
            call_text: f.call_text.clone(),
            category: f.category.label().to_string(),
        }
    }
}

pub struct DiffResult {
    pub new_findings: Vec<BaselineEntry>,
    pub removed_findings: Vec<BaselineEntry>,
    pub unchanged_count: usize,
}

pub fn load_baseline(workspace_root: &Path) -> Option<HashSet<BaselineEntry>> {
    let path = workspace_root.join(BASELINE_FILE);
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_baseline(workspace_root: &Path, findings: &[Finding]) -> Result<(), String> {
    let entries: Vec<BaselineEntry> = findings.iter().map(BaselineEntry::from).collect();
    let json = serde_json::to_string_pretty(&entries)
        .map_err(|e| format!("Failed to serialize baseline: {e}"))?;
    std::fs::write(workspace_root.join(BASELINE_FILE), json)
        .map_err(|e| format!("Failed to write baseline: {e}"))
}

pub fn diff(current: &[Finding], baseline: &HashSet<BaselineEntry>) -> DiffResult {
    let current_set: HashSet<BaselineEntry> = current.iter().map(BaselineEntry::from).collect();

    let new_findings: Vec<BaselineEntry> = current_set.difference(baseline).cloned().collect();
    let removed_findings: Vec<BaselineEntry> = baseline.difference(&current_set).cloned().collect();
    let unchanged_count = current_set.intersection(baseline).count();

    DiffResult {
        new_findings,
        removed_findings,
        unchanged_count,
    }
}

pub fn print_diff(diff_result: &DiffResult) {
    if !diff_result.new_findings.is_empty() {
        eprintln!(
            "\n{} new finding(s) since last baseline:",
            diff_result.new_findings.len()
        );
        for entry in &diff_result.new_findings {
            eprintln!(
                "  + [{}] {}::{} — {}",
                entry.category, entry.crate_name, entry.function, entry.call_text
            );
        }
    }
    if !diff_result.removed_findings.is_empty() {
        eprintln!(
            "\n{} finding(s) removed since last baseline:",
            diff_result.removed_findings.len()
        );
        for entry in &diff_result.removed_findings {
            eprintln!(
                "  - [{}] {}::{} — {}",
                entry.category, entry.crate_name, entry.function, entry.call_text
            );
        }
    }
    eprintln!("\n{} finding(s) unchanged.", diff_result.unchanged_count);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorities::{Category, Risk};

    fn make_finding(call: &str, category: Category) -> Finding {
        Finding {
            file: "src/lib.rs".to_string(),
            function: "test".to_string(),
            function_line: 1,
            call_line: 2,
            call_col: 5,
            call_text: call.to_string(),
            category,
            subcategory: "test".to_string(),
            risk: Risk::Medium,
            description: "test".to_string(),
            is_build_script: false,
            crate_name: "test-crate".to_string(),
            crate_version: "0.1.0".to_string(),
        }
    }

    #[test]
    fn diff_detects_new_findings() {
        let baseline: HashSet<BaselineEntry> = HashSet::new();
        let current = vec![make_finding("std::fs::read", Category::Fs)];
        let result = diff(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.removed_findings.len(), 0);
        assert_eq!(result.unchanged_count, 0);
    }

    #[test]
    fn diff_detects_removed_findings() {
        let entry = BaselineEntry {
            crate_name: "old-crate".to_string(),
            crate_version: "0.1.0".to_string(),
            file: "src/lib.rs".to_string(),
            function: "old_func".to_string(),
            call_text: "std::net::TcpStream::connect".to_string(),
            category: "NET".to_string(),
        };
        let baseline: HashSet<BaselineEntry> = [entry].into_iter().collect();
        let result = diff(&[], &baseline);
        assert_eq!(result.removed_findings.len(), 1);
        assert_eq!(result.new_findings.len(), 0);
    }

    #[test]
    fn diff_detects_unchanged() {
        let finding = make_finding("std::fs::read", Category::Fs);
        let baseline: HashSet<BaselineEntry> =
            [BaselineEntry::from(&finding)].into_iter().collect();
        let result = diff(&[finding], &baseline);
        assert_eq!(result.unchanged_count, 1);
        assert_eq!(result.new_findings.len(), 0);
        assert_eq!(result.removed_findings.len(), 0);
    }
}
