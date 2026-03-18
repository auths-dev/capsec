use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum Category {
    Fs,
    Net,
    Env,
    Process,
    Ffi,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fs => "FS",
            Self::Net => "NET",
            Self::Env => "ENV",
            Self::Process => "PROC",
            Self::Ffi => "FFI",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Authority {
    pub pattern: AuthorityPattern,
    pub category: Category,
    pub subcategory: &'static str,
    pub risk: Risk,
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub enum AuthorityPattern {
    /// Match a fully qualified path by suffix: `["std", "fs", "read"]`
    Path(&'static [&'static str]),
    /// Only match this method if the same function also contains a call
    /// matching the given path pattern (co-occurrence heuristic).
    /// Eliminates false positives from common method names like `.status()`.
    MethodWithContext {
        method: &'static str,
        requires_path: &'static [&'static str],
    },
}

/// For custom authorities loaded from .capsec.toml
#[derive(Debug, Clone)]
pub struct CustomAuthority {
    pub path: Vec<String>,
    pub category: Category,
    pub risk: Risk,
    pub description: String,
}

pub fn build_registry() -> Vec<Authority> {
    vec![
        // ── Filesystem: std ──────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read arbitrary file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read_to_string"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read arbitrary file contents as string",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "read_dir"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Low,
            description: "List directory contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "metadata"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Low,
            description: "Read file metadata",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "write"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Write arbitrary file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "create_dir_all"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Create directory tree",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "remove_file"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Delete a file",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "remove_dir_all"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Critical,
            description: "Recursively delete a directory tree",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "rename"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Rename/move a file",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "fs", "copy"]),
            category: Category::Fs,
            subcategory: "read+write",
            risk: Risk::Medium,
            description: "Copy a file",
        },
        // ── Filesystem: File ─────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["File", "open"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Open a file for reading",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["File", "create"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Create/truncate a file for writing",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["OpenOptions", "open"]),
            category: Category::Fs,
            subcategory: "read+write",
            risk: Risk::Medium,
            description: "Open file with custom options",
        },
        // ── Filesystem: tokio ────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "read"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Async read file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "read_to_string"]),
            category: Category::Fs,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Async read file as string",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "write"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Async write file contents",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "fs", "remove_file"]),
            category: Category::Fs,
            subcategory: "write",
            risk: Risk::High,
            description: "Async delete a file",
        },
        // ── Network: std ─────────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["TcpStream", "connect"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Open outbound TCP connection",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["TcpListener", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind a TCP listener to a port",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["UdpSocket", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind a UDP socket",
        },
        // send_to only flagged if UdpSocket::bind is in the same function
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "send_to",
                requires_path: &["UdpSocket", "bind"],
            },
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Send UDP datagram to address",
        },
        // ── Network: tokio ───────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "net", "TcpStream", "connect"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Async outbound TCP connection",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["tokio", "net", "TcpListener", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Async bind TCP listener",
        },
        // ── Network: reqwest ─────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "get"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP GET request",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "new"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::Medium,
            description: "Create HTTP client",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "get"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP GET via client",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["reqwest", "Client", "post"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "HTTP POST via client",
        },
        // ── Network: hyper ───────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["hyper", "Client", "request"]),
            category: Category::Net,
            subcategory: "connect",
            risk: Risk::High,
            description: "Hyper HTTP request",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["hyper", "Server", "bind"]),
            category: Category::Net,
            subcategory: "bind",
            risk: Risk::High,
            description: "Bind Hyper HTTP server",
        },
        // ── Environment ──────────────────────────────────────────
        // (no duplicate ["env", "var"] — import expansion handles use std::env)
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "var"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "vars"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Medium,
            description: "Read all environment variables",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "set_var"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::High,
            description: "Modify environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "remove_var"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::Medium,
            description: "Remove environment variable",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "current_dir"]),
            category: Category::Env,
            subcategory: "read",
            risk: Risk::Low,
            description: "Read current working directory",
        },
        Authority {
            pattern: AuthorityPattern::Path(&["std", "env", "set_current_dir"]),
            category: Category::Env,
            subcategory: "write",
            risk: Risk::High,
            description: "Change working directory",
        },
        // ── Process ──────────────────────────────────────────────
        Authority {
            pattern: AuthorityPattern::Path(&["Command", "new"]),
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Create command for subprocess execution",
        },
        // .output(), .spawn(), .status() only flagged if Command::new is in the same function
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "output",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Execute subprocess and capture output",
        },
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "spawn",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Spawn subprocess",
        },
        Authority {
            pattern: AuthorityPattern::MethodWithContext {
                method: "status",
                requires_path: &["Command", "new"],
            },
            category: Category::Process,
            subcategory: "spawn",
            risk: Risk::Critical,
            description: "Execute subprocess and get exit status",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_not_empty() {
        let reg = build_registry();
        assert!(reg.len() > 30);
    }

    #[test]
    fn all_categories_represented() {
        let reg = build_registry();
        let cats: std::collections::HashSet<_> = reg.iter().map(|a| &a.category).collect();
        assert!(cats.contains(&Category::Fs));
        assert!(cats.contains(&Category::Net));
        assert!(cats.contains(&Category::Env));
        assert!(cats.contains(&Category::Process));
    }

    #[test]
    fn risk_ordering() {
        assert!(Risk::Low < Risk::Medium);
        assert!(Risk::Medium < Risk::High);
        assert!(Risk::High < Risk::Critical);
    }
}
