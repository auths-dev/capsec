use std::path::Path;
use syn::visit::Visit;

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub path: String,
    pub functions: Vec<ParsedFunction>,
    pub use_imports: Vec<ImportPath>,
    pub extern_blocks: Vec<ExternBlock>,
}

#[derive(Debug, Clone)]
pub struct ParsedFunction {
    pub name: String,
    pub line: usize,
    pub calls: Vec<CallSite>,
    pub is_build_script: bool,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub segments: Vec<String>,
    pub line: usize,
    pub col: usize,
    pub kind: CallKind,
}

#[derive(Debug, Clone)]
pub enum CallKind {
    FunctionCall,
    MethodCall { method: String },
}

#[derive(Debug, Clone)]
pub struct ImportPath {
    pub segments: Vec<String>,
    pub alias: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExternBlock {
    pub abi: Option<String>,
    pub functions: Vec<String>,
    pub line: usize,
}

pub fn parse_file(path: &Path) -> Result<ParsedFile, String> {
    let source =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    parse_source(&source, &path.display().to_string())
}

pub fn parse_source(source: &str, path: &str) -> Result<ParsedFile, String> {
    let syntax = syn::parse_file(source).map_err(|e| format!("Failed to parse {path}: {e}"))?;

    let mut visitor = FileVisitor::new(path.to_string());
    visitor.visit_file(&syntax);

    Ok(ParsedFile {
        path: path.to_string(),
        functions: visitor.functions,
        use_imports: visitor.imports,
        extern_blocks: visitor.extern_blocks,
    })
}

struct FileVisitor {
    file_path: String,
    functions: Vec<ParsedFunction>,
    imports: Vec<ImportPath>,
    extern_blocks: Vec<ExternBlock>,
    current_function: Option<ParsedFunction>,
}

impl FileVisitor {
    fn new(file_path: String) -> Self {
        Self {
            file_path,
            functions: Vec::new(),
            imports: Vec::new(),
            extern_blocks: Vec::new(),
            current_function: None,
        }
    }
}

impl<'ast> Visit<'ast> for FileVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let func = ParsedFunction {
            name: node.sig.ident.to_string(),
            line: node.sig.ident.span().start().line,
            calls: Vec::new(),
            is_build_script: self.file_path.ends_with("build.rs") && node.sig.ident == "main",
        };

        let prev = self.current_function.take();
        self.current_function = Some(func);

        syn::visit::visit_item_fn(self, node);

        if let Some(func) = self.current_function.take() {
            self.functions.push(func);
        }
        self.current_function = prev;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let func = ParsedFunction {
            name: node.sig.ident.to_string(),
            line: node.sig.ident.span().start().line,
            calls: Vec::new(),
            is_build_script: false,
        };

        let prev = self.current_function.take();
        self.current_function = Some(func);

        syn::visit::visit_impl_item_fn(self, node);

        if let Some(func) = self.current_function.take() {
            self.functions.push(func);
        }
        self.current_function = prev;
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        // Only visit if there's a default body
        if node.default.is_some() {
            let func = ParsedFunction {
                name: node.sig.ident.to_string(),
                line: node.sig.ident.span().start().line,
                calls: Vec::new(),
                is_build_script: false,
            };

            let prev = self.current_function.take();
            self.current_function = Some(func);

            syn::visit::visit_trait_item_fn(self, node);

            if let Some(func) = self.current_function.take() {
                self.functions.push(func);
            }
            self.current_function = prev;
        } else {
            syn::visit::visit_trait_item_fn(self, node);
        }
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(ref mut func) = self.current_function {
            let segments: Vec<String> =
                node.path.segments.iter().map(|s| s.ident.to_string()).collect();

            if !segments.is_empty() {
                func.calls.push(CallSite {
                    segments,
                    line: node
                        .path
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().line)
                        .unwrap_or(0),
                    col: node
                        .path
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().column)
                        .unwrap_or(0),
                    kind: CallKind::FunctionCall,
                });
            }
        }

        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some(ref mut func) = self.current_function {
            func.calls.push(CallSite {
                segments: vec![node.method.to_string()],
                line: node.method.span().start().line,
                col: node.method.span().start().column,
                kind: CallKind::MethodCall {
                    method: node.method.to_string(),
                },
            });
        }

        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&node.tree, &mut Vec::new(), &mut paths);
        self.imports.extend(paths);

        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let functions: Vec<String> = node
            .items
            .iter()
            .filter_map(|item| {
                if let syn::ForeignItem::Fn(f) = item {
                    Some(f.sig.ident.to_string())
                } else {
                    None
                }
            })
            .collect();

        self.extern_blocks.push(ExternBlock {
            abi: node.abi.name.as_ref().map(|n| n.value()),
            functions,
            line: node.abi.extern_token.span.start().line,
        });

        syn::visit::visit_item_foreign_mod(self, node);
    }
}

fn collect_use_paths(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<ImportPath>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            collect_use_paths(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let mut segments = prefix.clone();
            segments.push(n.ident.to_string());
            out.push(ImportPath {
                segments,
                alias: None,
            });
        }
        syn::UseTree::Rename(r) => {
            let mut segments = prefix.clone();
            segments.push(r.ident.to_string());
            out.push(ImportPath {
                segments,
                alias: Some(r.rename.to_string()),
            });
        }
        syn::UseTree::Group(g) => {
            for item in &g.items {
                collect_use_paths(item, prefix, out);
            }
        }
        syn::UseTree::Glob(_) => {
            let mut segments = prefix.clone();
            segments.push("*".to_string());
            out.push(ImportPath {
                segments,
                alias: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_function_calls() {
        let source = r#"
            use std::fs;
            fn do_stuff() {
                let _ = fs::read("test");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].name, "do_stuff");
        assert!(!parsed.functions[0].calls.is_empty());
    }

    #[test]
    fn parse_use_statements() {
        let source = r#"
            use std::fs::read;
            use std::net::{TcpStream, TcpListener};
            use std::env::var as get_env;
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.use_imports.len(), 4);

        let read_import = &parsed.use_imports[0];
        assert_eq!(read_import.segments, vec!["std", "fs", "read"]);
        assert!(read_import.alias.is_none());

        let alias_import = parsed.use_imports.iter().find(|i| i.alias.is_some()).unwrap();
        assert_eq!(alias_import.segments, vec!["std", "env", "var"]);
        assert_eq!(alias_import.alias.as_deref(), Some("get_env"));
    }

    #[test]
    fn parse_method_calls() {
        let source = r#"
            fn network() {
                let stream = something();
                stream.connect("127.0.0.1:8080");
                stream.send_to(b"data", "addr");
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        let func = &parsed.functions[0];
        let method_calls: Vec<&CallSite> = func
            .calls
            .iter()
            .filter(|c| matches!(c.kind, CallKind::MethodCall { .. }))
            .collect();
        assert_eq!(method_calls.len(), 2);
    }

    #[test]
    fn parse_extern_blocks() {
        let source = r#"
            extern "C" {
                fn open(path: *const u8, flags: i32) -> i32;
                fn close(fd: i32) -> i32;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.extern_blocks.len(), 1);
        assert_eq!(parsed.extern_blocks[0].abi.as_deref(), Some("C"));
        assert_eq!(parsed.extern_blocks[0].functions, vec!["open", "close"]);
    }

    #[test]
    fn parse_error_returns_err() {
        let source = "this is not valid rust {{{";
        assert!(parse_source(source, "bad.rs").is_err());
    }

    #[test]
    fn parse_impl_block_methods() {
        let source = r#"
            use std::fs;
            struct Loader;
            impl Loader {
                fn load(&self) -> Vec<u8> {
                    fs::read("data.bin").unwrap()
                }
                fn name(&self) -> &str {
                    "loader"
                }
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        assert_eq!(parsed.functions.len(), 2);
        let load = parsed.functions.iter().find(|f| f.name == "load").unwrap();
        assert!(!load.calls.is_empty());
    }

    #[test]
    fn parse_trait_default_methods() {
        let source = r#"
            use std::fs;
            trait Readable {
                fn read_data(&self) -> Vec<u8> {
                    fs::read("default.dat").unwrap()
                }
                fn name(&self) -> &str;
            }
        "#;
        let parsed = parse_source(source, "test.rs").unwrap();
        // Only the default method with a body should be captured
        assert_eq!(parsed.functions.len(), 1);
        assert_eq!(parsed.functions[0].name, "read_data");
    }
}
