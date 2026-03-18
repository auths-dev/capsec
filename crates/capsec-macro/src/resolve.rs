//! Maps shorthand capability paths to full permission type token streams.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Meta;

/// Resolves a macro attribute meta to a fully qualified permission type.
///
/// Supports both shorthand (`fs::read`) and explicit (`FsRead`) forms.
pub fn meta_to_permission_type(meta: &Meta) -> Result<TokenStream, syn::Error> {
    let path_str = meta
        .path()
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");

    match path_str.as_str() {
        "fs::read" | "FsRead" => Ok(quote! { capsec_core::permission::FsRead }),
        "fs::write" | "FsWrite" => Ok(quote! { capsec_core::permission::FsWrite }),
        "fs::all" | "FsAll" => Ok(quote! { capsec_core::permission::FsAll }),
        "net::connect" | "NetConnect" => Ok(quote! { capsec_core::permission::NetConnect }),
        "net::bind" | "NetBind" => Ok(quote! { capsec_core::permission::NetBind }),
        "net::all" | "NetAll" => Ok(quote! { capsec_core::permission::NetAll }),
        "env::read" | "EnvRead" => Ok(quote! { capsec_core::permission::EnvRead }),
        "env::write" | "EnvWrite" => Ok(quote! { capsec_core::permission::EnvWrite }),
        "spawn" | "Spawn" => Ok(quote! { capsec_core::permission::Spawn }),
        "all" | "Ambient" => Ok(quote! { capsec_core::permission::Ambient }),
        _ => Err(syn::Error::new_spanned(
            meta.path(),
            format!(
                "Unknown capsec permission: `{path_str}`. Expected one of: fs::read, fs::write, fs::all, net::connect, net::bind, net::all, env::read, env::write, spawn, all"
            ),
        )),
    }
}
