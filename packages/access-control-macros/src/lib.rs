//! Proc macros:
//! - #[access_control] on an `impl` block (or inline `mod`):
//!     Emits compile errors if any public fn is missing #[no_access_control]
//!     or #[authorized_by(...)].
//! - #[no_access_control] on a function:
//!     Marker attribute (no-op) to indicate the fn is allowed.
//! - #[authorized_by(arg_ident, check_fn_or_path)] on a function:
//!     Injects an authorization guard at the top of the function:
//!       * (Self::)check_fn(&env, &arg) must be true
//!       * arg.require_auth()

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Attribute, FnArg, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, ItemMod, Pat, Path, Token,
    Visibility,
};

use proc_macro_error::{abort, abort_if_dirty, emit_error, proc_macro_error};

/// Returns true if the attribute list contains either `no_access_control` or `authorized_by`.
fn has_access_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let p = a.path();
        p.is_ident("no_access_control") || p.is_ident("authorized_by")
    })
}

/// Marker attribute for functions that are allowed (no-op).
#[proc_macro_error]
#[proc_macro_attribute]
pub fn no_access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// Args for #[authorized_by(arg_ident, check_fn_or_path)]
struct AuthorizedArgs {
    arg: syn::Ident,
    check_fn: Path, // e.g., is_owner  OR  crate::auth::is_owner
}

impl Parse for AuthorizedArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let arg: syn::Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let check_fn: Path = input.parse()?;
        Ok(Self { arg, check_fn })
    }
}

fn param_exists(sig: &syn::Signature, want: &syn::Ident) -> bool {
    sig.inputs.iter().any(|arg| match arg {
        FnArg::Typed(pat_ty) => matches!(&*pat_ty.pat, Pat::Ident(p) if p.ident == *want),
        FnArg::Receiver(_) => false,
    })
}

fn find_param_ident(sig: &syn::Signature, name: &str) -> Option<syn::Ident> {
    for arg in &sig.inputs {
        if let FnArg::Typed(pat_ty) = arg {
            if let Pat::Ident(pat) = &*pat_ty.pat {
                if pat.ident == name {
                    return Some(pat.ident.clone());
                }
            }
        }
    }
    None
}

/// Injects an authorization guard at the top of the function body:
///   if !(call_path(&env, &arg)) { panic!(...); }
///   arg.require_auth();
#[proc_macro_error]
#[proc_macro_attribute]
pub fn authorized_by(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match syn::parse::<AuthorizedArgs>(attr) {
        Ok(a) => a,
        Err(e) => abort!(e.span(), "{}", e),
    };

    // Case 1: method inside an `impl`
    if let Ok(mut m) = syn::parse::<ImplItemFn>(item.clone()) {
        if !param_exists(&m.sig, &args.arg) {
            emit_error!(
                args.arg.span(),
                "#[authorized_by] references parameter `{}` that does not exist",
                args.arg
            );
            abort_if_dirty(); // // if any emit_error! happened above, stop here
        }

        let env_ident = match find_param_ident(&m.sig, "env") {
            Some(id) => id,
            None => abort!(
                m.sig.span(),
                "#[authorized_by] needs a parameter named `env` (first argument of your method)"
            ),
        };

        // If the check path is a single ident, call as `Self::ident`; otherwise use the full path.
        let call_path = if args.check_fn.segments.len() == 1 {
            let ident = &args.check_fn.segments[0].ident;
            quote! { Self::#ident }
        } else {
            let p = &args.check_fn;
            quote! { #p }
        };

        let arg = &args.arg;
        let body = &m.block;

        m.block = syn::parse_quote_spanned! { m.sig.span()=>
            {
                if !(#call_path(&#env_ident, &#arg)) {
                    ::core::panic!(concat!(
                        "unauthorized: ",
                        stringify!(#call_path),
                        "(env,",
                        stringify!(#arg),
                        ") failed"
                    ));
                }
                #arg.require_auth();
                #body
            }
        };

        return TokenStream::from(quote!(#m));
    }

    // Case 2: free function (e.g., inside an inline `mod`)
    if let Ok(mut f) = syn::parse::<ItemFn>(item.clone()) {
        if !param_exists(&f.sig, &args.arg) {
            emit_error!(
                args.arg.span(),
                "#[authorized_by] references parameter `{}` that does not exist",
                args.arg
            );
            abort_if_dirty(); // ← function call
        }

        let env_ident = match find_param_ident(&f.sig, "env") {
            Some(id) => id,
            None => abort!(
                f.sig.span(),
                "#[authorized_by] needs a parameter named `env` (first argument of your function)"
            ),
        };

        let call_path = &args.check_fn; // free function: use as-is
        let arg = &args.arg;
        let body = &f.block;

        f.block = syn::parse_quote_spanned! { f.sig.span()=>
            {
                if !(#call_path(&#env_ident, &#arg)) {
                    ::core::panic!(concat!(
                        "unauthorized: ",
                        stringify!(#call_path),
                        "(env,",
                        stringify!(#arg),
                        ") failed"
                    ));
                }
                #arg.require_auth();
                #body
            }
        };

        return TokenStream::from(quote!(#f));
    }

    // Wrong placement
    abort!(
        Span::call_site(),
        "#[authorized_by] must be placed on a function or an `impl` method."
    );
}

/// Place on an `impl` block (or inline `mod`). Errors if any public `fn`
/// lacks #[no_access_control] or #[authorized_by(...)].
#[proc_macro_error]
#[proc_macro_attribute]
pub fn access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Try `impl` first
    if let Ok(impl_block) = syn::parse::<ItemImpl>(item.clone()) {
        for it in &impl_block.items {
            if let ImplItem::Fn(m) = it {
                // Consider anything not-private as requiring the marker:
                // (pub, pub(crate), pub(super), pub(in ...))
                let is_trait_impl = impl_block.trait_.is_some();
                let has_contractimpl_attr = impl_block
                    .attrs
                    .iter()
                    .any(|a| a.path().is_ident("contractimpl"));

                let is_publicish = is_trait_impl
                    || has_contractimpl_attr
                    || !matches!(m.vis, syn::Visibility::Inherited);

                if is_publicish && !has_access_attr(&m.attrs) {
                    emit_error!(
                        m.sig.ident.span(),
                        "public method {} is missing #[no_access_control] or #[authorized_by(...)]",
                        m.sig.ident
                    );
                }
            }
        }
        abort_if_dirty(); // ← function call
        return item;
    }

    // Also support inline modules: `#[access_control] mod m { pub fn ... }`
    if let Ok(module) = syn::parse::<ItemMod>(item.clone()) {
        if let Some((_, items)) = &module.content {
            for it in items {
                if let Item::Fn(f) = it {
                    let is_publicish = !matches!(f.vis, Visibility::Inherited);
                    if is_publicish && !has_access_attr(&f.attrs) {
                        emit_error!(
                            f.sig.ident.span(),
                            "public function {} is missing #[no_access_control] or #[authorized_by(...)]",
                            f.sig.ident
                        );
                    }
                }
            }
            abort_if_dirty(); // ← function call
            return item;
        }

        // @todo Add a test for this particular case
        // External module: we cannot inspect; hard error
        abort!(
            module.ident.span(),
            "#[access_control] cannot be used on external modules; \
                use it on an `impl` block or an inline `mod`."
        );
        // return item;
    }

    // Wrong placement
    abort!(
        Span::call_site(),
        "#[access_control] must be placed on an `impl` block or an inline `mod`."
    );
}
