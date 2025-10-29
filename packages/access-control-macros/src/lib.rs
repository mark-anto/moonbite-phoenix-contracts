//! Proc macros:
//! - #[access_control] on an `impl` block (or inline `mod`):
//!     * Instruments methods marked with #[authorized_by(...)] by injecting guards
//!       directly into their bodies, and removes the attribute so it isn't forwarded.
//!     * Emits compile errors if any public-ish fn is missing #[no_access_control]
//!       or #[authorized_by(...)].
//! - #[no_access_control] on a function: marker (no-op).
//! - #[authorized_by(arg_ident, check_fn_or_path)] on a function:
//!     * If applied directly to a function/impl method, injects the guard.
//!     * If it lands on a generated wrapper or non-function item, it no-ops (warns at most).

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Attribute, FnArg, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, ItemMod, Meta, Pat, Path,
    Token, Visibility,
};

use proc_macro_error::{
    abort, abort_if_dirty, emit_error, emit_warning, proc_macro_error,
};

fn has_no_access_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("no_access_control"))
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn no_access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

struct AuthorizedArgs {
    arg: syn::Ident,
    check_fn: Path,
}
impl Parse for AuthorizedArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let arg: syn::Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let check_fn: Path = input.parse()?;
        Ok(Self { arg, check_fn })
    }
}

fn ident_eq(a: &syn::Ident, b: &syn::Ident) -> bool {
    a.to_string() == b.to_string()
}

fn param_exists(sig: &syn::Signature, want: &syn::Ident) -> bool {
    sig.inputs.iter().any(|arg| match arg {
        FnArg::Typed(pat_ty) => {
            if let Pat::Ident(p) = &*pat_ty.pat {
                ident_eq(&p.ident, want)
            } else {
                false
            }
        }
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

fn instrument_block(
    body: &syn::Block,
    call_path: TokenStream2,
    env_ident: &syn::Ident,
    arg_ident: &syn::Ident,
    span: Span,
) -> Box<syn::Block> {
    syn::parse_quote_spanned! { span =>
        {
            if !(#call_path(&#env_ident, &#arg_ident)) {
                ::core::panic!(concat!(
                    "unauthorized: ",
                    stringify!(#call_path),
                    "(env,",
                    stringify!(#arg_ident),
                    ") failed"
                ));
            }
            #arg_ident.require_auth();
            #body
        }
    }
}

fn take_authorized_args(attrs: &mut Vec<Attribute>) -> Option<AuthorizedArgs> {
    let idx = attrs.iter().position(|a| a.path().is_ident("authorized_by"))?;
    let attr = attrs.remove(idx);
    match attr.meta {
        Meta::List(_) => match attr.parse_args::<AuthorizedArgs>() {
            Ok(a) => Some(a),
            Err(e) => {
                emit_error!(attr.span(), "malformed #[authorized_by(...)] args: {}", e);
                None
            }
        },
        _ => {
            emit_error!(
                attr.span(),
                "#[authorized_by] must be written as #[authorized_by(arg_ident, path)]"
            );
            None
        }
    }
}

fn try_instrument_method(m: &mut ImplItemFn, args: &AuthorizedArgs) -> Option<()> {
    if !param_exists(&m.sig, &args.arg) {
        emit_warning!(
            args.arg.span(),
            "skipping #[authorized_by]: parameter `{}` not found on `{}` (generated wrapper?)",
            args.arg,
            m.sig.ident
        );
        return None;
    }
    let env_ident = match find_param_ident(&m.sig, "env") {
        Some(id) => id,
        None => {
            emit_warning!(
                m.sig.span(),
                "skipping #[authorized_by]: no `env` parameter found on `{}`; leaving unchanged",
                m.sig.ident
            );
            return None;
        }
    };
    let call_path = if args.check_fn.segments.len() == 1 {
        let ident = &args.check_fn.segments[0].ident;
        quote! { Self::#ident }
    } else {
        let p = &args.check_fn;
        quote! { #p }
    };
    let arg = &args.arg;
    let body = &m.block;
    m.block = *instrument_block(body, call_path, &env_ident, arg, m.sig.span());
    Some(())
}

fn try_instrument_free_fn(f: &mut ItemFn, args: &AuthorizedArgs) -> Option<()> {
    if !param_exists(&f.sig, &args.arg) {
        emit_warning!(
            args.arg.span(),
            "skipping #[authorized_by]: parameter `{}` not found on function `{}`",
            args.arg,
            f.sig.ident
        );
        return None;
    }
    let env_ident = match find_param_ident(&f.sig, "env") {
        Some(id) => id,
        None => {
            emit_warning!(
                f.sig.span(),
                "skipping #[authorized_by]: no `env` parameter found on `{}`; leaving unchanged",
                f.sig.ident
            );
            return None;
        }
    };
    let call_path = {
        let p = &args.check_fn;
        quote! { #p }
    };
    let arg = &args.arg;
    let body = &f.block;
    f.block = instrument_block(body, call_path, &env_ident, arg, f.sig.span());
    Some(())
}

/// Standalone attribute. Never errors on placement: falls back to no-op
/// so rust-analyzer expansion order doesn't spam diagnostics.
#[proc_macro_error]
#[proc_macro_attribute]
pub fn authorized_by(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse args; if malformed, that's a real error.
    let args = match syn::parse::<AuthorizedArgs>(attr) {
        Ok(a) => a,
        Err(e) => {
            emit_error!(e.span(), "malformed #[authorized_by(..)]: {}", e);
            return item;
        }
    };

    // Case 1: method inside an `impl`
    if let Ok(mut m) = syn::parse::<ImplItemFn>(item.clone()) {
        // only instrument if both `env` and requested param exist
        if let Some(env_ident) = find_param_ident(&m.sig, "env") {
            if param_exists(&m.sig, &args.arg) {
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
            } else {
                // param not found – leave unchanged (avoid RA errors)
                emit_warning!(
                    args.arg.span(),
                    "skipping #[authorized_by]: parameter `{}` not found on `{}`; leaving unchanged",
                    args.arg, m.sig.ident
                );
            }
        } else {
            // no `env` – leave unchanged (avoid RA errors)
            emit_warning!(
                m.sig.span(),
                "skipping #[authorized_by]: no `env` parameter on `{}`; leaving unchanged",
                m.sig.ident
            );
        }
        return TokenStream::from(quote!(#m));
    }

    // Case 2: free function
    if let Ok(mut f) = syn::parse::<ItemFn>(item.clone()) {
        if let Some(env_ident) = find_param_ident(&f.sig, "env") {
            if param_exists(&f.sig, &args.arg) {
                let call_path = { let p = &args.check_fn; quote! { #p } };
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
            } else {
                emit_warning!(
                    args.arg.span(),
                    "skipping #[authorized_by]: parameter `{}` not found on function `{}`; leaving unchanged",
                    args.arg, f.sig.ident
                );
            }
        } else {
            emit_warning!(
                f.sig.span(),
                "skipping #[authorized_by]: no `env` parameter on `{}`; leaving unchanged",
                f.sig.ident
            );
        }
        return TokenStream::from(quote!(#f));
    }

    // Not a function/method → just return unchanged (no error).
    item
}

/// Apply to an `impl` block (or inline `mod`).
/// Instruments #[authorized_by(...)] in place and removes the attribute;
/// then enforces that public-ish functions have either #[no_access_control]
/// or #[authorized_by(...)].
#[proc_macro_error]
#[proc_macro_attribute]
pub fn access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // impl block path
    if let Ok(mut impl_block) = syn::parse::<ItemImpl>(item.clone()) {
        for it in &mut impl_block.items {
            if let ImplItem::Fn(m) = it {
                // instrument & strip #[authorized_by(...)] if present
                let mut had_authorized = false;
                if let Some(args) = take_authorized_args(&mut m.attrs) {
                    if try_instrument_method(m, &args).is_some() {
                        had_authorized = true;
                    }
                }

                let is_trait_impl = impl_block.trait_.is_some();
                let has_contractimpl_attr = impl_block
                    .attrs
                    .iter()
                    .any(|a| a.path().is_ident("contractimpl"));

                let is_publicish = is_trait_impl
                    || has_contractimpl_attr
                    || !matches!(m.vis, Visibility::Inherited);

                let has_no_access = has_no_access_attr(&m.attrs);

                if is_publicish && !(had_authorized || has_no_access) {
                    emit_error!(
                        m.sig.ident.span(),
                        "public method {} is missing #[no_access_control] or #[authorized_by(...)]",
                        m.sig.ident
                    );
                }
            }
        }
        abort_if_dirty();
        return TokenStream::from(quote!(#impl_block));
    }

    // inline module path
    if let Ok(mut module) = syn::parse::<ItemMod>(item.clone()) {
        if let Some((_, items)) = &mut module.content {
            for it in items {
                if let Item::Fn(f) = it {
                    let mut f = f;
                    let mut had_authorized = false;

                    let mut attrs = std::mem::take(&mut f.attrs);
                    if let Some(args) = take_authorized_args(&mut attrs) {
                        if try_instrument_free_fn(&mut f, &args).is_some() {
                            had_authorized = true;
                        }
                    }
                    f.attrs = attrs;

                    let is_publicish = !matches!(f.vis, Visibility::Inherited);
                    let has_no_access = has_no_access_attr(&f.attrs);

                    if is_publicish && !(had_authorized || has_no_access) {
                        emit_error!(
                            f.sig.ident.span(),
                            "public function {} is missing #[no_access_control] or #[authorized_by(...)]",
                            f.sig.ident
                        );
                    }
                }
            }
            abort_if_dirty();
            return TokenStream::from(quote!(#module));
        }

        abort!(
            module.ident.span(),
            "#[access_control] cannot be used on external modules; \
             use it on an `impl` block or an inline `mod`."
        );
    }

    abort!(
        Span::call_site(),
        "#[access_control] must be placed on an `impl` block or an inline `mod`."
    );
}
