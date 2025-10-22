use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Attribute, Ident, ImplItem, ImplItemFn, ItemImpl, Path, Result, Token,
};

#[derive(Clone)]
struct AuthorizedByArgs {
    subject: Ident,
    checker: Path,
}

impl Parse for AuthorizedByArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let subject: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let checker: Path = input.parse()?;

        Ok(AuthorizedByArgs { subject, checker })
    }
}

#[proc_macro_attribute]
pub fn authorized_by(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as AuthorizedByArgs);
    let subject = args.subject;
    let checker = args.checker;
    let item_tokens = proc_macro2::TokenStream::from(item);

    TokenStream::from(quote! {
        #[phoenix_internal_authorized_by(#subject, #checker)]
        #item_tokens
    })
}

#[proc_macro_attribute]
pub fn no_access_control(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[no_access_control] does not accept arguments",
        )
        .to_compile_error()
        .into();
    }

    let item_tokens = proc_macro2::TokenStream::from(item);
    TokenStream::from(quote! {
        #[phoenix_internal_no_access_control]
        #item_tokens
    })
}

#[proc_macro_attribute]
pub fn with_access_control(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(
            Span::call_site(),
            "#[with_access_control] does not accept arguments",
        )
        .to_compile_error()
        .into();
    }

    let mut item_impl = parse_macro_input!(item as ItemImpl);
    let mut error: Option<syn::Error> = None;

    for impl_item in &mut item_impl.items {
        let ImplItem::Fn(method) = impl_item else {
            continue;
        };
        if !matches!(method.vis, syn::Visibility::Public(_)) {
            continue;
        }

        match extract_access_control(method) {
            Ok(AccessControl::None) => {
                let err = syn::Error::new(
                    method.sig.ident.span(),
                    "Public functions must specify #[authorized_by] or #[no_access_control] when #[with_access_control] is used",
                );
                combine_error(&mut error, err);
            }
            Ok(AccessControl::NoAccessControl) => {}
            Ok(AccessControl::Authorized(args)) => {
                if let Err(err) = inject_authorization(method, &args) {
                    combine_error(&mut error, err);
                }
            }
            Err(err) => combine_error(&mut error, err),
        }
    }

    if let Some(err) = error {
        let mut tokens = item_impl.into_token_stream();
        tokens.extend(err.to_compile_error());
        tokens.into()
    } else {
        TokenStream::from(quote! { #item_impl })
    }
}

enum AccessControl {
    None,
    NoAccessControl,
    Authorized(AuthorizedByArgs),
}

fn extract_access_control(method: &mut ImplItemFn) -> Result<AccessControl> {
    let mut access = AccessControl::None;
    let mut retained = Vec::with_capacity(method.attrs.len());

    for attr in method.attrs.drain(..) {
        if is_authorized_attr(&attr) {
            let args = parse_authorized_args(&attr)?;
            if matches!(access, AccessControl::Authorized(_)) {
                return Err(syn::Error::new(
                    attr.span(),
                    "Multiple #[authorized_by] attributes are not allowed",
                ));
            }
            if matches!(access, AccessControl::NoAccessControl) {
                return Err(syn::Error::new(
                    attr.span(),
                    "Cannot combine #[authorized_by] with #[no_access_control]",
                ));
            }
            access = AccessControl::Authorized(args);
        } else if is_no_access_attr(&attr) {
            if matches!(access, AccessControl::Authorized(_)) {
                return Err(syn::Error::new(
                    attr.span(),
                    "Cannot combine #[authorized_by] with #[no_access_control]",
                ));
            }
            access = AccessControl::NoAccessControl;
        } else {
            retained.push(attr);
        }
    }

    method.attrs = retained;
    Ok(access)
}

fn parse_authorized_args(attr: &Attribute) -> Result<AuthorizedByArgs> {
    let args: AuthorizedByArgs = attr.parse_args()?;
    Ok(args)
}

fn is_authorized_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("authorized_by") || attr.path().is_ident("phoenix_internal_authorized_by")
}

fn is_no_access_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("no_access_control")
        || attr.path().is_ident("phoenix_internal_no_access_control")
}

fn inject_authorization(method: &mut ImplItemFn, args: &AuthorizedByArgs) -> Result<()> {
    let arg_ident = args.subject.clone();
    let method_name = method.sig.ident.clone();

    let has_parameter = method.sig.inputs.iter().any(|input| match input {
        syn::FnArg::Typed(pat_type) => {
            matches!(&*pat_type.pat, syn::Pat::Ident(ident) if ident.ident == arg_ident)
        }
        _ => false,
    });

    if !has_parameter {
        return Err(syn::Error::new(
            arg_ident.span(),
            format!(
                "Function `{}` does not have a parameter named `{}`",
                method_name, arg_ident
            ),
        ));
    }

    let mut checker_path = args.checker.clone();
    if checker_path.leading_colon.is_none() && checker_path.segments.len() == 1 {
        let ident = checker_path.segments.first().unwrap().ident.clone();
        checker_path = syn::parse_quote!(Self::#ident);
    }

    let check_call: syn::Expr = syn::parse_quote! { #checker_path(#arg_ident.clone()) };

    let use_stmt: syn::Stmt = syn::parse_quote! {
        use phoenix::access_control::RequireSignature as _;
    };

    let check_stmt: syn::Stmt = syn::parse_quote! {
        if !#check_call {
            panic!(
                concat!(
                    "Access control check failed for ",
                    stringify!(#method_name),
                    ": ",
                    stringify!(#checker_path),
                    " returned false"
                )
            );
        }
    };

    let require_stmt: syn::Stmt = syn::parse_quote! {
        #arg_ident.require_signature();
    };

    method.block.stmts.insert(0, require_stmt);
    method.block.stmts.insert(0, check_stmt);
    method.block.stmts.insert(0, use_stmt);

    Ok(())
}

fn combine_error(target: &mut Option<syn::Error>, err: syn::Error) {
    if let Some(existing) = target {
        existing.combine(err);
    } else {
        *target = Some(err);
    }
}
