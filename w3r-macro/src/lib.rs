use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(AdapterDerive)]
pub fn derive_adapter(ts: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(ts).unwrap();
    impl_adapter(ast)
}

fn impl_adapter(input: DeriveInput) -> TokenStream {
    let name = input.ident;
    quote! {
        impl Adapter for #name {}
    }
    .into()
}
