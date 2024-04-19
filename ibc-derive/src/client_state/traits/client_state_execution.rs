use proc_macro2::{Ident, TokenStream};
use quote::{quote, ToTokens};
use syn::punctuated::{Iter, Punctuated};
use syn::token::Comma;
use syn::Variant;

use crate::client_state::Opts;
use crate::utils::{get_enum_variant_type_path, Imports};

pub(crate) fn impl_ClientStateExecution(
    client_state_enum_name: &Ident,
    enum_variants: &Punctuated<Variant, Comma>,
    opts: &Opts,
    imports: &Imports,
) -> TokenStream {
    let initialise_impl = delegate_call_in_match(
        client_state_enum_name,
        enum_variants.iter(),
        opts,
        quote! { initialise(cs, ctx, client_id, consensus_state) },
        imports,
    );
    let update_state_impl = delegate_call_in_match(
        client_state_enum_name,
        enum_variants.iter(),
        opts,
        quote! { update_state(cs, ctx, client_id, header) },
        imports,
    );
    let update_tm_state_impl = delegate_call_in_match(
        client_state_enum_name,
        enum_variants.iter(),
        opts,
        quote! { update_tm_state(cs, ctx, client_id, header) },
        imports,
    );
    let update_state_on_misbehaviour_impl = delegate_call_in_match(
        client_state_enum_name,
        enum_variants.iter(),
        opts,
        quote! { update_state_on_misbehaviour(cs, ctx, client_id, client_message) },
        imports,
    );

    let update_state_with_upgrade_client_impl = delegate_call_in_match(
        client_state_enum_name,
        enum_variants.iter(),
        opts,
        quote! { update_state_on_upgrade(cs, ctx, client_id, upgraded_client_state, upgraded_consensus_state) },
        imports,
    );

    // The imports we need for the generated code.
    let Any = imports.any();
    let ClientId = imports.client_id();
    let ClientError = imports.client_error();
    let ClientStateExecution = imports.client_state_execution();
    let Height = imports.height();
    let TMHeader = imports.tm_header();

    // The types we need for the generated code.
    let HostClientState = client_state_enum_name;
    let ClientExecutionContext = &opts.client_execution_context.clone().into_token_stream();

    // The `impl` block quote based on whether the context includes generics.
    let Impl = opts.client_execution_context.impl_ts();

    // The `Where` clause quote based on whether the generics within the context
    // include trait bounds
    let Where = opts.client_execution_context.where_clause_ts();

    quote! {
        #Impl #ClientStateExecution<#ClientExecutionContext> for #HostClientState #Where {
            fn initialise(
                &self,
                ctx: &mut #ClientExecutionContext,
                client_id: &#ClientId,
                consensus_state: #Any,
            ) -> Result<(), #ClientError> {
                match self {
                    #(#initialise_impl),*
                }
            }

            fn update_state(
                &self,
                ctx: &mut #ClientExecutionContext,
                client_id: &#ClientId,
                header: #Any,
            ) -> core::result::Result<Vec<#Height>, #ClientError> {
                match self {
                    #(#update_state_impl),*
                }
            }

            fn update_tm_state(
                &self,
                ctx: &mut #ClientExecutionContext,
                client_id: &#ClientId,
                header: core::option::Option<#TMHeader>,
            ) -> core::result::Result<Vec<#Height>, #ClientError> {
                match self {
                    #(#update_tm_state_impl),*
                }
            }

            fn update_state_on_misbehaviour(
                &self,
                ctx: &mut #ClientExecutionContext,
                client_id: &#ClientId,
                client_message: #Any,
            ) -> core::result::Result<(), #ClientError> {
                match self {
                    #(#update_state_on_misbehaviour_impl),*
                }
            }

            fn update_state_on_upgrade(
                &self,
                ctx: &mut #ClientExecutionContext,
                client_id: &#ClientId,
                upgraded_client_state: #Any,
                upgraded_consensus_state: #Any,
            ) -> core::result::Result<#Height, #ClientError> {
                match self {
                    #(#update_state_with_upgrade_client_impl),*
                }
            }
        }

    }
}

fn delegate_call_in_match(
    enum_name: &Ident,
    enum_variants: Iter<'_, Variant>,
    opts: &Opts,
    fn_call: TokenStream,
    imports: &Imports,
) -> Vec<TokenStream> {
    let ClientStateExecution = imports.client_state_execution();

    enum_variants
        .map(|variant| {
            let HostClientState = enum_name;
            let Tendermint = &variant.ident;
            let TmClientState = get_enum_variant_type_path(variant);
            let ClientExecutionContext = &opts.client_execution_context;

            // Note: We use `HostClientState` and `Tendermint`, etc as *variable names*. They're
            // only meant to improve readability of the `quote`; it's not literally what's generated!
            quote! {
                #HostClientState::#Tendermint(cs) => <#TmClientState as #ClientStateExecution<#ClientExecutionContext>>::#fn_call
            }
        })
        .collect()
}
