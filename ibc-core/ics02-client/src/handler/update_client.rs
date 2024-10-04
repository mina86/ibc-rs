//! Protocol logic specific to processing ICS2 messages of type `MsgUpdateAnyClient`.

use ibc_core_client_context::prelude::*;
use ibc_core_client_types::error::ClientError;
use ibc_core_client_types::events::{ClientMisbehaviour, UpdateClient};
use ibc_core_client_types::msgs::MsgUpdateOrMisbehaviour;
use ibc_core_client_types::UpdateKind;
use ibc_core_handler_types::error::ContextError;
use ibc_core_handler_types::events::{IbcEvent, MessageEvent};
use ibc_core_host::{ExecutionContext, ValidationContext};
use ibc_primitives::prelude::*;

pub fn validate<Ctx>(
    ctx: &Ctx,
    msg: MsgUpdateOrMisbehaviour,
    header: Option<ibc_client_tendermint_types::Header>,
) -> Result<(), ContextError>
where
    Ctx: ValidationContext,
{
    ctx.validate_message_signer(msg.signer())?;

    let client_id = msg.client_id().clone();

    let client_val_ctx = ctx.get_client_validation_context();

    // Read client state from the host chain store. The client should already exist.
    let client_state = client_val_ctx.client_state(&client_id)?;

    client_state
        .status(client_val_ctx, &client_id)?
        .verify_is_active()?;

    client_state.verify_tm_client_message(
        client_val_ctx,
        &client_id,
        header,
    )?;

    Ok(())
}

pub fn execute<Ctx>(
    ctx: &mut Ctx,
    msg: MsgUpdateOrMisbehaviour,
    header: Option<ibc_client_tendermint_types::Header>,
) -> Result<(), ContextError>
where
    Ctx: ExecutionContext,
{
    let client_id = msg.client_id().clone();
    let update_kind = match msg {
        MsgUpdateOrMisbehaviour::UpdateClient(_) => UpdateKind::UpdateClient,
        MsgUpdateOrMisbehaviour::Misbehaviour(_) => UpdateKind::SubmitMisbehaviour,
    };
    let client_message = msg.client_message();

    let client_exec_ctx = ctx.get_client_execution_context();

    let client_state = client_exec_ctx.client_state(&client_id)?;

    let found_misbehaviour = client_state.check_for_tm_misbehaviour(
        client_exec_ctx,
        &client_id,
        header.clone(),
    )?;

    if found_misbehaviour {
        // the client message is not deserialized so
        // there is no need of having another method
        // for tendermint client state.
        client_state.update_state_on_misbehaviour(
            client_exec_ctx,
            &client_id,
            client_message,
        )?;

        let event = IbcEvent::ClientMisbehaviour(ClientMisbehaviour::new(
            client_id,
            client_state.client_type(),
        ));
        ctx.emit_ibc_event(IbcEvent::Message(MessageEvent::Client))?;
        ctx.emit_ibc_event(event)?;
    } else {
        if !matches!(update_kind, UpdateKind::UpdateClient) {
            return Err(ClientError::MisbehaviourHandlingFailure {
                reason: "misbehaviour submitted, but none found".to_string(),
            }
            .into());
        }

        let consensus_heights =
            client_state.update_tm_state(ctx.get_client_execution_context(), &client_id, header)?;

        {
            let event = {
                let consensus_height = consensus_heights.first().ok_or(ClientError::Other {
                    description: "client update state returned no updated height".to_string(),
                })?;
                IbcEvent::UpdateClient(UpdateClient::new(
                    client_id,
                    client_state.client_type(),
                    *consensus_height,
                    consensus_heights,
                    Vec::new(),
                ))
            };
            ctx.emit_ibc_event(IbcEvent::Message(MessageEvent::Client))?;
            ctx.emit_ibc_event(event)?;
        }
    }

    Ok(())
}
