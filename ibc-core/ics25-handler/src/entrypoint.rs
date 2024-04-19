use ibc_core_channel::handler::{
    acknowledgement_packet_execute, acknowledgement_packet_validate, chan_close_confirm_execute,
    chan_close_confirm_validate, chan_close_init_execute, chan_close_init_validate,
    chan_open_ack_execute, chan_open_ack_validate, chan_open_confirm_execute,
    chan_open_confirm_validate, chan_open_init_execute, chan_open_init_validate,
    chan_open_try_execute, chan_open_try_validate, recv_packet_execute, recv_packet_validate,
    timeout_packet_execute, timeout_packet_validate, TimeoutMsgType,
};
use ibc_core_channel::types::msgs::{
    channel_msg_to_port_id, packet_msg_to_port_id, ChannelMsg, PacketMsg,
};
use ibc_core_client::handler::{create_client, update_client, upgrade_client};
use ibc_core_client::types::msgs::{ClientMsg, MsgUpdateOrMisbehaviour};
use ibc_core_connection::handler::{
    conn_open_ack, conn_open_confirm, conn_open_init, conn_open_try,
};
use ibc_core_connection::types::msgs::ConnectionMsg;
use ibc_core_handler_types::error::ContextError;
use ibc_core_handler_types::msgs::MsgEnvelope;
use ibc_core_host::{ExecutionContext, ValidationContext};
use ibc_core_router::router::Router;
use ibc_core_router::types::error::RouterError;

/// Entrypoint which performs both validation and message execution
pub fn dispatch(
    ctx: &mut impl ExecutionContext,
    router: &mut impl Router,
    msg: MsgEnvelope,
) -> Result<(), ContextError> {

    if matches!(msg, MsgEnvelope::Client(ClientMsg::UpdateClient(_))) {
        let header = match msg {
            MsgEnvelope::Client(ref msg) => match msg {
                ClientMsg::UpdateClient(msg) => msg,
                _ => panic!("Invalid message type"),
            },
            _ => panic!("Invalid message type"),
        };
        let header = ibc_client_tendermint_types::Header::try_from(header.clone().client_message).unwrap();
        validate(ctx, router, msg.clone(), Some(header.clone()))?;
        // solana_program::msg!("Before execute");
        // solana_program::log::sol_log_compute_units();
        execute(ctx, router, msg, Some(header))?;
        // solana_program::log::sol_log_compute_units();
        // solana_program::msg!("After execute");
    } else {
        validate(ctx, router, msg.clone(), None)?;
        execute(ctx, router, msg, None)?;
    }
    
    Ok(())
}

/// Entrypoint which only performs message validation
///
/// If a transaction contains `n` messages `m_1` ... `m_n`, then
/// they MUST be processed as follows:
///     validate(m_1), execute(m_1), ..., validate(m_n), execute(m_n)
/// That is, the state transition of message `i` must be applied before
/// message `i+1` is validated. This is equivalent to calling
/// `dispatch()` on each successively.
pub fn validate<Ctx>(ctx: &Ctx, router: &impl Router, msg: MsgEnvelope, header: Option<ibc_client_tendermint_types::Header>) -> Result<(), ContextError>
where
    Ctx: ValidationContext,
{
    match msg {
        MsgEnvelope::Client(msg) => match msg {
            ClientMsg::CreateClient(msg) => create_client::validate(ctx, msg),
            ClientMsg::UpdateClient(msg) => {
                update_client::validate(ctx, MsgUpdateOrMisbehaviour::UpdateClient(msg), header)
            }
            ClientMsg::Misbehaviour(msg) => {
                update_client::validate(ctx, MsgUpdateOrMisbehaviour::Misbehaviour(msg), header)
            }
            ClientMsg::UpgradeClient(msg) => upgrade_client::validate(ctx, msg),
        },
        MsgEnvelope::Connection(msg) => match msg {
            ConnectionMsg::OpenInit(msg) => conn_open_init::validate(ctx, msg),
            ConnectionMsg::OpenTry(msg) => conn_open_try::validate(ctx, msg),
            ConnectionMsg::OpenAck(msg) => conn_open_ack::validate(ctx, msg),
            ConnectionMsg::OpenConfirm(ref msg) => conn_open_confirm::validate(ctx, msg),
        },
        MsgEnvelope::Channel(msg) => {
            let port_id = channel_msg_to_port_id(&msg);
            let module_id = router
                .lookup_module(port_id)
                .ok_or(RouterError::UnknownPort {
                    port_id: port_id.clone(),
                })?;
            let module = router
                .get_route(&module_id)
                .ok_or(RouterError::ModuleNotFound)?;

            match msg {
                ChannelMsg::OpenInit(msg) => chan_open_init_validate(ctx, module, msg),
                ChannelMsg::OpenTry(msg) => chan_open_try_validate(ctx, module, msg),
                ChannelMsg::OpenAck(msg) => chan_open_ack_validate(ctx, module, msg),
                ChannelMsg::OpenConfirm(msg) => chan_open_confirm_validate(ctx, module, msg),
                ChannelMsg::CloseInit(msg) => chan_close_init_validate(ctx, module, msg),
                ChannelMsg::CloseConfirm(msg) => chan_close_confirm_validate(ctx, module, msg),
            }
        }
        MsgEnvelope::Packet(msg) => {
            let port_id = packet_msg_to_port_id(&msg);
            let module_id = router
                .lookup_module(port_id)
                .ok_or(RouterError::UnknownPort {
                    port_id: port_id.clone(),
                })?;
            let module = router
                .get_route(&module_id)
                .ok_or(RouterError::ModuleNotFound)?;

            match msg {
                PacketMsg::Recv(msg) => recv_packet_validate(ctx, msg),
                PacketMsg::Ack(msg) => acknowledgement_packet_validate(ctx, module, msg),
                PacketMsg::Timeout(msg) => {
                    timeout_packet_validate(ctx, module, TimeoutMsgType::Timeout(msg))
                }
                PacketMsg::TimeoutOnClose(msg) => {
                    timeout_packet_validate(ctx, module, TimeoutMsgType::TimeoutOnClose(msg))
                }
            }
        }
    }
}

/// Entrypoint which only performs message execution
pub fn execute<Ctx>(
    ctx: &mut Ctx,
    router: &mut impl Router,
    msg: MsgEnvelope,
    header: Option<ibc_client_tendermint_types::Header>
) -> Result<(), ContextError>
where
    Ctx: ExecutionContext,
{
    match msg {
        MsgEnvelope::Client(msg) => match msg {
            ClientMsg::CreateClient(msg) => create_client::execute(ctx, msg),
            ClientMsg::UpdateClient(msg) => {
                update_client::execute(ctx, MsgUpdateOrMisbehaviour::UpdateClient(msg), header)
            }
            ClientMsg::Misbehaviour(msg) => {
                update_client::execute(ctx, MsgUpdateOrMisbehaviour::Misbehaviour(msg), header)
            }
            ClientMsg::UpgradeClient(msg) => upgrade_client::execute(ctx, msg),
        },
        MsgEnvelope::Connection(msg) => match msg {
            ConnectionMsg::OpenInit(msg) => conn_open_init::execute(ctx, msg),
            ConnectionMsg::OpenTry(msg) => conn_open_try::execute(ctx, msg),
            ConnectionMsg::OpenAck(msg) => conn_open_ack::execute(ctx, msg),
            ConnectionMsg::OpenConfirm(ref msg) => conn_open_confirm::execute(ctx, msg),
        },
        MsgEnvelope::Channel(msg) => {
            let port_id = channel_msg_to_port_id(&msg);
            let module_id = router
                .lookup_module(port_id)
                .ok_or(RouterError::UnknownPort {
                    port_id: port_id.clone(),
                })?;
            let module = router
                .get_route_mut(&module_id)
                .ok_or(RouterError::ModuleNotFound)?;

            match msg {
                ChannelMsg::OpenInit(msg) => chan_open_init_execute(ctx, module, msg),
                ChannelMsg::OpenTry(msg) => chan_open_try_execute(ctx, module, msg),
                ChannelMsg::OpenAck(msg) => chan_open_ack_execute(ctx, module, msg),
                ChannelMsg::OpenConfirm(msg) => chan_open_confirm_execute(ctx, module, msg),
                ChannelMsg::CloseInit(msg) => chan_close_init_execute(ctx, module, msg),
                ChannelMsg::CloseConfirm(msg) => chan_close_confirm_execute(ctx, module, msg),
            }
        }
        MsgEnvelope::Packet(msg) => {
            let port_id = packet_msg_to_port_id(&msg);
            let module_id = router
                .lookup_module(port_id)
                .ok_or(RouterError::UnknownPort {
                    port_id: port_id.clone(),
                })?;
            let module = router
                .get_route_mut(&module_id)
                .ok_or(RouterError::ModuleNotFound)?;

            match msg {
                PacketMsg::Recv(msg) => recv_packet_execute(ctx, module, msg),
                PacketMsg::Ack(msg) => acknowledgement_packet_execute(ctx, module, msg),
                PacketMsg::Timeout(msg) => {
                    timeout_packet_execute(ctx, module, TimeoutMsgType::Timeout(msg))
                }
                PacketMsg::TimeoutOnClose(msg) => {
                    timeout_packet_execute(ctx, module, TimeoutMsgType::TimeoutOnClose(msg))
                }
            }
        }
    }
}
