#![cfg(target_os = "solana")]

use tendermint::public_key::PublicKey;
use tendermint::crypto::signature::Error;
use tendermint_light_client_verifier::PredicateVerifier;
use tendermint_light_client_verifier::operations::ProvidedVotingPowerCalculator;
use tendermint_light_client_verifier::operations::commit_validator::ProdCommitValidator;
use tendermint_light_client_verifier::predicates::ProdPredicates;

pub type Verifier = PredicateVerifier<ProdPredicates, VotingPowerCalculator, ProdCommitValidator>;
pub type VotingPowerCalculator = ProvidedVotingPowerCalculator<SigVerifier>;

#[derive(Clone, Debug, PartialEq)]
pub struct SigVerifier;

extern "C" {
    /// Returns global verifier if one has been set.
    ///
    /// This is defined in solana-ibc crate in allocator module.  We’re not
    /// depending on that crate directly due to cyclic dependencies.  This is
    /// a hack but for the time being it’s the best we have.
    fn get_global_ed25519_verifier() -> *const ();
}
impl tendermint::crypto::signature::Verifier for SigVerifier {
    fn verify(pubkey: PublicKey, msg: &[u8], signature: &tendermint::signature::Signature) -> Result<(), Error> {
        let pubkey = if let PublicKey::Ed25519(pubkey) = pubkey {
            pubkey
        } else {
            return Err(Error::UnsupportedKeyType);
        };
        let pubkey = <&sigverify::ed25519::PubKey>::try_from(pubkey.as_bytes())
            .map_err(|_| Error::MalformedPublicKey)?;
        let sig = <&sigverify::ed25519::Signature>::try_from(signature.as_bytes())
            .map_err(|_| Error::MalformedSignature)?;

        // SAFETY: The function is always safe to run and if it returns non-null
        // than it returns a pointer to an object with static lifetime thus it’s
        // always sound to dereference it.
        let verifier: Option<&sigverify::Verifier> = unsafe {
            let ptr = get_global_ed25519_verifier() as *mut ();
            core::ptr::NonNull::new(ptr).map(|ptr| ptr.cast().as_ref())
        };
        match verifier {
            Some(verifier) if verifier.verify(msg, pubkey, sig) => Ok(()),
            _ => Err(Error::VerificationFailed),
        }
    }
}