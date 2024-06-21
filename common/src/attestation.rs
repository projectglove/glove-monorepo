use aws_nitro_enclaves_cose::CoseSign1;
use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::error::CoseError;
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::{X509, X509StoreContext, X509VerifyResult};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;

static AWS_NITRO_ROOT_CA_BYTES: &[u8] = include_bytes!("../../assets/aws-nitro-root.pem");

#[derive(Debug, Clone)]
pub enum AttestationInfo {
    Nitro(NitroAttestationInfo),
    Mock
}

#[derive(Debug, Clone)]
pub struct NitroAttestationInfo {
    pub doc: AttestationDoc
}

fn decode_verified_nitro_attestation(bytes: &[u8]) -> Result<NitroAttestationInfo, Error> {
    let cose_sign_1 = serde_cbor::from_slice::<CoseSign1>(bytes)?;
    let encoded_attestation_doc = cose_sign_1.get_payload::<Openssl>(None)?;
    let doc = serde_cbor::from_slice::<AttestationDoc>(&encoded_attestation_doc)?;

    let certificate = X509::from_der(&doc.certificate)?;

    let mut cert_chain = Stack::new()?;
    for ca_cert in &doc.cabundle {
        cert_chain.push(X509::from_der(&ca_cert)?)?;
    }

    // Create the trust store containing the root AWS nitro cert, and also configured to use the
    // timestamp from the attestation document. This is necessary as the attestation certificate
    // only has a 3 hour lifetime, but also, the validity of the entire cert chain only matters
    // within the context of this timestamp. It doesn't matter if any of the certs expire in the
    // future, what matters is they were valid at the time of the attestation.
    let mut trust_store_builder = X509StoreBuilder::new()?;
    let mut verify_params = X509VerifyParam::new()?;
    verify_params.set_time((doc.timestamp / 1000) as i64);
    trust_store_builder.set_param(&verify_params)?;
    trust_store_builder.add_cert(X509::from_pem(AWS_NITRO_ROOT_CA_BYTES)?)?;
    let trust_store = trust_store_builder.build();

    // Verify the cert chain and prove the certicate public key is a valid AWS nitro signing key.
    let mut cert_ctx = X509StoreContext::new()?;
    let valid = cert_ctx.init(&trust_store, &certificate, &cert_chain, |ctx| ctx.verify_cert())?;
    if !valid {
        return Err(cert_ctx.error().into());
    }

    // Verify the signature over the attestation doc with the signing key
    cose_sign_1
        .verify_signature::<Openssl>(certificate.public_key()?.as_ref())?
        .then(|| NitroAttestationInfo { doc })
        .ok_or_else(|| Error::Cose(CoseError::UnverifiedSignature))
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("CBOR decoding error: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("OpenSSL error: {0}")]
    OpenSsl(#[from] ErrorStack),
    #[error("COSE error: {0}")]
    Cose(#[from] CoseError),
    #[error("X.509 verification error: {0}")]
    Verify(#[from] X509VerifyResult),
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use crate::attestation::decode_verified_nitro_attestation;

    #[test]
    fn decode_sample_nitro_attestation_doc() {
        let bytes = fs::read(format!("{}/sample-aws-nitro-attestation-doc", env::var("CARGO_MANIFEST_DIR").unwrap())).unwrap();
        let info = decode_verified_nitro_attestation(&bytes).unwrap();
        println!("{:?}", info);
        assert_eq!(info.doc.pcrs.get(&0).unwrap().to_vec(), hex::decode("dd1c94beae9a589b37f6601ecf73c297ff0bf41a8872f737fabf3c9a2a96eb3b1dcdabc8e33ba1f7654b528518b8b9ed").unwrap());
        assert_eq!(info.doc.pcrs.get(&1).unwrap().to_vec(), hex::decode("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546").unwrap());
        assert_eq!(info.doc.pcrs.get(&2).unwrap().to_vec(), hex::decode("35a4393a77e7f60a9eb28b974b400149e36fe07791a84b3285cb16f3fdeaf7503f98ecdf6cc800d0109166d82fc7052b").unwrap());
        assert_eq!(info.doc.user_data, None);
        assert_eq!(info.doc.public_key, None);
        assert_eq!(info.doc.nonce, None);
    }
}