//! Explicit TLS 1.3, SAN verification, local roots and HTTP/1.1 only.
use crate::security::invalid;
use crate::Result;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
};

#[derive(Clone)]
pub struct ClientTls {
    pub(crate) config: Arc<rustls::ClientConfig>,
    pub(crate) name: ServerName<'static>,
}
impl ClientTls {
    pub fn from_pem(ca: &[u8], expected_name: &str) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(ca)) {
            roots
                .add(cert.map_err(|_| invalid("invalid CA PEM"))?)
                .map_err(|_| invalid("invalid CA"))?;
        }
        if roots.is_empty() {
            return Err(invalid("explicit CA required"));
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("TLS versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.enable_early_data = false;
        let name = ServerName::try_from(expected_name.to_owned())
            .map_err(|_| invalid("invalid SAN name"))?;
        Ok(Self {
            config: Arc::new(config),
            name,
        })
    }
}
#[derive(Clone)]
pub struct ServerTls {
    pub(crate) config: Arc<rustls::ServerConfig>,
}
impl ServerTls {
    pub fn from_pem(chain: &[u8], key: &[u8]) -> Result<Self> {
        let certs = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(chain))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid certificate PEM"))?;
        let key = PrivateKeyDer::pem_reader_iter(&mut std::io::Cursor::new(key))
            .next()
            .transpose()
            .map_err(|_| invalid("invalid TLS private key"))?
            .ok_or_else(|| invalid("missing TLS private key"))?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("TLS versions"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| invalid("certificate/key mismatch"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}
