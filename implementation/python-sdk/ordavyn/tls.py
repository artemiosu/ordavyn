"""Explicit TLS 1.3 configuration; no system roots or insecure contexts."""
import ssl
from dataclasses import dataclass


def _base(protocol):
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    return context


@dataclass(frozen=True)
class ClientTLS:
    ca_pem: str
    server_name: str

    def __post_init__(self):
        if not isinstance(self.server_name, str) or not self.server_name or '\x00' in self.server_name:
            raise ValueError('expected certificate SAN name required')
        self.context()

    def context(self):
        context = _base(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=self.ca_pem)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.hostname_checks_common_name = False
        return context


@dataclass(frozen=True)
class ServerTLS:
    certfile: str
    keyfile: str

    def context(self):
        context = _base(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certfile, self.keyfile)
        return context
