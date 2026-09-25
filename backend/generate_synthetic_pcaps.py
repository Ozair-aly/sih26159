from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, Raw, wrpcap


OUTPUT_DIR = Path(__file__).resolve().parents[1] / "synthetic_pcaps"


def server_hello(version, cipher_id):
    body = version.to_bytes(2, "big") + bytes(range(32)) + b"\x00" + cipher_id.to_bytes(2, "big") + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16" + version.to_bytes(2, "big") + len(handshake).to_bytes(2, "big") + handshake
    return record


def certificate_handshake(der):
    certificate_list = len(der).to_bytes(3, "big") + der
    body = len(certificate_list).to_bytes(3, "big") + certificate_list
    handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def make_certificate(days_from_now, key_size=2048, algorithm=hashes.SHA256()):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.synthetic.local")])
    now = datetime.now(timezone.utc)
    not_valid_before = now - timedelta(days=1) if days_from_now >= 0 else now - timedelta(days=365)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(now + timedelta(days=days_from_now))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, algorithm)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def tcp_stream(source, destination, source_port, destination_port, payload, prefix=b""):
    client_payload = prefix + payload if prefix else b""
    packets = []
    if client_payload:
        packets.append(IP(src=source, dst=destination) / TCP(sport=source_port, dport=destination_port, flags="PA", seq=1, ack=1) / Raw(load=client_payload))
    packets.append(IP(src=destination, dst=source) / TCP(sport=destination_port, dport=source_port, flags="PA", seq=900, ack=1) / Raw(load=payload))
    return packets


def tls_stream(source, destination, source_port, destination_port, version, cipher_id, certificate=None, prefix=b""):
    payload = server_hello(version, cipher_id)
    if certificate:
        payload += certificate_handshake(certificate)
    return tcp_stream(source, destination, source_port, destination_port, payload, prefix=prefix)


def write_capture(name, packets):
    path = OUTPUT_DIR / name
    wrpcap(str(path), packets)
    print(f"{path} ({path.stat().st_size} bytes)")


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    legacy_tls = tls_stream(
        "10.10.0.10",
        "10.10.0.20",
        41000,
        25,
        0x0301,
        0x000A,
    )
    write_capture("synthetic_legacy_tls_3des.pcap", legacy_tls)

    plaintext = tcp_stream(
        "10.10.1.10",
        "10.10.1.20",
        42000,
        25,
        b"EHLO workstation.example\r\nAUTH LOGIN dXNlcg== cGFzcw==\r\nMAIL FROM:<user@example>\r\n",
    )
    write_capture("synthetic_plaintext_smtp_auth.pcap", plaintext)

    rsa_tls = tls_stream(
        "10.10.2.10",
        "10.10.2.20",
        43000,
        993,
        0x0303,
        0x009C,
    )
    write_capture("synthetic_tls12_rsa_no_forward_secrecy.pcap", rsa_tls)

    ecdhe_tls = tls_stream(
        "10.10.3.10",
        "10.10.3.20",
        44000,
        993,
        0x0303,
        0xC02F,
    )
    write_capture("synthetic_tls12_ecdhe_secure.pcap", ecdhe_tls)

    tls13 = tls_stream(
        "10.10.4.10",
        "10.10.4.20",
        45000,
        993,
        0x0304,
        0x1301,
    )
    write_capture("synthetic_tls13_secure.pcap", tls13)

    starttls = tls_stream(
        "10.10.5.10",
        "10.10.5.20",
        46000,
        587,
        0x0303,
        0xC02F,
        prefix=b"EHLO workstation.synthetic\r\nSTARTTLS\r\n",
    )
    write_capture("synthetic_smtp_starttls_secure.pcap", starttls)

    expired_weak_certificate = make_certificate(-30, key_size=1024)
    expired_tls = tls_stream(
        "10.10.6.10",
        "10.10.6.20",
        47000,
        993,
        0x0301,
        0x000A,
        certificate=expired_weak_certificate,
    )
    write_capture("synthetic_expired_weak_certificate.pcap", expired_tls)

    secure_tls = tls_stream(
        "10.10.2.10",
        "10.10.2.20",
        43000,
        993,
        0x0303,
        0xC02F,
    )
    mixed = legacy_tls + plaintext + rsa_tls + ecdhe_tls + tls13 + starttls + expired_tls
    write_capture("synthetic_comprehensive_email_posture.pcap", mixed)


if __name__ == "__main__":
    main()