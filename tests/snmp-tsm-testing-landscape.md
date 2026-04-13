# SNMP TSM Testing Landscape

This document summarises what was learned while attempting to build Behave system tests
for the SNMP Transport Security Model (TSM, RFC 5953 / RFC 6353 / RFC 9456), covering
net-snmp's TSM support, the available test-client options, and the broader adoption
picture.

---

## Background

The agent implements SNMPv3 inbound transport over TLS/TCP (SNMP TSM), as specified in
RFC 6353 (updated by RFC 9456). The system tests use Behave with Docker containers: a
`test-agent-mib` container runs the agent, and a `snmp-client` container runs the SNMP
client tool. The objective was to find a standards-compliant, freely usable SNMP TSM
client that can drive Behave steps.

---

## RFC 9456 (November 2023)

RFC 9456 updates RFC 6353 without architectural change. The principal normative changes
are:

- Implementations **MUST** use (D)TLS 1.2 or later, aligning with RFC 8996's
  deprecation of TLS 1.0 and 1.1.
- (D)TLS 1.3 implementations **MUST NOT** enable 0-RTT session resumption (no SNMP
  message is inherently replay-safe).
- The `SnmpTLSFingerprint` hash-algorithm identifier now references a new IANA registry;
  MD5 and SHA-1 identifiers are explicitly prohibited.
- Language clarifications (BCP 14 capitalisation, grammar); no structural changes to the
  framing, session model, or MIB.

---

## net-snmp TSM Support

net-snmp is the reference open-source SNMP implementation and the most widely used SNMP
CLI toolset on Linux. TLS/DTLS transport (RFC 6353) was introduced in net-snmp 5.6.

### The TLS 1.0 hard-coding bug

Net-snmp 5.9.3 (shipped in Debian 12 bookworm) deliberately caps the TLS version at 1.0
via `SSL_CTX_set_max_proto_version(TLS1_VERSION)` in its TSM TCP client code. This means:

- The ClientHello always advertises `client_version = 0x0301` (TLS 1.0).
- OpenSSL omits the `signature_algorithms` extension (type `0x000d`) from TLS 1.0
  ClientHellos.
- Rustls rejects any ClientHello that lacks this extension when ECDHE cipher suites are
  offered (RFC 5246 §7.4.1.4.1), responding with a `handshake_failure` alert.
- Attempting to force TLS 1.2 via `MinProtocol = TLSv1.2` in `openssl.cnf` causes
  net-snmp to detect the mismatch internally and send a fatal `protocol_version` alert
  before the ClientHello is even transmitted.
- The `tlsAlgorithms` directive in `snmp.conf` triggers a different pre-ClientHello
  `InternalError` alert from net-snmp's own `tls_setup_handshake()`.

In short: net-snmp 5.9.3 cannot complete a TLS 1.2 or TLS 1.3 handshake under any
configuration, making it non-compliant with RFC 9456's MUST requirement.

This bug was reported as [GitHub issue #263](https://github.com/net-snmp/net-snmp/issues/263)
and fixed in [PR #377](https://github.com/net-snmp/net-snmp/pull/377), merged November
2021.

### Distro package status

| Distro | net-snmp version | TLS 1.0 fix present | Notes |
|--------|-----------------|--------------------|----|
| Debian 12 bookworm | 5.9.3 | No | Current stable; TLS broken with rustls |
| Debian 13 trixie | 5.9.4 | Yes | CHANGES notes "TLS/DTLS not functioning properly with various OpenSSL versions" |
| Debian sid | 5.9.5.2 | Yes | Likely most stable TLS support |
| Ubuntu 22.04 LTS | 5.9.1 | No | Fix post-dates this release |
| Ubuntu 24.04 LTS | 5.9.4 | Yes | Subject to the 5.9.4 OpenSSL caveat |

The 5.9.4 CHANGES file itself warns that TLS transport is broken in some configurations
in that release, suggesting that even upgrading from bookworm to trixie may not resolve
interoperability issues with a strict TLS 1.2+ server such as rustls.

---

## Client Options Evaluated

### net-snmp (plain)

**Verdict: blocked.** The TLS 1.0 hard-coding bug prevents any handshake with a
TLS 1.2+ server. No configuration workaround exists; the bug requires a code fix.

### net-snmp + stunnel proxy

A stunnel proxy (or similar) could accept TLS 1.0 from net-snmp on a local port,
re-establish a TLS 1.2+ connection to the rustls agent, and forward bytes verbatim.
Because SNMP messages are just bytes inside TLS (with RFC 6353's 4-byte length-prefix
framing), no SNMP-layer parsing is required in the proxy.

**Advantage:** net-snmp remains the SNMP implementation; the proxy adds no SNMP logic,
so interoperability evidence is genuine.

**Complication:** Mutual TLS on both sides. The proxy must hold both the server cert/key
(to satisfy net-snmp's server validation) and the client cert/key (to satisfy the
agent's client validation). In a controlled test environment this is manageable, but it
adds configuration complexity.

**Verdict: viable** but architecturally awkward.

### snmp4j-CLT (Java)

AGENTPP's SNMP4J Command Line Tool is a standalone JAR with full TSM/TLS support
(TLS 1.2 in version 2.x, TLS 1.3 in 3.1.1+). It uses Java's standard TLS stack, which
supports TLS 1.2+ without any of net-snmp's limitations.

**Blocker: commercial licence.** The `snmp4j-clt` JAR requires a purchased licence after
an evaluation period. Including it in a Docker image for CI violates the licence terms.

**Verdict: not viable** for open, freely distributable test infrastructure.

### pysnmp / snmpclitools

The revived pysnmp library (maintained by LeXtudio since 2022) and its companion CLI
package `snmpclitools` (which provides `snmpget`, `snmpwalk`, etc.) support SNMPv3 with
USM over UDP only. TLS transport (tlstcp / RFC 6363) is not implemented.

**Verdict: not applicable.** Cannot connect to a TLS-only agent regardless of TLS
version.

### Custom Rust client

Ruled out on principle: a client written for this project cannot provide evidence of
interoperability or standards compliance. It would only prove that our client and our
server agree with each other.

---

## General Adoption of SNMP TSM

SNMP TSM sees very limited production deployment. Key observations:

- **SNMPv3/USM over UDP remains dominant** across enterprise and ISP networks. Operators
  who want encrypted SNMP management traffic overwhelmingly use USM with AES-128/AES-256
  rather than switching to the TSM transport model.
- **Device support is sparse.** Cisco IOS, Juniper Junos, and the majority of NMS
  polling engines implement SNMPv3/USM only. No evidence was found of TSM (tlstcp) being
  shipped in production NOS software from major vendors.
- **Complexity is a barrier.** TSM requires TCP, mutual TLS, X.509 certificate
  provisioning, and TLSTM MIB support — significantly more operational overhead than
  USM with shared secrets.
- **Industry direction is away from SNMP entirely.** Cisco, Juniper, and Arista are
  actively promoting model-driven telemetry (gNMI, gRPC, OpenConfig) and NETCONF/YANG.
  SNMP persists in the installed base (embedded devices, printers, UPS units) but is not
  gaining new deployment. TSM is not a stepping stone in this migration; organisations
  that modernise skip it entirely.
- **No interoperability certification programme exists** for SNMP TSM. Commercial
  conformance test suites (SilverCreek, SimpleSoft SimpleTester) cover it, but there is
  no IETF interoperability event or alliance certification analogous to Wi-Fi or DLNA
  testing.

The net result is that SNMP TSM is standards-complete but commercially niche, most
relevant to compliance-driven environments (government, finance) that must use SNMP and
must encrypt management traffic, and where certificate infrastructure already exists.

---

## Conclusion

The most viable path for Behave system tests against the TLS agent is **net-snmp with a
stunnel proxy** in the `snmp-client` Docker container. This preserves net-snmp as the
authoritative SNMP implementation (the proxy adds no SNMP logic), while working around
the TLS 1.0 limitation at the TLS layer only. All other freely available options either
do not support TLS transport at all (pysnmp) or carry licence restrictions that prevent
CI use (snmp4j-CLT).

The broad immaturity of the SNMP TSM ecosystem — one reference implementation with a
known TLS version bug in all currently stable distro packages, no freely available
alternative CLI clients, and negligible production adoption — reflects the general
industry trajectory away from SNMP rather than towards it.
