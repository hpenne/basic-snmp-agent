// Exercises the BER length-field parser used for RFC 3430 TCP message framing.
#![no_main]

use basic_snmp_agent::transport::parse_ber_length;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|length_field_bytes: &[u8]| {
    let _ = parse_ber_length(length_field_bytes);
});
