// Each fuzz target includes only the type it needs; the remaining public items
// appear unused to the dead-code lint in that binary's test build.
#![allow(dead_code)]

use arbitrary::Arbitrary;

const FUZZ_ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80test";

// All variants share the "Request" postfix because they are SNMP PDU request types;
// removing it would produce names that do not match the RFC terminology.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Arbitrary)]
pub enum PduType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    SetRequest,
}

#[derive(Debug, Arbitrary)]
pub enum EngineIdChoice {
    Matching,
    Empty,
    Custom([u8; 8]),
}

impl EngineIdChoice {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Matching => FUZZ_ENGINE_ID,
            Self::Empty => b"",
            Self::Custom(custom_engine_id) => custom_engine_id,
        }
    }
}

// Constrain the first two arcs to avoid an overflow panic in rasn 0.22's
// OID encoder (first * 40 + second can overflow u32 for large second values).
fn constrained_oid_arcs(oid_arc_count: u8, oid_arcs: &[u32; 12]) -> Vec<u32> {
    let count = usize::from(oid_arc_count).clamp(2, 12);
    oid_arcs[..count]
        .iter()
        .enumerate()
        .map(|(index, &arc)| match index {
            0 => arc % 3,
            1 => arc % 40,
            _ => arc,
        })
        .collect()
}

#[derive(Debug, Arbitrary)]
pub struct FuzzSnmpv3 {
    pub pdu_type: PduType,
    pub msg_id: i32,
    pub request_id: i32,
    pub engine_id: EngineIdChoice,
    pub oid_arc_count: u8,
    pub oid_arcs: [u32; 12],
    pub non_repeaters: u16,
    pub max_repetitions: u16,
}

impl FuzzSnmpv3 {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let engine_id = self.engine_id.as_bytes();
        let oid_arcs = constrained_oid_arcs(self.oid_arc_count, &self.oid_arcs);
        match self.pdu_type {
            PduType::GetRequest => snmpv3_frames::try_encode_get_request(
                engine_id,
                b"",
                self.msg_id,
                self.request_id,
                &oid_arcs,
            )
            .ok(),
            PduType::GetNextRequest => snmpv3_frames::try_encode_get_next_request(
                engine_id,
                b"",
                self.msg_id,
                self.request_id,
                &oid_arcs,
            )
            .ok(),
            PduType::GetBulkRequest => snmpv3_frames::try_encode_get_bulk_request(
                engine_id,
                b"",
                self.msg_id,
                self.request_id,
                u32::from(self.non_repeaters),
                u32::from(self.max_repetitions),
                &oid_arcs,
            )
            .ok(),
            PduType::SetRequest => snmpv3_frames::try_encode_set_request(
                engine_id,
                b"",
                self.msg_id,
                self.request_id,
                &oid_arcs,
            )
            .ok(),
        }
    }
}

#[derive(Debug, Arbitrary)]
pub enum UserNameChoice {
    Valid,
    Custom([u8; 9]),
}

impl UserNameChoice {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Valid => b"fuzz-user",
            Self::Custom(custom_user_name) => custom_user_name,
        }
    }
}

// Only GetRequest PDUs are generated because the USM authentication code paths are
// PDU-type-independent; supporting all PDU types would require additional
// try_encode_*_with_auth_params_and_time variants in snmpv3-frames.
#[derive(Debug, Arbitrary)]
pub struct FuzzSnmpv3Auth {
    pub msg_id: i32,
    pub request_id: i32,
    pub engine_id: EngineIdChoice,
    pub user_name: UserNameChoice,
    pub msg_flags: u8,
    pub auth_params: [u8; 24],
    pub engine_boots: u32,
    pub engine_time: u32,
    pub oid_arc_count: u8,
    pub oid_arcs: [u32; 12],
}

impl FuzzSnmpv3Auth {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let oid_arcs = constrained_oid_arcs(self.oid_arc_count, &self.oid_arcs);
        snmpv3_frames::try_encode_get_request_with_auth_params_and_time(
            self.engine_id.as_bytes(),
            self.user_name.as_bytes(),
            b"",
            self.msg_id,
            self.request_id,
            &oid_arcs,
            self.msg_flags,
            &self.auth_params,
            self.engine_boots,
            self.engine_time,
        )
        .ok()
    }
}
