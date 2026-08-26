//! Content-minimized, non-authorizing projection of local node runtime health.
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use iicp_client::runtime_health::{
    HealthSnapshot, Liveness, Readiness, SubsystemState, HEALTH_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::digest;

pub const RUNTIME_OBSERVATION_SCHEMA: &str = "iicp.management-runtime-observation.v1";
pub const RUNTIME_HEALTH_SOURCE: &str = "iicp.runtime-health.v1";
pub const MAX_RUNTIME_HEALTH_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEvidenceStateV1 {
    Current,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEffectiveStateV1 {
    Ready,
    Degraded,
    NotReady,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObservationV1 {
    pub schema_version: String,
    pub target_id: String,
    pub evidence_source: String,
    pub source_digest: String,
    pub observed_at: String,
    pub expires_at: String,
    pub evidence_state: RuntimeEvidenceStateV1,
    pub reported_lifecycle: String,
    pub reported_liveness: Liveness,
    pub reported_readiness: Readiness,
    pub effective_state: RuntimeEffectiveStateV1,
    pub reason_codes: Vec<String>,
    pub subsystems: BTreeMap<String, SubsystemState>,
    pub external_connectivity: BTreeMap<String, SubsystemState>,
    pub authorizes_mutation: bool,
}

fn forbidden_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace(['_', '-', ' '], "");
    matches!(
        normalized.as_str(),
        "secret"
            | "secretvalue"
            | "operatorsecret"
            | "password"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "bearertoken"
            | "apikey"
            | "privatekey"
            | "prompt"
            | "response"
            | "taskpayload"
    )
}

fn reject_sensitive(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if forbidden_key(key) {
                    return Err("RUNTIME_HEALTH_SENSITIVE_FIELD_FORBIDDEN".into());
                }
                reject_sensitive(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_sensitive(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn parse_runtime_health(bytes: &[u8]) -> Result<HealthSnapshot, String> {
    if bytes.len() > MAX_RUNTIME_HEALTH_BYTES {
        return Err("RUNTIME_HEALTH_INPUT_TOO_LARGE".into());
    }
    let raw: Value = serde_json::from_slice(bytes).map_err(|_| "RUNTIME_HEALTH_JSON_INVALID")?;
    reject_sensitive(&raw)?;
    serde_json::from_value(raw).map_err(|_| "RUNTIME_HEALTH_SCHEMA_INVALID".into())
}

pub(crate) fn enum_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_value(value)
        .map_err(|_| "RUNTIME_HEALTH_SERIALIZATION_FAILED".to_string())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "RUNTIME_HEALTH_SERIALIZATION_FAILED".into())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn expected_effective_state(
    evidence: &RuntimeEvidenceStateV1,
    liveness: &Liveness,
    readiness: &Readiness,
) -> RuntimeEffectiveStateV1 {
    if *evidence == RuntimeEvidenceStateV1::Stale {
        RuntimeEffectiveStateV1::Unknown
    } else {
        match liveness {
            Liveness::NotLive => RuntimeEffectiveStateV1::NotReady,
            Liveness::Indeterminate => RuntimeEffectiveStateV1::Unknown,
            _ => match readiness {
                Readiness::Ready => RuntimeEffectiveStateV1::Ready,
                Readiness::Degraded => RuntimeEffectiveStateV1::Degraded,
                Readiness::NotReady => RuntimeEffectiveStateV1::NotReady,
            },
        }
    }
}

pub fn validate_runtime_observation(
    value: &RuntimeObservationV1,
    evaluated_at_unix_s: u64,
) -> Result<(), String> {
    let observed = DateTime::parse_from_rfc3339(&value.observed_at)
        .map_err(|_| "RUNTIME_OBSERVATION_INVALID")?
        .with_timezone(&Utc);
    let expires = DateTime::parse_from_rfc3339(&value.expires_at)
        .map_err(|_| "RUNTIME_OBSERVATION_INVALID")?
        .with_timezone(&Utc);
    let evaluated = DateTime::from_timestamp(
        i64::try_from(evaluated_at_unix_s).map_err(|_| "RUNTIME_OBSERVATION_INVALID")?,
        0,
    )
    .ok_or("RUNTIME_OBSERVATION_INVALID")?;
    let stale_reason = "IICP-MGMT-RUNTIME-EVIDENCE-STALE";
    if value.schema_version != RUNTIME_OBSERVATION_SCHEMA
        || value.evidence_source != RUNTIME_HEALTH_SOURCE
        || value.authorizes_mutation
        || value.target_id.trim().is_empty()
        || value.target_id.len() > 256
        || !valid_digest(&value.source_digest)
        || value.reported_lifecycle.is_empty()
        || value.reported_lifecycle.len() > 64
        || observed > evaluated
        || observed > expires
        || value.reason_codes.len() > 128
        || value
            .reason_codes
            .iter()
            .any(|reason| reason.is_empty() || reason.len() > 128)
        || value.subsystems.len() > 128
        || value.external_connectivity.len() > 128
        || value
            .subsystems
            .keys()
            .chain(value.external_connectivity.keys())
            .any(|key| key.is_empty() || key.len() > 128)
        || value.effective_state
            != expected_effective_state(
                &value.evidence_state,
                &value.reported_liveness,
                &value.reported_readiness,
            )
        || (value.evidence_state == RuntimeEvidenceStateV1::Current && evaluated > expires)
        || (value.evidence_state == RuntimeEvidenceStateV1::Stale
            && !value
                .reason_codes
                .iter()
                .any(|reason| reason == stale_reason))
        || (value.evidence_state == RuntimeEvidenceStateV1::Current
            && value
                .reason_codes
                .iter()
                .any(|reason| reason == stale_reason))
    {
        return Err("RUNTIME_OBSERVATION_INVALID".into());
    }
    Ok(())
}

pub fn project_runtime_health(
    snapshot: &HealthSnapshot,
    target_id: &str,
    evaluated_at_unix_s: u64,
) -> Result<RuntimeObservationV1, String> {
    if snapshot.health_schema_version != HEALTH_SCHEMA_VERSION {
        return Err("RUNTIME_HEALTH_SCHEMA_UNSUPPORTED".into());
    }
    if target_id.trim().is_empty() || target_id.len() > 256 {
        return Err("RUNTIME_TARGET_INVALID".into());
    }
    if snapshot.progress.runtime.stale_after_ms == 0
        || snapshot.subsystems.len() > 128
        || snapshot.external_connectivity.len() > 128
        || snapshot.reason_codes.len() > 128
        || snapshot
            .subsystems
            .keys()
            .chain(snapshot.external_connectivity.keys())
            .any(|key| key.is_empty() || key.len() > 128)
    {
        return Err("RUNTIME_HEALTH_BOUNDS_INVALID".into());
    }
    let observed = DateTime::parse_from_rfc3339(&snapshot.emitted_at)
        .map_err(|_| "RUNTIME_HEALTH_TIMESTAMP_INVALID")?
        .with_timezone(&Utc);
    let evaluated = DateTime::from_timestamp(
        i64::try_from(evaluated_at_unix_s).map_err(|_| "RUNTIME_HEALTH_EVALUATION_TIME_INVALID")?,
        0,
    )
    .ok_or("RUNTIME_HEALTH_EVALUATION_TIME_INVALID")?;
    if observed > evaluated {
        return Err("RUNTIME_HEALTH_TIMESTAMP_FUTURE".into());
    }
    let mut freshness_ms = snapshot
        .progress
        .runtime
        .stale_after_ms
        .saturating_sub(snapshot.progress.runtime.age_ms);
    if snapshot.progress.supervisor.required {
        if snapshot.progress.supervisor.stale_after_ms == 0 {
            return Err("RUNTIME_HEALTH_BOUNDS_INVALID".into());
        }
        freshness_ms = freshness_ms.min(
            snapshot
                .progress
                .supervisor
                .stale_after_ms
                .saturating_sub(snapshot.progress.supervisor.age_ms),
        );
    }
    let expires = observed
        .checked_add_signed(TimeDelta::milliseconds(
            i64::try_from(freshness_ms).map_err(|_| "RUNTIME_HEALTH_BOUNDS_INVALID")?,
        ))
        .ok_or("RUNTIME_HEALTH_BOUNDS_INVALID")?;
    let stale = freshness_ms == 0 || evaluated > expires;
    let evidence_state = if stale {
        RuntimeEvidenceStateV1::Stale
    } else {
        RuntimeEvidenceStateV1::Current
    };
    let effective_state = if stale {
        RuntimeEffectiveStateV1::Unknown
    } else {
        match snapshot.liveness {
            Liveness::NotLive => RuntimeEffectiveStateV1::NotReady,
            Liveness::Indeterminate => RuntimeEffectiveStateV1::Unknown,
            _ => match snapshot.readiness {
                Readiness::Ready => RuntimeEffectiveStateV1::Ready,
                Readiness::Degraded => RuntimeEffectiveStateV1::Degraded,
                Readiness::NotReady => RuntimeEffectiveStateV1::NotReady,
            },
        }
    };
    let mut reason_codes = snapshot
        .reason_codes
        .iter()
        .map(enum_string)
        .collect::<Result<Vec<_>, _>>()?;
    if stale {
        reason_codes.push("IICP-MGMT-RUNTIME-EVIDENCE-STALE".into());
    }
    reason_codes.sort();
    reason_codes.dedup();
    let value = RuntimeObservationV1 {
        schema_version: RUNTIME_OBSERVATION_SCHEMA.into(),
        target_id: target_id.into(),
        evidence_source: RUNTIME_HEALTH_SOURCE.into(),
        source_digest: digest(snapshot).map_err(|e| e.to_string())?,
        observed_at: observed.to_rfc3339_opts(SecondsFormat::Millis, true),
        expires_at: expires.to_rfc3339_opts(SecondsFormat::Millis, true),
        evidence_state,
        reported_lifecycle: enum_string(&snapshot.lifecycle)?,
        reported_liveness: snapshot.liveness,
        reported_readiness: snapshot.readiness,
        effective_state,
        reason_codes,
        subsystems: snapshot.subsystems.clone(),
        external_connectivity: snapshot.external_connectivity.clone(),
        authorizes_mutation: false,
    };
    validate_runtime_observation(&value, evaluated_at_unix_s)?;
    Ok(value)
}
