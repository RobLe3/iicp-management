use crate::apply_gate::LocalApplyGateV1;
use crate::controller::ApplyAuthorizationReceiptV1;
use crate::controller::{LocalPlanSubmissionV1, PlanSubmissionReceiptV1};
use crate::execution::{ApplyLifecycleReceiptV1, LocalApplyExecutionV1};
use crate::profile::{
    ManagementProfileQueryV1, ManagementProfileResponseV1, MANAGEMENT_PROFILE_QUERY_SCHEMA,
};
use crate::recovery::{LocalRecoveryExecutionV1, LocalRecoveryGateV1, RecoveryLifecycleReceiptV1};
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[cfg(unix)]
pub fn submit_plan(
    endpoint: &Path,
    submission: &LocalPlanSubmissionV1,
) -> Result<PlanSubmissionReceiptV1, String> {
    use std::{os::unix::net::UnixStream, time::Duration};

    let mut stream = UnixStream::connect(endpoint).map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "IPC_TIMEOUT_CONFIGURATION_FAILED".to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "IPC_TIMEOUT_CONFIGURATION_FAILED".to_string())?;
    exchange(&mut stream, submission)
}

#[cfg(unix)]
pub fn request_apply(
    endpoint: &Path,
    gate: &LocalApplyGateV1,
) -> Result<ApplyAuthorizationReceiptV1, String> {
    use std::{os::unix::net::UnixStream, time::Duration};

    let mut stream = UnixStream::connect(endpoint).map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "IPC_TIMEOUT_CONFIGURATION_FAILED".to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "IPC_TIMEOUT_CONFIGURATION_FAILED".to_string())?;
    exchange(&mut stream, gate)
}

#[cfg(any(unix, windows))]
pub fn execute_apply(
    endpoint: &Path,
    execution: &LocalApplyExecutionV1,
) -> Result<ApplyLifecycleReceiptV1, String> {
    #[cfg(unix)]
    let mut stream = {
        use std::os::unix::net::UnixStream;
        UnixStream::connect(endpoint).map_err(|_| "IPC_CONNECT_FAILED".to_string())?
    };
    #[cfg(windows)]
    let mut stream = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    exchange(&mut stream, execution)
}

#[cfg(any(unix, windows))]
pub fn request_recovery(
    endpoint: &Path,
    gate: &LocalRecoveryGateV1,
) -> Result<ApplyAuthorizationReceiptV1, String> {
    platform_exchange(endpoint, gate)
}

#[cfg(any(unix, windows))]
pub fn execute_recovery(
    endpoint: &Path,
    execution: &LocalRecoveryExecutionV1,
) -> Result<RecoveryLifecycleReceiptV1, String> {
    platform_exchange(endpoint, execution)
}

#[cfg(any(unix, windows))]
pub fn query_profile(endpoint: &Path) -> Result<ManagementProfileResponseV1, String> {
    platform_exchange(
        endpoint,
        &ManagementProfileQueryV1 {
            schema_version: MANAGEMENT_PROFILE_QUERY_SCHEMA.into(),
        },
    )
}

#[cfg(any(unix, windows))]
fn platform_exchange<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    endpoint: &Path,
    value: &Q,
) -> Result<R, String> {
    #[cfg(unix)]
    let mut stream = std::os::unix::net::UnixStream::connect(endpoint)
        .map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    #[cfg(windows)]
    let mut stream = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    exchange(&mut stream, value)
}

#[cfg(windows)]
pub fn submit_plan(
    endpoint: &Path,
    submission: &LocalPlanSubmissionV1,
) -> Result<PlanSubmissionReceiptV1, String> {
    use std::fs::OpenOptions;

    let name = endpoint.to_str().ok_or("IPC_ENDPOINT_INVALID")?;
    if !name.starts_with(r"\\.\pipe\") || name.len() <= r"\\.\pipe\".len() {
        return Err("IPC_ENDPOINT_INVALID".into());
    }
    let mut stream = OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    exchange(&mut stream, submission)
}

#[cfg(windows)]
pub fn request_apply(
    endpoint: &Path,
    gate: &LocalApplyGateV1,
) -> Result<ApplyAuthorizationReceiptV1, String> {
    use std::fs::OpenOptions;

    let name = endpoint.to_str().ok_or("IPC_ENDPOINT_INVALID")?;
    if !name.starts_with(r"\\.\pipe\") || name.len() <= r"\\.\pipe\".len() {
        return Err("IPC_ENDPOINT_INVALID".into());
    }
    let mut stream = OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .map_err(|_| "IPC_CONNECT_FAILED".to_string())?;
    exchange(&mut stream, gate)
}

#[cfg(not(any(unix, windows)))]
pub fn execute_apply(
    _: &Path,
    _: &LocalApplyExecutionV1,
) -> Result<ApplyLifecycleReceiptV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

#[cfg(not(any(unix, windows)))]
pub fn request_recovery(
    _: &Path,
    _: &LocalRecoveryGateV1,
) -> Result<ApplyAuthorizationReceiptV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

#[cfg(not(any(unix, windows)))]
pub fn execute_recovery(
    _: &Path,
    _: &LocalRecoveryExecutionV1,
) -> Result<RecoveryLifecycleReceiptV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

#[cfg(not(any(unix, windows)))]
pub fn query_profile(_: &Path) -> Result<ManagementProfileResponseV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

#[cfg(not(any(unix, windows)))]
pub fn submit_plan(_: &Path, _: &LocalPlanSubmissionV1) -> Result<PlanSubmissionReceiptV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

#[cfg(not(any(unix, windows)))]
pub fn request_apply(
    _: &Path,
    _: &LocalApplyGateV1,
) -> Result<ApplyAuthorizationReceiptV1, String> {
    Err("IPC_UNSUPPORTED_PLATFORM".into())
}

fn exchange<S: std::io::Read + Write, Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    stream: &mut S,
    submission: &Q,
) -> Result<R, String> {
    let request = serde_json::to_string(submission).map_err(|_| "IPC_REQUEST_INVALID")?;
    if request.len() > MAX_RESPONSE_BYTES as usize {
        return Err("IPC_REQUEST_TOO_LARGE".into());
    }
    writeln!(stream, "{request}").map_err(|_| "IPC_WRITE_FAILED".to_string())?;
    stream.flush().map_err(|_| "IPC_WRITE_FAILED".to_string())?;
    let mut response = String::new();
    BufReader::new(stream)
        .take(MAX_RESPONSE_BYTES + 1)
        .read_line(&mut response)
        .map_err(|_| "IPC_READ_FAILED".to_string())?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("IPC_RESPONSE_TOO_LARGE".into());
    }
    serde_json::from_str(&response).map_err(|_| "IPC_RESPONSE_INVALID".into())
}
