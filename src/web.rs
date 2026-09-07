use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

use crate::model::{ScanReport, ThreadIdentity};

pub const WEB_COMPARISON_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_ITEMS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebVerdict {
    Present,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebComparison {
    report: ScanReport,
    verdicts: HashMap<ThreadIdentity, WebVerdict>,
    observed_at: Instant,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WebError {
    #[error("browser comparison payload is malformed")]
    Malformed,
    #[error("browser requested-ID checks are incomplete or have an unsupported schema")]
    Incomplete,
    #[error("browser account identity or workspace cannot be verified")]
    AccountUnverified,
    #[error("browser comparison contains duplicate or inconsistent identities")]
    Inconsistent,
}

impl WebComparison {
    /// Validate a sanitized result from the authenticated browser transport.
    /// `complete` means every requested ID received authenticated metadata presence
    /// or a direct JSON GET result. Metadata is used only as positive evidence.
    /// Controls are requested positive IDs confirmed by direct JSON GET 200 after
    /// all requested statuses, including a repeated GET for direct-positive controls.
    /// A 404 establishes endpoint unavailability, never deletion or absence from
    /// the complete account history. Account validation and repeated requests are
    /// performed by the trusted collector before this sanitized result is returned.
    /// This payload is not a user-importable or persisted authorization format.
    pub fn from_value(report: &ScanReport, value: serde_json::Value) -> Result<Self, WebError> {
        let wire: ComparisonWire =
            serde_json::from_value(value).map_err(|_| WebError::Malformed)?;
        if wire.schema_version != 3 || wire.kind != "requested_metadata_checks" || !wire.complete {
            return Err(WebError::Incomplete);
        }
        if wire.account_structure != "personal"
            || !valid_identifier(&wire.user_id)
            || !valid_uuid(&wire.account_id)
            || !(wire.account_user_id == wire.user_id
                || wire.account_user_id == format!("{}__{}", wire.user_id, wire.account_id))
        {
            return Err(WebError::AccountUnverified);
        }
        if wire.controls.len() > MAX_ITEMS
            || wire.checks.len() > MAX_ITEMS
            || report.threads.len() > MAX_ITEMS
        {
            return Err(WebError::Malformed);
        }
        let mut local = HashSet::with_capacity(report.threads.len());
        let mut requested_ids = HashSet::new();
        let mut bound_ids = HashSet::new();
        for thread in &report.threads {
            let identity = thread.identity();
            if !local.insert(identity) {
                return Err(WebError::Inconsistent);
            }
            if thread.source_kind() != "chatgpt" {
                continue;
            }
            if !valid_uuid(&identity.thread_id) {
                return Err(WebError::Malformed);
            }
            requested_ids.insert(identity.thread_id.as_str());
            if host_account_user(&identity.host_id) == Some(wire.user_id.as_str()) {
                bound_ids.insert(identity.thread_id.as_str());
            }
        }
        if bound_ids.is_empty() {
            return Err(WebError::AccountUnverified);
        }
        let mut checks = HashMap::with_capacity(wire.checks.len());
        for check in wire.checks {
            if !valid_uuid(&check.id) || !requested_ids.contains(check.id.as_str()) {
                return Err(WebError::Inconsistent);
            }
            if checks.insert(check.id, check.evidence).is_some() {
                return Err(WebError::Inconsistent);
            }
        }
        if checks.len() != requested_ids.len() {
            return Err(WebError::Incomplete);
        }
        let mut controls = HashSet::with_capacity(wire.controls.len());
        for id in wire.controls {
            if !valid_uuid(&id)
                || !checks.get(&id).is_some_and(CheckEvidence::is_positive)
                || !controls.insert(id)
            {
                return Err(WebError::Inconsistent);
            }
        }
        if controls.is_empty()
            && checks
                .values()
                .any(|evidence| *evidence == CheckEvidence::AuthenticatedJsonGet404)
        {
            return Err(WebError::Inconsistent);
        }
        let control_hosts: HashSet<_> = report
            .threads
            .iter()
            .filter(|thread| {
                thread.source_kind() == "chatgpt"
                    && host_account_user(&thread.identity().host_id) == Some(wire.user_id.as_str())
                    && controls.contains(&thread.identity().thread_id)
            })
            .map(|thread| thread.identity().host_id.as_str())
            .collect();
        let verdicts = report
            .threads
            .iter()
            .map(|thread| {
                let identity = thread.identity();
                let bound = thread.source_kind() == "chatgpt"
                    && host_account_user(&identity.host_id) == Some(wire.user_id.as_str());
                let verdict = if thread.source_kind() == "chatgpt"
                    && checks
                        .get(&identity.thread_id)
                        .is_some_and(CheckEvidence::is_positive)
                {
                    WebVerdict::Present
                } else if bound
                    && thread.project_id().is_none()
                    && thread.cwd().is_none()
                    && control_hosts.contains(identity.host_id.as_str())
                    && checks.get(&identity.thread_id)
                        == Some(&CheckEvidence::AuthenticatedJsonGet404)
                {
                    WebVerdict::Unavailable
                } else {
                    WebVerdict::Unknown
                };
                (identity.clone(), verdict)
            })
            .collect();
        Ok(Self {
            report: report.clone(),
            verdicts,
            observed_at: Instant::now(),
        })
    }

    pub fn verdict(&self, identity: &ThreadIdentity) -> WebVerdict {
        self.verdicts
            .get(identity)
            .copied()
            .unwrap_or(WebVerdict::Unknown)
    }

    pub fn permits(
        &self,
        report: &ScanReport,
        identities: &[ThreadIdentity],
        now: Instant,
    ) -> bool {
        if !self.matches_report(report) || identities.is_empty() || !self.is_fresh_at(now) {
            return false;
        }
        let mut unique = HashSet::with_capacity(identities.len());
        identities.iter().all(|identity| {
            unique.insert(identity) && self.verdict(identity) == WebVerdict::Unavailable
        })
    }

    pub fn matches_report(&self, report: &ScanReport) -> bool {
        report == &self.report
    }

    pub fn is_fresh_at(&self, now: Instant) -> bool {
        now.checked_duration_since(self.observed_at)
            .is_some_and(|age| age < WEB_COMPARISON_TTL)
    }

    pub fn summary(&self) -> String {
        let count = |verdict| {
            self.verdicts
                .values()
                .filter(|value| **value == verdict)
                .count()
        };
        format!(
            "웹 존재 {}개 · 접근 불가 {}개 · 확인 불가 {}개 (5분 유효)",
            count(WebVerdict::Present),
            count(WebVerdict::Unavailable),
            count(WebVerdict::Unknown)
        )
    }

    pub const fn observed_at(&self) -> Instant {
        self.observed_at
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComparisonWire {
    schema_version: u32,
    kind: String,
    user_id: String,
    account_id: String,
    account_user_id: String,
    account_structure: String,
    complete: bool,
    checks: Vec<ConversationCheck>,
    controls: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationCheck {
    id: String,
    evidence: CheckEvidence,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
enum CheckEvidence {
    #[serde(rename = "authenticated_list_item")]
    AuthenticatedListItem,
    #[serde(rename = "authenticated_json_get_200")]
    AuthenticatedJsonGet200,
    #[serde(rename = "authenticated_json_get_404")]
    AuthenticatedJsonGet404,
}

impl CheckEvidence {
    fn is_positive(&self) -> bool {
        matches!(
            self,
            Self::AuthenticatedListItem | Self::AuthenticatedJsonGet200
        )
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn host_account_user(host: &str) -> Option<&str> {
    let mut parts = host.split(':');
    let (Some("chatgpt"), Some(opaque), Some(user), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    // The UUID is an opaque local identifier, never inferred to be a workspace ID.
    (valid_uuid(opaque) && valid_identifier(user)).then_some(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CatalogThread, Classification, DeletionEvidence, LocalPath, SchemaReport};
    use serde_json::json;
    use std::path::Path;

    const HOST: &str = "chatgpt:11111111-1111-4111-8111-111111111111:user-fixture";
    const CONTROL: &str = "22222222-2222-4222-8222-222222222222";
    const MISSING: &str = "33333333-3333-4333-8333-333333333333";
    const OTHER_PRESENT: &str = "44444444-4444-4444-8444-444444444444";

    fn identity(id: &str) -> ThreadIdentity {
        ThreadIdentity::new(HOST, id)
    }

    fn report() -> ScanReport {
        let threads = [CONTROL, MISSING, OTHER_PRESENT]
            .into_iter()
            .map(|id| {
                CatalogThread::review_required(identity(id), "fixture", "chatgpt", true, None, None)
                    .expect("valid fixture")
            })
            .collect();
        ScanReport::new(
            LocalPath::try_from(Path::new("/fixture/catalog.db")).unwrap(),
            "macos",
            SchemaReport {
                write_capable: true,
                reason: "fixture".into(),
                fingerprint: "fixture".into(),
                columns: vec![],
            },
            threads,
            true,
        )
    }

    fn payload() -> serde_json::Value {
        json!({
            "schema_version": 3,
            "kind": "requested_metadata_checks",
            "user_id": "user-fixture",
            "account_id": "55555555-5555-4555-8555-555555555555",
            "account_user_id": "user-fixture",
            "account_structure": "personal",
            "complete": true,
            "checks": [
                {"id": CONTROL, "evidence": "authenticated_list_item"},
                {"id": MISSING, "evidence": "authenticated_json_get_404"},
                {"id": OTHER_PRESENT, "evidence": "authenticated_json_get_200"}
            ],
            "controls": [CONTROL]
        })
    }

    #[test]
    fn listed_control_permits_only_exact_checked_unavailability_on_the_same_host() {
        let report = report();
        let proof =
            WebComparison::from_value(&report, payload()).expect("valid sanitized comparison");
        assert_eq!(proof.verdict(&identity(CONTROL)), WebVerdict::Present);
        assert_eq!(proof.verdict(&identity(MISSING)), WebVerdict::Unavailable);
        assert_eq!(proof.verdict(&identity(OTHER_PRESENT)), WebVerdict::Present);
        assert!(proof.permits(&report, &[identity(MISSING)], proof.observed_at()));
        for selection in [
            vec![],
            vec![identity(CONTROL)],
            vec![identity(OTHER_PRESENT)],
            vec![identity(MISSING), identity(MISSING)],
        ] {
            assert!(!proof.permits(&report, &selection, proof.observed_at()));
        }
    }

    #[test]
    fn listed_presence_protects_a_locally_confirmed_deleted_conversation() {
        let mut report = report();
        report.threads[0] = CatalogThread::confirmed_deleted(
            identity(CONTROL),
            "locally deleted fixture",
            "chatgpt",
            true,
            None,
            None,
            DeletionEvidence {
                source_path: LocalPath::try_from(Path::new("/fixture/deletion.log")).unwrap(),
                reason: "fixture deletion event".into(),
            },
        )
        .unwrap();
        let proof = WebComparison::from_value(&report, payload()).unwrap();
        assert_eq!(proof.verdict(&identity(CONTROL)), WebVerdict::Present);
        assert!(!proof.permits(&report, &[identity(CONTROL)], proof.observed_at()));
        assert_eq!(
            report.threads[0].classification(),
            Classification::ConfirmedDeleted
        );
    }

    #[test]
    fn proof_expires_and_binds_the_entire_original_report() {
        let report = report();
        let proof = WebComparison::from_value(&report, payload()).unwrap();
        let selected = [identity(MISSING)];
        assert!(!proof.permits(&report, &selected, proof.observed_at() + WEB_COMPARISON_TTL));
        assert!(!proof.permits(
            &report,
            &selected,
            proof.observed_at() - Duration::from_secs(1)
        ));
        let mut changed = report.clone();
        changed.schema.fingerprint.push_str("-changed");
        assert!(!proof.permits(&changed, &selected, proof.observed_at()));
        changed = report.clone();
        changed.threads.pop();
        assert!(!proof.permits(&changed, &selected, proof.observed_at()));
    }

    #[test]
    fn personal_account_user_id_is_normalized_only_with_exact_account_binding() {
        let report = report();
        let mut value = payload();
        value["account_user_id"] = json!("user-fixture__55555555-5555-4555-8555-555555555555");
        let proof = WebComparison::from_value(&report, value).unwrap();
        assert!(proof.permits(&report, &[identity(MISSING)], proof.observed_at()));
        let mut value = payload();
        value["account_user_id"] = json!("user-fixture__66666666-6666-4666-8666-666666666666");
        assert!(WebComparison::from_value(&report, value).is_err());
    }

    #[test]
    fn malformed_incomplete_duplicate_and_unbound_results_fail_closed() {
        let report = report();
        for (key, invalid) in [
            ("schema_version", json!(1)),
            ("kind", json!("full_inventory")),
            ("complete", json!(false)),
            ("account_user_id", json!("user-other")),
            ("user_id", json!("")),
            ("account_structure", json!("team")),
            ("account_id", json!("")),
        ] {
            let mut value = payload();
            value[key] = invalid;
            assert!(
                WebComparison::from_value(&report, value).is_err(),
                "accepted invalid {key}"
            );
        }
        let mut value = payload();
        let duplicate = value["checks"][0].clone();
        value["checks"].as_array_mut().unwrap().push(duplicate);
        assert!(WebComparison::from_value(&report, value).is_err());
        let mut value = payload();
        value["checks"][1]["id"] = json!(CONTROL);
        assert!(WebComparison::from_value(&report, value).is_err());
        let mut value = payload();
        value["checks"][0]["evidence"] = json!("authenticated_json_get_404");
        assert!(WebComparison::from_value(&report, value).is_err());
        let mut value = payload();
        value["checks"][0]["id"] = json!("66666666-6666-4666-8666-666666666666");
        assert!(WebComparison::from_value(&report, value).is_err());
    }

    #[test]
    fn listed_and_direct_presence_remain_protected_without_a_confirmed_control() {
        let report = report();
        let mut value = payload();
        value["controls"] = json!([]);
        value["checks"][1]["evidence"] = json!("authenticated_list_item");
        let proof = WebComparison::from_value(&report, value).unwrap();
        assert_eq!(proof.verdict(&identity(CONTROL)), WebVerdict::Present);
        assert_eq!(proof.verdict(&identity(OTHER_PRESENT)), WebVerdict::Present);
        assert_eq!(proof.verdict(&identity(MISSING)), WebVerdict::Present);
        assert!(!proof.permits(&report, &[identity(MISSING)], proof.observed_at()));
    }

    #[test]
    fn every_requested_id_requires_exactly_one_typed_check() {
        let report = report();
        let mut missing = payload();
        missing["checks"].as_array_mut().unwrap().pop();
        assert!(WebComparison::from_value(&report, missing).is_err());
        for invalid in [
            "present",
            "unavailable",
            "deleted",
            "unknown",
            "authenticated_json_get_403",
        ] {
            let mut value = payload();
            value["checks"][1]["evidence"] = json!(invalid);
            assert!(WebComparison::from_value(&report, value).is_err());
        }
        let mut extra = payload();
        extra["checks"].as_array_mut().unwrap().push(json!({
            "id": "66666666-6666-4666-8666-666666666666", "evidence": "authenticated_json_get_404"
        }));
        assert!(WebComparison::from_value(&report, extra).is_err());
    }

    #[test]
    fn confirmed_controls_must_be_unique_requested_positive_ids() {
        for controls in [
            json!([CONTROL, CONTROL]),
            json!([MISSING]),
            json!(["../invalid"]),
            json!(["66666666-6666-4666-8666-666666666666"]),
            json!(null),
        ] {
            let mut value = payload();
            value["controls"] = controls;
            assert!(WebComparison::from_value(&report(), value).is_err());
        }
    }

    #[test]
    fn blanket_404_results_cannot_authorize_any_cleanup() {
        let report = report();
        let mut value = payload();
        value["controls"] = json!([]);
        for check in value["checks"].as_array_mut().unwrap() {
            check["evidence"] = json!("authenticated_json_get_404");
        }
        assert_eq!(
            WebComparison::from_value(&report, value),
            Err(WebError::Inconsistent)
        );
    }

    #[test]
    fn a_negative_result_requires_a_confirmed_control_even_with_other_positive_checks() {
        let mut value = payload();
        value["controls"] = json!([]);
        assert_eq!(
            WebComparison::from_value(&report(), value),
            Err(WebError::Inconsistent)
        );
    }

    #[test]
    fn old_schemas_cannot_mint_requested_metadata_proof() {
        let old = json!({
            "schema_version": 1, "user_id": "user-fixture",
            "account_id": "55555555-5555-4555-8555-555555555555",
            "account_user_id": "user-fixture", "account_structure": "personal", "complete": true,
            "items": [{"id": CONTROL, "title": "fixture", "archived": true}],
            "checks": [{"id": MISSING, "status": "unavailable"}]
        });
        assert!(WebComparison::from_value(&report(), old).is_err());
        let mut old_direct = payload();
        old_direct["schema_version"] = json!(2);
        old_direct["kind"] = json!("requested_id_checks");
        old_direct["checks"][0]["evidence"] = json!("authenticated_json_get_200");
        assert!(WebComparison::from_value(&report(), old_direct).is_err());
        let mut value = payload();
        value["items"] = json!([]);
        assert!(WebComparison::from_value(&report(), value).is_err());
    }

    #[test]
    fn control_from_another_host_cannot_authorize_a_missing_conversation() {
        let mut report = report();
        let other = ThreadIdentity::new(
            "chatgpt:77777777-7777-4777-8777-777777777777:user-fixture",
            MISSING,
        );
        report.threads.push(
            CatalogThread::review_required(
                other.clone(),
                "other host",
                "chatgpt",
                true,
                None,
                None,
            )
            .unwrap(),
        );
        let proof = WebComparison::from_value(&report, payload()).unwrap();
        assert_eq!(proof.verdict(&other), WebVerdict::Unknown);
        assert!(!proof.permits(&report, &[other], proof.observed_at()));
        assert!(proof.permits(&report, &[identity(MISSING)], proof.observed_at()));
    }

    #[test]
    fn unknown_identity_and_payload_shapes_never_mint_authorization() {
        for code in [
            "session_user_mismatch",
            "account_match_mismatch",
            "account_user_mismatch",
            "final_identity_changed",
        ] {
            assert!(WebComparison::from_value(&report(), json!({"error": code})).is_err());
        }
        let mut duplicated = report();
        duplicated.threads.push(duplicated.threads[0].clone());
        assert!(WebComparison::from_value(&duplicated, payload()).is_err());
        for (field, value) in [
            ("checks", json!([{"id": MISSING, "status": "deleted"}])),
            ("items", json!([{"id": CONTROL, "title": "fixture"}])),
            (
                "items",
                json!([{"id": "../invalid", "title": "fixture", "archived": false}]),
            ),
        ] {
            let mut malformed = payload();
            malformed[field] = value;
            assert!(WebComparison::from_value(&report(), malformed).is_err());
        }
        let mut malformed = payload();
        malformed["access_token"] = json!("unexpected-field");
        assert!(WebComparison::from_value(&report(), malformed).is_err());
    }

    #[test]
    fn direct_presence_is_protected_and_unbound_absence_does_not_poison_bound_results() {
        let mut report = report();
        let foreign = ThreadIdentity::new(
            "chatgpt:88888888-8888-4888-8888-888888888888:user-other",
            "99999999-9999-4999-8999-999999999999",
        );
        report.threads.push(
            CatalogThread::review_required(foreign.clone(), "foreign", "chatgpt", true, None, None)
                .unwrap(),
        );
        let normal = identity("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        report.threads.push(CatalogThread::preserved(
            normal.clone(),
            "normal",
            "chatgpt",
            false,
            None,
            None,
        ));
        let mut value = payload();
        value["checks"].as_array_mut().unwrap().extend([
            json!({"id": foreign.thread_id, "evidence": "authenticated_json_get_404"}),
            json!({"id": normal.thread_id, "evidence": "authenticated_json_get_404"}),
        ]);
        let proof = WebComparison::from_value(&report, value).unwrap();
        assert_eq!(proof.verdict(&identity(OTHER_PRESENT)), WebVerdict::Present);
        assert_eq!(proof.verdict(&foreign), WebVerdict::Unknown);
        assert_eq!(proof.verdict(&normal), WebVerdict::Unavailable);
        assert!(proof.permits(&report, &[identity(MISSING)], proof.observed_at()));
        assert!(proof.permits(&report, &[normal], proof.observed_at()));
    }

    #[test]
    fn project_and_cwd_rows_remain_protected_despite_checked_absence() {
        let mut report = report();
        let project = identity("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        let cwd = identity("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        report.threads.push(CatalogThread::preserved(
            project.clone(),
            "project",
            "chatgpt",
            false,
            Some("project-context".into()),
            None,
        ));
        report.threads.push(CatalogThread::preserved(
            cwd.clone(),
            "cwd",
            "chatgpt",
            false,
            None,
            Some(LocalPath::try_from(Path::new("/synthetic/project")).unwrap()),
        ));
        let mut value = payload();
        value["checks"].as_array_mut().unwrap().extend([
            json!({"id": project.thread_id, "evidence": "authenticated_json_get_404"}),
            json!({"id": cwd.thread_id, "evidence": "authenticated_json_get_404"}),
        ]);
        let proof = WebComparison::from_value(&report, value).unwrap();
        for identity in [project, cwd] {
            assert_eq!(proof.verdict(&identity), WebVerdict::Unknown);
            assert!(!proof.permits(&report, &[identity], proof.observed_at()));
        }
    }
}
