//! `dtrack-rs` — OWASP Dependency-Track SBOM Client & EU CRA / BSI TR-03183 CSAF 2.0 VEX Engine (`v3.1.0-MASTER`).
//!
//! Co-architected with Sabin Ranjit (evolving `DTrackAuditor` into memory-safe Rust for NLnet
//! `CodeSupply` / `Restack [Note 1]` and Germany Sovereign Tech Fund WP1/WP2):
//! 1. Ingests **CycloneDX 1.6** (`bomFormat: "CycloneDX"`) and **SPDX 3.0** (`spdxVersion: "SPDX-3.0"`) SBOMs.
//! 2. Builds deterministic **OWASP Dependency-Track `/api/v1/bom`** upload envelopes.
//! 3. Evaluates **VEX (Vulnerability Exploitability eXchange)** status (`NotAffected`, `Affected`, `Fixed`, `UnderInvestigation`).
//! 4. Emits **EU Cyber Resilience Act (CRA) & German BSI TR-03183 CSAF 2.0 / VEX JSON attestations**
//!    signed with `BLAKE3` + `Ed25519`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Supported SBOM wire standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomDocumentFormat {
    CycloneDx1_6,
    Spdx3_0,
}

/// Normalized software component extracted from CycloneDX 1.6 or SPDX 3.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: String,
    pub spdx_license: String,
}

/// VEX exploitability status per CycloneDX VEX / OASIS CSAF 2.0 / BSI TR-03183-2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

/// Machine-readable VEX justification when status is `NotAffected` or `Fixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexJustification {
    CodeNotReachable,
    ProtectedByCompiler,
    MitigatedByLokahiGate,
    SymbolicAstPatchApplied,
}

/// A single VEX statement linking a CVE/CWE to a component PURL and its exploitability justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VexStatement {
    pub vulnerability_id: String,
    pub cwe_id: String,
    pub product_purl: String,
    pub status: VexStatus,
    pub justification: Option<VexJustification>,
    pub remediation_detail: String,
}

/// Signed EU Cyber Resilience Act (CRA) & BSI TR-03183 CSAF 2.0 / VEX Attestation Bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CsafVexAttestation {
    pub csaf_version: String,
    pub profile: String,
    pub project_name: String,
    pub project_version: String,
    pub sbom_format: SbomDocumentFormat,
    pub components: Vec<SbomComponent>,
    pub vex_statements: Vec<VexStatement>,
    pub attestation_blake3: String,
    pub ed25519_pubkey_hex: String,
    pub ed25519_sig_hex: String,
}

/// Parse either a **CycloneDX 1.6** JSON document or an **SPDX 3.0** JSON document into normalized `SbomComponent`s.
pub fn parse_sbom_document(json_str: &str) -> Result<(SbomDocumentFormat, Vec<SbomComponent>), String> {
    let root: Value = serde_json::from_str(json_str).map_err(|e| format!("Invalid SBOM JSON: {e}"))?;
    let mut components = Vec::new();

    if root.get("spdxVersion").is_some() || root.get("@context").is_some() {
        // SPDX 3.0 / 2.3 JSON
        if let Some(pkgs) = root["packages"].as_array().or_else(|| root["elements"].as_array()) {
            for p in pkgs {
                let name = p["name"].as_str().unwrap_or("unknown").to_string();
                let version = p["versionInfo"]
                    .as_str()
                    .or_else(|| p["packageVersion"].as_str())
                    .unwrap_or("0.0.0")
                    .to_string();
                let purl = p["purl"]
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("pkg:cargo/{name}@{version}"));
                let spdx_license = p["licenseConcluded"]
                    .as_str()
                    .or_else(|| p["licenseDeclared"].as_str())
                    .unwrap_or("MIT OR Apache-2.0")
                    .to_string();
                components.push(SbomComponent {
                    name,
                    version,
                    purl,
                    spdx_license,
                });
            }
        }
        Ok((SbomDocumentFormat::Spdx3_0, components))
    } else {
        // CycloneDX 1.6 JSON
        if let Some(comps) = root["components"].as_array() {
            for c in comps {
                let name = c["name"].as_str().unwrap_or("unknown").to_string();
                let version = c["version"].as_str().unwrap_or("0.0.0").to_string();
                let purl = c["purl"]
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("pkg:cargo/{name}@{version}"));
                let spdx_license = c["licenses"]
                    .as_array()
                    .and_then(|l| l.first())
                    .and_then(|l| l["license"]["id"].as_str())
                    .unwrap_or("MIT OR Apache-2.0")
                    .to_string();
                components.push(SbomComponent {
                    name,
                    version,
                    purl,
                    spdx_license,
                });
            }
        }
        Ok((SbomDocumentFormat::CycloneDx1_6, components))
    }
}

/// Parse a Rust `Cargo.lock` or Node.js `package-lock.json` text into normalized `SbomComponent`s
/// so enterprise users can generate CycloneDX 1.6 & CSAF 2.0 VEX attestations directly from repository lockfiles.
pub fn parse_lockfile_to_components(lockfile_text: &str) -> Vec<SbomComponent> {
    let trimmed = lockfile_text.trim();
    if trimmed.starts_with('{') {
        // Node.js `package-lock.json`
        let mut out = Vec::new();
        if let Ok(root) = serde_json::from_str::<Value>(trimmed) {
            if let Some(pkgs) = root["packages"].as_object() {
                for (path_key, meta) in pkgs {
                    let name = meta["name"]
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| path_key.trim_start_matches("node_modules/").to_string());
                    if name.is_empty() {
                        continue;
                    }
                    let version = meta["version"].as_str().unwrap_or("0.0.0").to_string();
                    let spdx_license = meta["license"].as_str().unwrap_or("MIT").to_string();
                    out.push(SbomComponent {
                        purl: format!("pkg:npm/{name}@{version}"),
                        name,
                        version,
                        spdx_license,
                    });
                }
            }
        }
        return out;
    }

    // Rust `Cargo.lock` (`[[package]]` blocks)
    let mut components = Vec::new();
    for block in trimmed.split("[[package]]").skip(1) {
        let mut name = String::new();
        let mut version = String::new();
        for line in block.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("name = ") {
                name = rest.trim_matches('"').to_string();
            } else if let Some(rest) = l.strip_prefix("version = ") {
                version = rest.trim_matches('"').to_string();
            }
        }
        if !name.is_empty() && !version.is_empty() {
            components.push(SbomComponent {
                purl: format!("pkg:cargo/{name}@{version}"),
                name,
                version,
                spdx_license: "MIT OR Apache-2.0".to_string(),
            });
        }
    }
    components
}

/// Construct an OWASP Dependency-Track `/api/v1/bom` PUT payload (`DTrackAuditor` protocol compatible).
pub fn build_dependency_track_bom_payload(
    project_name: &str,
    project_version: &str,
    auto_create: bool,
    cyclonedx_json: &str,
) -> Value {
    json!({
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": auto_create,
        "bom": cyclonedx_json
    })
}

/// Generate and cryptographically sign an **EU CRA & German BSI TR-03183 CSAF 2.0 / VEX Attestation**
/// combining SBOM components and `arniko-audit` symbolic remediation proofs.
pub fn generate_csaf_2_0_vex_attestation(
    project_name: &str,
    project_version: &str,
    sbom_format: SbomDocumentFormat,
    components: Vec<SbomComponent>,
    vex_statements: Vec<VexStatement>,
    signing_seed: &str,
) -> CsafVexAttestation {
    let comps_json = serde_json::to_string(&components).unwrap_or_default();
    let vex_json = serde_json::to_string(&vex_statements).unwrap_or_default();
    let material = format!(
        "CSAF-2.0:{project_name}:{project_version}:{sbom_format:?}:{comps_json}:{vex_json}"
    );
    let attestation_blake3 = blake3::hash(material.as_bytes()).to_hex().to_string();

    let key_digest = blake3::hash(format!("dtrack-rs-cra-signer-v3.1:{signing_seed}").as_bytes());
    let signing_key = SigningKey::from_bytes(key_digest.as_bytes());
    let verifying_key = signing_key.verifying_key();
    let sig: Signature = signing_key.sign(attestation_blake3.as_bytes());

    CsafVexAttestation {
        csaf_version: "2.0".into(),
        profile: "csaf_vex (EU-CRA + BSI-TR-03183-2)".into(),
        project_name: project_name.into(),
        project_version: project_version.into(),
        sbom_format,
        components,
        vex_statements,
        attestation_blake3,
        ed25519_pubkey_hex: hex::encode(verifying_key.to_bytes()),
        ed25519_sig_hex: hex::encode(sig.to_bytes()),
    }
}

impl CsafVexAttestation {
    /// Verify the `BLAKE3` digest and `Ed25519` signature of the CSAF 2.0 / VEX attestation bundle.
    pub fn verify_signature(&self) -> bool {
        let comps_json = serde_json::to_string(&self.components).unwrap_or_default();
        let vex_json = serde_json::to_string(&self.vex_statements).unwrap_or_default();
        let material = format!(
            "CSAF-2.0:{}:{}:{:?}:{}:{}",
            self.project_name, self.project_version, self.sbom_format, comps_json, vex_json
        );
        let expected_hash = blake3::hash(material.as_bytes()).to_hex().to_string();
        if expected_hash != self.attestation_blake3 {
            return false;
        }
        let Ok(pk_bytes) = hex::decode(&self.ed25519_pubkey_hex) else {
            return false;
        };
        let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.try_into() else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(&self.ed25519_sig_hex) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(self.attestation_blake3.as_bytes(), &sig).is_ok()
    }
}

/// Evaluate Sabin Ranjit's `DTrackAuditor` CI severity threshold rules
/// (e.g. `"-r critical:1:true,high:2:true,medium:10:false"`).
/// Returns `Ok(())` if all thresholds pass or have `fail=false`, or `Err(reason)` if a blocking rule trips.
pub fn evaluate_dtrack_severity_rules(
    counts_by_severity: &std::collections::BTreeMap<String, usize>,
    rules_spec: &str,
) -> Result<(), String> {
    for raw_rule in rules_spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = raw_rule.split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let sev = parts[0].trim().to_ascii_uppercase();
        let threshold: usize = parts[1].trim().parse().unwrap_or(1);
        let should_fail = matches!(parts[2].trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes");

        let actual = counts_by_severity
            .get(&sev)
            .or_else(|| counts_by_severity.get(&sev.to_ascii_lowercase()))
            .copied()
            .unwrap_or(0);
        if actual >= threshold && should_fail {
            return Err(format!(
                "DTrackAuditor rule tripped: {sev} count ({actual}) >= threshold ({threshold})"
            ));
        }
    }
    Ok(())
}

/// Cross-Framework Compliance Control Mapping (`CriteriaMeter` by Sabin Ranjit):
/// Maps a CWE ID to its corresponding controls across **SLSA v1.2**, **OWASP ASVS 5.0**,
/// **SOC 2**, **GDPR**, **ISO 27001:2022**, and **EU Cyber Resilience Act (CRA)**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriteriaMeterControlMapping {
    pub cwe_id: String,
    pub domain: String,
    pub slsa_v1_2: &'static str,
    pub owasp_asvs_5_0: &'static str,
    pub soc2_tsc: &'static str,
    pub gdpr_art: &'static str,
    pub iso27001_2022: &'static str,
    pub eu_cra_annex_i: &'static str,
}

pub fn map_cwe_to_criteriameter_controls(cwe_id: &str) -> CriteriaMeterControlMapping {
    let norm = cwe_id.trim().to_ascii_uppercase();
    let (domain, slsa, asvs, soc2, gdpr, iso, cra) = match norm.as_str() {
        "CWE-798" => (
            "secret_management",
            "SLSA-BUILD-L2-CREDENTIALS",
            "ASVS-V2.10.4 (No Hardcoded Secrets)",
            "CC6.1 (Logical Access & Secrets)",
            "Art. 32(1)(a) (Pseudonymisation & Encryption)",
            "A.8.24 (Use of Cryptography & Key Mgmt)",
            "CRA-Annex-I-1(2)(f) (Confidentiality of Secrets)",
        ),
        "CWE-295" | "CWE-327" => (
            "cryptography_and_signing",
            "SLSA-PROVENANCE-AUTH",
            "ASVS-V9.1.2 (Strict TLS & Modern Cipher Suites)",
            "CC6.7 (Transmission Integrity)",
            "Art. 32(1)(a) (State-of-the-Art Cryptography)",
            "A.8.24 (Cryptographic Controls)",
            "CRA-Annex-I-1(2)(e) (State-of-the-Art Encryption)",
        ),
        "CWE-78" | "CWE-89" | "CWE-94" => (
            "build_process_integrity",
            "SLSA-BUILD-ISOLATION-L3",
            "ASVS-V5.3.8 (OS Command & Interpreter Injection Defense)",
            "CC7.1 (System Operations & Input Integrity)",
            "Art. 25 (Data Protection by Design)",
            "A.8.28 (Secure Coding Principles)",
            "CRA-Annex-I-1(2)(d) (Protection from Unauthorized Manipulation)",
        ),
        _ => (
            "dependency_management",
            "SLSA-SOURCE-TRACK",
            "ASVS-V14.2.1 (Dependency & SBOM Hygiene)",
            "CC8.1 (Change & Vulnerability Management)",
            "Art. 32(1)(d) (Regular Security Testing)",
            "A.8.8 (Management of Technical Vulnerabilities)",
            "CRA-Annex-I-2(1) (SBOM & Coordinated Vulnerability Handling)",
        ),
    };
    CriteriaMeterControlMapping {
        cwe_id: norm,
        domain: domain.into(),
        slsa_v1_2: slsa,
        owasp_asvs_5_0: asvs,
        soc2_tsc: soc2,
        gdpr_art: gdpr,
        iso27001_2022: iso,
        eu_cra_annex_i: cra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyclonedx_spdx_parsing_and_csaf_2_0_vex_ed25519_signature() {
        let cdx = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"name": "lokahi-gate", "version": "0.2.0", "purl": "pkg:cargo/lokahi-gate@0.2.0"},
                {"name": "arniko-audit", "version": "0.2.0", "purl": "pkg:cargo/arniko-audit@0.2.0"}
            ]
        }"#;
        let (fmt, comps) = parse_sbom_document(cdx).unwrap();
        assert_eq!(fmt, SbomDocumentFormat::CycloneDx1_6);
        assert_eq!(comps.len(), 2);

        let spdx = r#"{
            "spdxVersion": "SPDX-3.0",
            "packages": [
                {"name": "dirgha-core", "versionInfo": "0.2.0", "licenseConcluded": "MIT OR Apache-2.0"}
            ]
        }"#;
        let (spdx_fmt, spdx_comps) = parse_sbom_document(spdx).unwrap();
        assert_eq!(spdx_fmt, SbomDocumentFormat::Spdx3_0);
        assert_eq!(spdx_comps.len(), 1);

        let dtrack_payload = build_dependency_track_bom_payload("dirgha-kernel", "0.2.0", true, cdx);
        assert_eq!(dtrack_payload["projectName"], "dirgha-kernel");

        let vex = vec![VexStatement {
            vulnerability_id: "CVE-2026-4091".into(),
            cwe_id: "CWE-295".into(),
            product_purl: "pkg:cargo/lokahi-gate@0.2.0".into(),
            status: VexStatus::Fixed,
            justification: Some(VexJustification::SymbolicAstPatchApplied),
            remediation_detail: "Patched via ARNIKO-AST-CWE295-TLS-STRICT".into(),
        }];

        let attestation = generate_csaf_2_0_vex_attestation(
            "dirgha-kernel",
            "0.2.0",
            fmt,
            comps,
            vex,
            "sabin-ranjit-dtrack-seed",
        );
        assert!(attestation.verify_signature());

        let cargo_lock = r#"
[[package]]
name = "lokahi-gate"
version = "0.2.0"

[[package]]
name = "dirgha-core"
version = "0.2.0"
"#;
        let parsed_cargo = parse_lockfile_to_components(cargo_lock);
        assert_eq!(parsed_cargo.len(), 2);
        assert_eq!(parsed_cargo[0].purl, "pkg:cargo/lokahi-gate@0.2.0");

        let pkg_lock = r#"{
            "name": "dirgha",
            "packages": {
                "node_modules/commander": { "version": "12.1.0", "license": "MIT" }
            }
        }"#;
        let parsed_npm = parse_lockfile_to_components(pkg_lock);
        assert_eq!(parsed_npm.len(), 1);
        assert_eq!(parsed_npm[0].purl, "pkg:npm/commander@12.1.0");

        // Verify Sabin's DTrackAuditor `-r` severity rule evaluator & CriteriaMeter 6-framework mapper
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("CRITICAL".to_string(), 1);
        counts.insert("HIGH".to_string(), 1);
        assert!(evaluate_dtrack_severity_rules(&counts, "critical:2:true,high:2:true").is_ok());
        assert!(evaluate_dtrack_severity_rules(&counts, "critical:1:true,high:2:true").is_err());

        let cm = map_cwe_to_criteriameter_controls("CWE-798");
        assert_eq!(cm.domain, "secret_management");
        assert!(cm.owasp_asvs_5_0.contains("ASVS-V2.10.4"));
    }
}
