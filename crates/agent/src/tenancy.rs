//! Spec 084 P0 phase 1C — agent-side per-tenant attribution.
//!
//! The sensor (phase 1B) stamps every container-scoped eBPF event with the
//! non-forgeable `container_id` + Kubernetes `pod_uid` parsed straight from the
//! cgroup the kernel wrote. This module turns that `pod_uid` into a human
//! **tenant** by asking the Kubernetes API (over the node's own kubeconfig)
//! which pod owns it and which namespace/label it carries.
//!
//! Design constraints (spec 084 sovereignty + sensor/agent split):
//!   - The SENSOR never calls the k8s API (stays deterministic). All API I/O is
//!     here, in the interpretive agent.
//!   - Tenant resolution is a node-local read of the cluster the agent already
//!     runs in (kubeconfig on disk); nothing leaves the host.
//!   - The resolver is a refreshed cache (slow-loop, `refresh_secs`); incident
//!     enrichment is a synchronous cache read on the hot path.
//!
//! Tenant id precedence: pod label[`tenant_label_key`] -> namespace
//! label[`tenant_label_key`] -> namespace name. A pod with no tenant label in a
//! namespace with no tenant label is attributed to its namespace, so a plain
//! `kubectl run` is still grouped sanely.

use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

/// `[tenancy]` agent config section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TenancyConfig {
    /// Master switch. When false this module is entirely inert (no API calls,
    /// no enrichment) — the default, so non-k8s hosts pay nothing.
    pub enabled: bool,
    /// Path to the kubeconfig the agent uses to read pods. Defaults to the k3s
    /// location, then the standard one, when unset.
    pub kubeconfig_path: Option<String>,
    /// Label key whose value names the tenant. Checked on the pod first, then
    /// its namespace.
    pub tenant_label_key: String,
    /// How often (seconds) the slow loop refreshes the pod cache.
    pub refresh_secs: u64,
}

impl Default for TenancyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kubeconfig_path: None,
            tenant_label_key: "innerwarden.io/tenant".to_string(),
            refresh_secs: 60,
        }
    }
}

impl TenancyConfig {
    /// Resolve the kubeconfig path: explicit config, then the k3s default, then
    /// the standard `~/.kube/config`.
    fn resolved_kubeconfig_path(&self) -> Option<String> {
        if let Some(p) = &self.kubeconfig_path {
            return Some(p.clone());
        }
        for cand in ["/etc/rancher/k3s/k3s.yaml"] {
            if std::path::Path::new(cand).exists() {
                return Some(cand.to_string());
            }
        }
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.kube/config"))
            .filter(|p| std::path::Path::new(p).exists())
    }
}

/// The resolved identity of one pod, keyed in the cache by `pod_uid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodIdentity {
    pub pod_uid: String,
    pub namespace: String,
    pub pod_name: String,
    pub tenant_id: String,
    /// 12-char container ids belonging to this pod (lets us resolve an event
    /// that only carries `container_id`, not `pod_uid`).
    pub container_ids: Vec<String>,
}

#[derive(Default)]
struct Cache {
    by_pod_uid: HashMap<String, PodIdentity>,
    by_container_id: HashMap<String, String>, // 12-char container id -> pod_uid
    last_refresh: Option<Instant>,
}

fn cache() -> &'static RwLock<Cache> {
    static CACHE: OnceLock<RwLock<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(Cache::default()))
}

// ───────────────────────── kubeconfig (pure) ─────────────────────────

/// Just enough of a kubeconfig to reach the API server with the current
/// context's cluster + user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiAccess {
    pub server: String,
    pub ca_pem: Option<Vec<u8>>,
    /// client cert PEM ++ client key PEM, ready for `reqwest::Identity::from_pem`.
    pub client_identity_pem: Option<Vec<u8>>,
    pub token: Option<String>,
    pub insecure: bool,
}

#[derive(Deserialize)]
struct KcCluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    ca_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify")]
    insecure: Option<bool>,
}
#[derive(Deserialize)]
struct KcUser {
    #[serde(rename = "client-certificate-data")]
    cert_data: Option<String>,
    #[serde(rename = "client-key-data")]
    key_data: Option<String>,
    token: Option<String>,
}
#[derive(Deserialize)]
struct KcNamedCluster {
    name: String,
    cluster: KcCluster,
}
#[derive(Deserialize)]
struct KcNamedUser {
    name: String,
    user: KcUser,
}
#[derive(Deserialize)]
struct KcContextInner {
    cluster: String,
    user: String,
}
#[derive(Deserialize)]
struct KcNamedContext {
    name: String,
    context: KcContextInner,
}
#[derive(Deserialize)]
struct Kubeconfig {
    clusters: Vec<KcNamedCluster>,
    users: Vec<KcNamedUser>,
    contexts: Vec<KcNamedContext>,
    #[serde(rename = "current-context")]
    current_context: String,
}

/// Parse a kubeconfig YAML into the access bits for the current context.
pub fn parse_kubeconfig(yaml: &str) -> Result<ApiAccess, String> {
    let kc: Kubeconfig = serde_yaml::from_str(yaml).map_err(|e| format!("yaml: {e}"))?;
    let ctx = kc
        .contexts
        .iter()
        .find(|c| c.name == kc.current_context)
        .ok_or_else(|| format!("current-context {} not found", kc.current_context))?;
    let cluster = kc
        .clusters
        .iter()
        .find(|c| c.name == ctx.context.cluster)
        .ok_or_else(|| format!("cluster {} not found", ctx.context.cluster))?;
    let user = kc
        .users
        .iter()
        .find(|u| u.name == ctx.context.user)
        .ok_or_else(|| format!("user {} not found", ctx.context.user))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let ca_pem = match &cluster.cluster.ca_data {
        Some(d) => Some(b64.decode(d).map_err(|e| format!("ca b64: {e}"))?),
        None => None,
    };
    let client_identity_pem = match (&user.user.cert_data, &user.user.key_data) {
        (Some(c), Some(k)) => {
            let mut pem = b64.decode(c).map_err(|e| format!("cert b64: {e}"))?;
            if !pem.ends_with(b"\n") {
                pem.push(b'\n');
            }
            pem.extend_from_slice(&b64.decode(k).map_err(|e| format!("key b64: {e}"))?);
            Some(pem)
        }
        _ => None,
    };
    Ok(ApiAccess {
        server: cluster.cluster.server.clone(),
        ca_pem,
        client_identity_pem,
        token: user.user.token.clone(),
        insecure: cluster.cluster.insecure.unwrap_or(false),
    })
}

// ───────────────────────── PodList parsing (pure) ─────────────────────────

#[derive(Deserialize)]
struct PlMeta {
    uid: String,
    name: String,
    namespace: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}
#[derive(Deserialize)]
struct PlContainerStatus {
    #[serde(rename = "containerID")]
    container_id: Option<String>,
}
#[derive(Deserialize)]
struct PlPodStatus {
    #[serde(default, rename = "containerStatuses")]
    container_statuses: Vec<PlContainerStatus>,
}
#[derive(Deserialize)]
struct PlPod {
    metadata: PlMeta,
    #[serde(default)]
    status: Option<PlPodStatus>,
}
#[derive(Deserialize)]
struct PlList {
    #[serde(default)]
    items: Vec<PlPod>,
}

#[derive(Deserialize)]
struct NsMeta {
    name: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}
#[derive(Deserialize)]
struct NsItem {
    metadata: NsMeta,
}
#[derive(Deserialize)]
struct NsList {
    #[serde(default)]
    items: Vec<NsItem>,
}

/// `containerd://<64hex>` / `docker://<id>` -> 12-char id matching the sensor.
fn short_container_id(raw: &str) -> Option<String> {
    let id = raw.rsplit("//").next().unwrap_or(raw);
    if id.len() >= 12 && id.as_bytes()[..12].iter().all(|b| b.is_ascii_hexdigit()) {
        Some(id[..12].to_string())
    } else {
        None
    }
}

/// Derive the tenant id from pod labels, falling back to namespace labels, then
/// the namespace name.
fn derive_tenant(
    pod_labels: &HashMap<String, String>,
    ns_labels: Option<&HashMap<String, String>>,
    namespace: &str,
    key: &str,
) -> String {
    if let Some(t) = pod_labels.get(key) {
        return t.clone();
    }
    if let Some(t) = ns_labels.and_then(|m| m.get(key)) {
        return t.clone();
    }
    namespace.to_string()
}

/// Parse a k8s PodList (+ NamespaceList for namespace-level labels) into
/// `PodIdentity` rows. Pure — unit-testable against captured API JSON.
pub fn parse_pod_list(
    pods_json: &str,
    namespaces_json: &str,
    tenant_label_key: &str,
) -> Result<Vec<PodIdentity>, String> {
    let pods: PlList = serde_json::from_str(pods_json).map_err(|e| format!("pods json: {e}"))?;
    let ns_labels: HashMap<String, HashMap<String, String>> =
        match serde_json::from_str::<NsList>(namespaces_json) {
            Ok(n) => n
                .items
                .into_iter()
                .map(|i| (i.metadata.name, i.metadata.labels))
                .collect(),
            Err(_) => HashMap::new(), // namespaces optional; fall back to ns name
        };

    let mut out = Vec::with_capacity(pods.items.len());
    for p in pods.items {
        let container_ids: Vec<String> = p
            .status
            .as_ref()
            .map(|s| {
                s.container_statuses
                    .iter()
                    .filter_map(|c| c.container_id.as_deref().and_then(short_container_id))
                    .collect()
            })
            .unwrap_or_default();
        let tenant_id = derive_tenant(
            &p.metadata.labels,
            ns_labels.get(&p.metadata.namespace),
            &p.metadata.namespace,
            tenant_label_key,
        );
        out.push(PodIdentity {
            pod_uid: p.metadata.uid,
            namespace: p.metadata.namespace,
            pod_name: p.metadata.name,
            tenant_id,
            container_ids,
        });
    }
    Ok(out)
}

fn install_into_cache(pods: Vec<PodIdentity>) {
    let mut c = cache().write().unwrap_or_else(|e| e.into_inner());
    c.by_pod_uid.clear();
    c.by_container_id.clear();
    for p in pods {
        for cid in &p.container_ids {
            c.by_container_id.insert(cid.clone(), p.pod_uid.clone());
        }
        c.by_pod_uid.insert(p.pod_uid.clone(), p);
    }
    c.last_refresh = Some(Instant::now());
}

// ───────────────────────── live refresh (I/O) ─────────────────────────

/// Refresh the pod cache from the Kubernetes API, but only if at least
/// `refresh_secs` have elapsed since the last refresh. Safe to call every slow
/// tick. Inert when `enabled = false`.
pub async fn maybe_refresh(cfg: &TenancyConfig) {
    if !cfg.enabled {
        return;
    }
    let due = {
        let c = cache().read().unwrap_or_else(|e| e.into_inner());
        match c.last_refresh {
            Some(t) => t.elapsed() >= Duration::from_secs(cfg.refresh_secs.max(5)),
            None => true,
        }
    };
    if !due {
        return;
    }
    if let Err(e) = refresh_now(cfg).await {
        tracing::warn!("tenancy: pod cache refresh failed: {e}");
        // Stamp last_refresh so a hard failure (no cluster) backs off instead of
        // hammering the API every tick.
        let mut c = cache().write().unwrap_or_else(|e| e.into_inner());
        c.last_refresh = Some(Instant::now());
    }
}

async fn refresh_now(cfg: &TenancyConfig) -> Result<(), String> {
    let path = cfg
        .resolved_kubeconfig_path()
        .ok_or_else(|| "no kubeconfig found".to_string())?;
    let yaml = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("read {path}: {e}"))?;
    let access = parse_kubeconfig(&yaml)?;
    let client = build_client(&access)?;

    let pods_json = api_get(&client, &access, "/api/v1/pods").await?;
    let ns_json = api_get(&client, &access, "/api/v1/namespaces")
        .await
        .unwrap_or_else(|_| "{}".to_string());
    let pods = parse_pod_list(&pods_json, &ns_json, &cfg.tenant_label_key)?;
    let n = pods.len();
    install_into_cache(pods);
    tracing::info!("tenancy: pod cache refreshed ({n} pods)");
    Ok(())
}

fn build_client(access: &ApiAccess) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(10));
    if access.insecure {
        b = b.danger_accept_invalid_certs(true);
    } else if let Some(ca) = &access.ca_pem {
        let cert = reqwest::Certificate::from_pem(ca).map_err(|e| format!("ca pem: {e}"))?;
        b = b.add_root_certificate(cert);
    }
    if let Some(id) = &access.client_identity_pem {
        let identity =
            reqwest::Identity::from_pem(id).map_err(|e| format!("client identity: {e}"))?;
        b = b.identity(identity);
    }
    b.build().map_err(|e| format!("client build: {e}"))
}

async fn api_get(
    client: &reqwest::Client,
    access: &ApiAccess,
    path: &str,
) -> Result<String, String> {
    let url = format!("{}{}", access.server.trim_end_matches('/'), path);
    let mut req = client.get(&url);
    if let Some(tok) = &access.token {
        req = req.bearer_auth(tok);
    }
    let resp = req.send().await.map_err(|e| format!("GET {path}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {path}: HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| format!("body {path}: {e}"))
}

// ───────────────────────── lookup + enrichment ─────────────────────────

/// Resolve a `pod_uid` (or 12-char `container_id`) to its pod identity from the
/// cache. Synchronous, hot-path safe.
pub fn resolve(pod_uid: Option<&str>, container_id: Option<&str>) -> Option<PodIdentity> {
    let c = cache().read().unwrap_or_else(|e| e.into_inner());
    if let Some(uid) = pod_uid {
        if let Some(p) = c.by_pod_uid.get(uid) {
            return Some(p.clone());
        }
    }
    if let Some(cid) = container_id {
        let short = if cid.len() > 12 { &cid[..12] } else { cid };
        if let Some(uid) = c.by_container_id.get(short) {
            if let Some(p) = c.by_pod_uid.get(uid) {
                return Some(p.clone());
            }
        }
    }
    None
}

/// Pull `pod_uid` / `container_id` from an incident (evidence first, then a
/// container entity) and, when the cache resolves a tenant, stamp
/// `tenant_id` / `namespace` / `pod_name` into the evidence and a `tenant:<id>`
/// tag. No-op when tenancy is disabled or the incident is not container-scoped.
pub fn enrich_incident(incident: &mut innerwarden_core::incident::Incident, cfg: &TenancyConfig) {
    if !cfg.enabled {
        return;
    }
    let pod_uid = incident
        .evidence
        .get("pod_uid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut container_id = incident
        .evidence
        .get("container_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            incident
                .entities
                .iter()
                .find(|e| e.r#type == innerwarden_core::entities::EntityType::Container)
                .map(|e| e.value.clone())
        });
    // Fallback: several sensor detectors key the incident_id on the container
    // (e.g. `container_escape:<cid>:...`) but do not copy the id into evidence
    // or a container entity. Scan the id's `:`-tokens for one the pod cache
    // recognises as a real container, so these incidents still attribute.
    if pod_uid.is_none() && container_id.is_none() {
        container_id = incident
            .incident_id
            .split(':')
            .find(|tok| {
                tok.len() >= 12
                    && tok.as_bytes()[..12].iter().all(|b| b.is_ascii_hexdigit())
                    && resolve(None, Some(tok)).is_some()
            })
            .map(|s| s.to_string());
    }
    if pod_uid.is_none() && container_id.is_none() {
        return;
    }
    let Some(pod) = resolve(pod_uid.as_deref(), container_id.as_deref()) else {
        return;
    };
    if let Some(obj) = incident.evidence.as_object_mut() {
        obj.insert("tenant_id".to_string(), pod.tenant_id.clone().into());
        obj.insert("namespace".to_string(), pod.namespace.clone().into());
        obj.insert("pod_name".to_string(), pod.pod_name.clone().into());
        obj.insert("pod_uid".to_string(), pod.pod_uid.clone().into());
    }
    let tag = format!("tenant:{}", pod.tenant_id);
    if !incident.tags.contains(&tag) {
        incident.tags.push(tag);
    }
    // Observable per-incident attribution (greppable on the box; the aggregate
    // is the per-tenant telemetry counter). Only fires for container-scoped
    // incidents that resolve to a tenant, so host incidents stay quiet. The
    // tenant/namespace/pod are formatted INTO the message (not as structured
    // fields) so the line is greppable under any tracing fmt layer — the
    // journald/systemd default the agent runs under does not render k-v fields.
    tracing::info!(
        "tenancy: incident {} attributed to tenant {} (namespace {}, pod {})",
        incident.incident_id,
        pod.tenant_id,
        pod.namespace,
        pod.pod_name
    );
}

/// Enrich a batch of incidents in place (the agent's pre-pass before the
/// read-only processing loops take references).
pub fn enrich_incidents(
    incidents: &mut [innerwarden_core::incident::Incident],
    cfg: &TenancyConfig,
) {
    if !cfg.enabled {
        return;
    }
    for inc in incidents.iter_mut() {
        enrich_incident(inc, cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::entities::EntityRef;
    use innerwarden_core::event::Severity;
    use innerwarden_core::incident::Incident;

    fn reset_cache_with(pods: Vec<PodIdentity>) {
        install_into_cache(pods);
    }

    // REAL PodList JSON projected from a live k3s v1.36 node (2026-06-29). The
    // pod uid + containerID + tenant label are the actual API values, matching
    // the cgroup-derived gold fixtures in the sensor.
    const REAL_PODS_JSON: &str = r#"{
      "items": [
        {"metadata": {"uid": "d729dbb9-5684-498d-9c5f-7244bfbba548",
          "name": "agent-a", "namespace": "tenant-a",
          "labels": {"app": "ai-agent", "innerwarden.io/tenant": "acme-corp"}},
         "status": {"containerStatuses": [
            {"containerID": "containerd://4858a7b75b55f36c13e0991cf8370fd2d05edbf33d7d813c06f4cb7a24318025"}]}},
        {"metadata": {"uid": "b9b2ae1e-9f07-4656-b1f5-71d0f7cb6191",
          "name": "agent-b", "namespace": "tenant-b",
          "labels": {"app": "ai-agent", "innerwarden.io/tenant": "globex-inc"}},
         "status": {"containerStatuses": [
            {"containerID": "containerd://1a0fb1e4f294cafd9e0da8c2e65de9310bccf1f6f6c950ecb09aa5f9343dfa1c"}]}}
      ]
    }"#;

    const REAL_NS_JSON: &str = r#"{"items": [
        {"metadata": {"name": "tenant-a", "labels": {"innerwarden.io/tenant": "acme-corp"}}},
        {"metadata": {"name": "tenant-b", "labels": {"innerwarden.io/tenant": "globex-inc"}}}]}"#;

    #[test]
    fn parse_real_pod_list_maps_uid_container_tenant() {
        let pods = parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap();
        assert_eq!(pods.len(), 2);
        let a = pods.iter().find(|p| p.namespace == "tenant-a").unwrap();
        assert_eq!(a.pod_uid, "d729dbb9-5684-498d-9c5f-7244bfbba548");
        assert_eq!(a.tenant_id, "acme-corp");
        assert_eq!(a.container_ids, vec!["4858a7b75b55".to_string()]);
        let b = pods.iter().find(|p| p.namespace == "tenant-b").unwrap();
        assert_eq!(b.tenant_id, "globex-inc");
        assert_eq!(b.container_ids, vec!["1a0fb1e4f294".to_string()]);
    }

    #[test]
    fn tenant_falls_back_to_namespace_then_label() {
        let mut pl = HashMap::new();
        let mut nsl = HashMap::new();
        // no labels anywhere -> namespace name
        assert_eq!(
            derive_tenant(&pl, None, "team-x", "innerwarden.io/tenant"),
            "team-x"
        );
        // namespace label wins over name
        nsl.insert("innerwarden.io/tenant".to_string(), "ns-tenant".to_string());
        assert_eq!(
            derive_tenant(&pl, Some(&nsl), "team-x", "innerwarden.io/tenant"),
            "ns-tenant"
        );
        // pod label wins over namespace
        pl.insert(
            "innerwarden.io/tenant".to_string(),
            "pod-tenant".to_string(),
        );
        assert_eq!(
            derive_tenant(&pl, Some(&nsl), "team-x", "innerwarden.io/tenant"),
            "pod-tenant"
        );
    }

    #[test]
    fn parse_real_kubeconfig_shape() {
        // base64("X") placeholders for the cert/key/ca blobs.
        let b64 = base64::engine::general_purpose::STANDARD;
        let ca = b64.encode("CA-PEM");
        let cert = b64.encode("CERT-PEM");
        let key = b64.encode("KEY-PEM");
        let yaml = format!(
            r#"apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {ca}
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
users:
- name: default
  user:
    client-certificate-data: {cert}
    client-key-data: {key}
"#
        );
        let acc = parse_kubeconfig(&yaml).unwrap();
        assert_eq!(acc.server, "https://127.0.0.1:6443");
        assert_eq!(acc.ca_pem.as_deref(), Some(&b"CA-PEM"[..]));
        let id = acc.client_identity_pem.unwrap();
        assert!(id.starts_with(b"CERT-PEM"));
        assert!(id.ends_with(b"KEY-PEM"));
    }

    #[test]
    fn short_container_id_strips_runtime_prefix() {
        assert_eq!(
            short_container_id("containerd://4858a7b75b55f36c"),
            Some("4858a7b75b55".to_string())
        );
        assert_eq!(short_container_id("docker://short"), None);
    }

    #[test]
    fn parse_kubeconfig_token_user() {
        // A token-auth user (no client cert) yields a token + no identity.
        let b64 = base64::engine::general_purpose::STANDARD;
        let ca = b64.encode("CA");
        let yaml = format!(
            r#"apiVersion: v1
clusters:
- cluster: {{certificate-authority-data: {ca}, server: https://api:6443}}
  name: c
contexts:
- context: {{cluster: c, user: u}}
  name: ctx
current-context: ctx
users:
- name: u
  user: {{token: sha256~abc}}
"#
        );
        let acc = parse_kubeconfig(&yaml).unwrap();
        assert_eq!(acc.token.as_deref(), Some("sha256~abc"));
        assert!(acc.client_identity_pem.is_none());
        assert_eq!(acc.server, "https://api:6443");
    }

    #[test]
    fn parse_kubeconfig_unknown_context_errors() {
        let yaml =
            "apiVersion: v1\nclusters: []\nusers: []\ncontexts: []\ncurrent-context: missing\n";
        assert!(parse_kubeconfig(yaml).is_err());
    }

    #[test]
    fn build_client_variants_construct() {
        // insecure: skips TLS verification, still builds.
        let insecure = ApiAccess {
            server: "https://127.0.0.1:6443".to_string(),
            ca_pem: None,
            client_identity_pem: None,
            token: Some("t".to_string()),
            insecure: true,
        };
        assert!(build_client(&insecure).is_ok());
        // no CA, no identity, not insecure: still builds (uses default roots).
        let bare = ApiAccess {
            insecure: false,
            ..insecure.clone()
        };
        assert!(build_client(&bare).is_ok());
    }

    #[test]
    fn resolved_kubeconfig_path_prefers_explicit() {
        let cfg = TenancyConfig {
            kubeconfig_path: Some("/custom/kubeconfig".to_string()),
            ..Default::default()
        };
        assert_eq!(
            cfg.resolved_kubeconfig_path().as_deref(),
            Some("/custom/kubeconfig")
        );
    }

    #[tokio::test]
    async fn maybe_refresh_disabled_is_noop() {
        // enabled = false must return without any cache mutation or panic.
        maybe_refresh(&TenancyConfig::default()).await;
    }

    #[test]
    fn resolve_by_pod_uid_and_container_id() {
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        // by pod_uid
        let p = resolve(Some("d729dbb9-5684-498d-9c5f-7244bfbba548"), None).unwrap();
        assert_eq!(p.tenant_id, "acme-corp");
        // by 12-char container_id
        let p = resolve(None, Some("1a0fb1e4f294")).unwrap();
        assert_eq!(p.tenant_id, "globex-inc");
        // by 64-char container_id (truncated to 12 internally)
        let p = resolve(
            None,
            Some("4858a7b75b55f36c13e0991cf8370fd2d05edbf33d7d813c06f4cb7a24318025"),
        )
        .unwrap();
        assert_eq!(p.tenant_id, "acme-corp");
        // unknown
        assert!(resolve(Some("00000000-0000-0000-0000-000000000000"), None).is_none());
    }

    #[test]
    fn enrich_incident_stamps_tenant_from_pod_uid() {
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        let cfg = TenancyConfig {
            enabled: true,
            ..Default::default()
        };
        let mut inc = Incident {
            ts: chrono::Utc::now(),
            host: "node1".to_string(),
            incident_id: "reverse_shell:1".to_string(),
            severity: Severity::High,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({"pod_uid": "b9b2ae1e-9f07-4656-b1f5-71d0f7cb6191"}),
            recommended_checks: vec![],
            tags: vec!["ebpf".to_string()],
            entities: vec![],
        };
        enrich_incident(&mut inc, &cfg);
        assert_eq!(inc.evidence["tenant_id"], "globex-inc");
        assert_eq!(inc.evidence["namespace"], "tenant-b");
        assert_eq!(inc.evidence["pod_name"], "agent-b");
        assert!(inc.tags.contains(&"tenant:globex-inc".to_string()));
    }

    #[test]
    fn enrich_incident_resolves_via_container_entity() {
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        let cfg = TenancyConfig {
            enabled: true,
            ..Default::default()
        };
        let mut inc = Incident {
            ts: chrono::Utc::now(),
            host: "node1".to_string(),
            incident_id: "privesc:1".to_string(),
            severity: Severity::Critical,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({"comm": "id"}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::container("4858a7b75b55")],
        };
        enrich_incident(&mut inc, &cfg);
        assert_eq!(inc.evidence["tenant_id"], "acme-corp");
    }

    #[test]
    fn enrich_incident_attributes_array_evidence_via_container_entity() {
        // The real demo path: the sensor's behavioural detectors (reverse_shell,
        // crypto_miner, ...) emit ARRAY evidence and the sensor's central
        // `stamp_tenancy` re-attaches the container id as a Container ENTITY (it
        // cannot write a top-level evidence key into an array). On array evidence
        // the tenant_id evidence write is a no-op, so the operator-visible proof of
        // attribution is the `tenant:<id>` TAG. This is the exact incident shape the
        // sensor produces; it must still resolve to the right tenant.
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        let cfg = TenancyConfig {
            enabled: true,
            ..Default::default()
        };
        let mut inc = Incident {
            ts: chrono::Utc::now(),
            host: "node1".to_string(),
            incident_id: "reverse_shell:bash_dev_tcp:1234:2026-06-29T14:13Z".to_string(),
            severity: Severity::Critical,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!([{ "kind": "reverse_shell", "pid": 1234 }]),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![EntityRef::container("4858a7b75b55")],
        };
        enrich_incident(&mut inc, &cfg);
        assert!(
            inc.tags.contains(&"tenant:acme-corp".to_string()),
            "array-evidence container incident must still get the tenant tag, got {:?}",
            inc.tags
        );
        // Evidence stays an array (no shape flip); the tag is the attribution signal.
        assert!(inc.evidence.is_array());
    }

    // Real-world shape from test001: `container_escape` (and several other
    // sensor detectors) key the incident_id on the container id but do NOT copy
    // it into evidence or a container entity — enrich must still attribute it.
    #[test]
    fn enrich_incident_resolves_via_incident_id_token() {
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        let cfg = TenancyConfig {
            enabled: true,
            ..Default::default()
        };
        let mut inc = Incident {
            ts: chrono::Utc::now(),
            host: "node1".to_string(),
            incident_id: "container_escape:4858a7b75b55:sensitive_file_access:2026-06-29T14:13Z"
                .to_string(),
            severity: Severity::High,
            title: "t".to_string(),
            summary: "s".to_string(),
            // No pod_uid / container_id in evidence and no container entity.
            evidence: serde_json::json!({"detail": "x"}),
            recommended_checks: vec![],
            tags: vec!["container".to_string()],
            entities: vec![],
        };
        enrich_incident(&mut inc, &cfg);
        assert_eq!(inc.evidence["tenant_id"], "acme-corp");
        assert!(inc.tags.contains(&"tenant:acme-corp".to_string()));
    }

    #[test]
    fn disabled_config_is_inert() {
        reset_cache_with(
            parse_pod_list(REAL_PODS_JSON, REAL_NS_JSON, "innerwarden.io/tenant").unwrap(),
        );
        let cfg = TenancyConfig::default(); // enabled = false
        let mut inc = Incident {
            ts: chrono::Utc::now(),
            host: "node1".to_string(),
            incident_id: "x:1".to_string(),
            severity: Severity::Low,
            title: "t".to_string(),
            summary: "s".to_string(),
            evidence: serde_json::json!({"pod_uid": "d729dbb9-5684-498d-9c5f-7244bfbba548"}),
            recommended_checks: vec![],
            tags: vec![],
            entities: vec![],
        };
        enrich_incident(&mut inc, &cfg);
        assert!(inc.evidence.get("tenant_id").is_none());
        assert!(inc.tags.is_empty());
    }

    // Live integration: exercises the real reqwest-rustls client-cert handshake
    // against the node's own Kubernetes API. Ignored by default (needs a working
    // kubeconfig + cluster). On a k3s node:
    //   cargo test -p innerwarden-agent tenancy::tests::live_refresh -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires a live Kubernetes cluster + readable kubeconfig"]
    async fn live_refresh_against_local_cluster() {
        let cfg = TenancyConfig {
            enabled: true,
            refresh_secs: 0,
            ..Default::default()
        };
        refresh_now(&cfg).await.expect("live refresh must succeed");
        let n = cache().read().unwrap().by_pod_uid.len();
        assert!(n > 0, "expected pods from the live cluster, got {n}");
        let any_uid = cache()
            .read()
            .unwrap()
            .by_pod_uid
            .keys()
            .next()
            .cloned()
            .unwrap();
        let pod = resolve(Some(&any_uid), None).expect("a cached pod must resolve");
        eprintln!(
            "live: resolved {n} pods; sample pod {} ns={} tenant={}",
            pod.pod_name, pod.namespace, pod.tenant_id
        );
    }

    // Drive the full refresh I/O path (build_client -> api_get x2 ->
    // parse_pod_list -> install_into_cache) against a mock Kubernetes API, so it
    // is covered without a live cluster. Insecure HTTP + token auth keeps it
    // off the TLS path (that is covered separately).
    #[tokio::test]
    async fn refresh_now_against_mock_k8s_api() {
        let mut server = mockito::Server::new_async().await;
        let pods = server
            .mock("GET", "/api/v1/pods")
            .with_status(200)
            .with_body(REAL_PODS_JSON)
            .create_async()
            .await;
        let ns = server
            .mock("GET", "/api/v1/namespaces")
            .with_status(200)
            .with_body(REAL_NS_JSON)
            .create_async()
            .await;

        let kc = format!(
            "apiVersion: v1\nclusters:\n- cluster: {{server: {url}, insecure-skip-tls-verify: true}}\n  name: c\ncontexts:\n- context: {{cluster: c, user: u}}\n  name: ctx\ncurrent-context: ctx\nusers:\n- name: u\n  user: {{token: t}}\n",
            url = server.url()
        );
        let path = std::env::temp_dir().join("iw_tenancy_mock_kubeconfig.yaml");
        std::fs::write(&path, kc).unwrap();
        let cfg = TenancyConfig {
            enabled: true,
            kubeconfig_path: Some(path.to_string_lossy().into_owned()),
            refresh_secs: 0,
            ..Default::default()
        };

        refresh_now(&cfg)
            .await
            .expect("refresh against the mock API must succeed");
        pods.assert_async().await;
        ns.assert_async().await;

        let p = resolve(Some("d729dbb9-5684-498d-9c5f-7244bfbba548"), None)
            .expect("a pod from the mock cluster must resolve");
        assert_eq!(p.tenant_id, "acme-corp");
        assert_eq!(p.namespace, "tenant-a");
        assert!(resolve(None, Some("4858a7b75b55")).is_some());

        // maybe_refresh on the same enabled cfg exercises the orchestration
        // wrapper (just-refreshed -> not due -> early return).
        maybe_refresh(&cfg).await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn refresh_error_paths_back_off_not_panic() {
        // Missing kubeconfig: refresh_now returns Err deterministically, and
        // maybe_refresh swallows it (warn + stamp), never panicking.
        let cfg = TenancyConfig {
            enabled: true,
            kubeconfig_path: Some("/nonexistent/iw-tenancy/kubeconfig".to_string()),
            refresh_secs: 0,
            ..Default::default()
        };
        assert!(refresh_now(&cfg).await.is_err());
        maybe_refresh(&cfg).await;
    }

    // A self-signed EC cert/key (generated for tests only) to exercise the TLS
    // branches of build_client: the custom-CA root and the client-cert identity.
    const TEST_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBijCCAS+gAwIBAgIUNfRDzIMajrwDOsuNUYUF9jnNNr4wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPaXctdGVuYW5jeS10ZXN0MB4XDTI2MDYyOTEyMDU1NFoXDTM2
MDYyNjEyMDU1NFowGjEYMBYGA1UEAwwPaXctdGVuYW5jeS10ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEAT0o4GKnX6F9Cyy8kaAyO4ywmM0Zkg5/U3NgI1wI
pa6loB4IEqZi9QwcAAYIM8IqPbZaUmT3f5lHOoFbogEZPKNTMFEwHQYDVR0OBBYE
FCbScJthZYXbDKweJJlzZW6PL0L+MB8GA1UdIwQYMBaAFCbScJthZYXbDKweJJlz
ZW6PL0L+MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAIlB4rQE
v7NI6zMx0CBUSoS8sEA1mP8T3jfqxlf3FtELAiEAhIlIf7+7I2hwLcJq7Cp2w8ls
XfWxG3b+iSoDRiyOECI=
-----END CERTIFICATE-----
"#;
    const TEST_KEY_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIjS9B5YV4sxJndLQ0kaeveYqng0R1+kQJYCgz/Bf9xEoAoGCCqGSM49
AwEHoUQDQgAEAT0o4GKnX6F9Cyy8kaAyO4ywmM0Zkg5/U3NgI1wIpa6loB4IEqZi
9QwcAAYIM8IqPbZaUmT3f5lHOoFbogEZPA==
-----END EC PRIVATE KEY-----
"#;

    #[test]
    fn build_client_with_ca_and_client_identity() {
        let mut identity = TEST_CA_PEM.as_bytes().to_vec();
        identity.extend_from_slice(TEST_KEY_PEM.as_bytes());
        let acc = ApiAccess {
            server: "https://127.0.0.1:6443".to_string(),
            ca_pem: Some(TEST_CA_PEM.as_bytes().to_vec()),
            client_identity_pem: Some(identity),
            token: None,
            insecure: false,
        };
        assert!(
            build_client(&acc).is_ok(),
            "client with a custom CA + client identity must build"
        );
    }
}
