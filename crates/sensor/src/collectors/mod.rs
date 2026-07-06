pub mod audit_state;
pub mod auth_log;
pub mod cloudtrail;
pub mod dns_capture;
pub mod docker;
pub mod ebpf_syscall;
pub mod exec_audit;
pub mod fanotify_watch;
pub mod file_extract;
pub mod firmware_integrity;
pub mod http_capture;
pub mod integrity;
pub mod journald;
pub mod kernel_integrity;
pub mod log_state;
pub mod macos_log;
pub mod net_snapshot;
pub mod nginx_access;
pub mod nginx_error;
pub mod proc_maps;
pub mod proto_http;
pub mod proto_smb;
pub mod proto_ssh;
pub mod suid_inventory;
pub mod sysctl_drift;
pub mod syslog_firewall;
pub mod systemd_inventory;
pub mod tcp_stream;
// The pure TLS ClientHello parser + JA3/JA4 hashing logic does not
// need `aya`/`aya-log`, so the module compiles without the `ebpf`
// feature. The eBPF-backed packet pump that feeds the parser is
// gated internally (search for `cfg(all(target_os = "linux",
// feature = "ebpf"))` inside the module). Leaving the outer gate on
// broke the `tls_client_hello` fuzz target because the fuzz
// workflow builds the sensor without the `ebpf` feature.
//
// `cfg_attr` scopes the dead-code + unused-import silence to
// non-ebpf builds: when the feature is off no sensor code path
// calls the parser (only the fuzz target does, from outside the
// crate), so the items look unused to `-D warnings`. Under the
// ebpf feature the collector pump uses them and the allows are
// a no-op.
#[cfg_attr(not(feature = "ebpf"), allow(dead_code, unused_imports))]
pub mod tls_fingerprint;
pub mod tunnel_iface;
pub mod usb_monitor;
/// Windows ETW / Event Log collector (spec 085). The pure XML parser +
/// its watermark helpers compile and unit-test on every platform; the
/// `run` collector only does useful work on Windows (its `wevtutil` probe
/// fails open elsewhere) and is only spawned under
/// `cfg!(target_os = "windows")` in `boot::spawn_collectors`.
pub mod windows_etw;
