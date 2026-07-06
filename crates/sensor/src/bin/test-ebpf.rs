//! Minimal test binary to verify eBPF programs load and attach.
//! Run: sudo ./target/release/test-ebpf
//!
//! This embeds the compiled eBPF bytecode and tests:
//! 1. Loading into kernel
//! 2. Attaching to tracepoints
//! 3. Reading events from ring buffer

#[cfg(any(test, feature = "ebpf"))]
#[derive(Debug, PartialEq, Eq)]
enum EbpfEventSummary {
    Exec {
        pid: u32,
        comm: String,
    },
    Connect {
        pid: u32,
        comm: String,
        ip: String,
        port: u16,
    },
}

#[cfg(any(test, feature = "ebpf"))]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(bytes))
}

#[cfg(any(test, feature = "ebpf"))]
fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_ne_bytes(bytes))
}

#[cfg(any(test, feature = "ebpf"))]
fn read_comm(data: &[u8]) -> Option<String> {
    let comm_bytes = data.get(32..96)?;
    let comm_end = comm_bytes.iter().position(|&b| b == 0).unwrap_or(64);
    Some(
        std::str::from_utf8(&comm_bytes[..comm_end])
            .unwrap_or("?")
            .to_string(),
    )
}

#[cfg(any(test, feature = "ebpf"))]
fn summarize_event(data: &[u8]) -> Option<EbpfEventSummary> {
    match read_u32(data, 0)? {
        1 => Some(EbpfEventSummary::Exec {
            pid: read_u32(data, 4)?,
            comm: read_comm(data)?,
        }),
        2 => {
            let addr_bytes = data.get(96..100)?;
            Some(EbpfEventSummary::Connect {
                pid: read_u32(data, 4)?,
                comm: read_comm(data)?,
                ip: format!(
                    "{}.{}.{}.{}",
                    addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]
                ),
                port: read_u16(data, 100)?,
            })
        }
        _ => None,
    }
}

#[cfg(not(feature = "ebpf"))]
fn missing_ebpf_feature_message() -> &'static str {
    "This binary requires the 'ebpf' feature. Compile with:\n  cargo build --release --features ebpf -p innerwarden-sensor --bin test-ebpf"
}

#[cfg(feature = "ebpf")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aya::maps::RingBuf;
    use aya::programs::KProbe;
    use aya::Ebpf;

    println!("Inner Warden eBPF test loader\n");

    // Load eBPF bytecode from file (in production, embedded via include_bytes!)
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        "crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf".to_string()
    });

    let bytes = std::fs::read(&path)?;
    println!("Loaded {} bytes from {path}", bytes.len());

    let mut bpf = Ebpf::load(&bytes)?;
    println!("eBPF object loaded into kernel ✅");

    // List available programs
    for (name, _) in bpf.programs() {
        println!("  Program: {name}");
    }
    println!();

    // Attach the execve kprobe. Spec 069 Phase 2 replaced the
    // `sys_enter_execve` tracepoint with a kprobe on the x86_64 syscall
    // entry wrapper; on aarch64 the symbol is `__arm64_sys_execve`.
    let execve: &mut KProbe = bpf.program_mut("dispatch_execve").unwrap().try_into()?;
    execve.load()?;
    execve.attach("__x64_sys_execve", 0)?;
    println!("✅ dispatch_execve → __x64_sys_execve");

    // Attach the connect kprobe.
    let connect: &mut KProbe = bpf.program_mut("dispatch_connect").unwrap().try_into()?;
    connect.load()?;
    connect.attach("__x64_sys_connect", 0)?;
    println!("✅ dispatch_connect → __x64_sys_connect");

    // Read ring buffer
    println!("\nListening for events (5 seconds)...\n");
    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    let start = std::time::Instant::now();
    let mut exec_count = 0u64;
    let mut connect_count = 0u64;

    while start.elapsed() < std::time::Duration::from_secs(5) {
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() >= 4 {
                match summarize_event(data) {
                    Some(EbpfEventSummary::Exec { pid, comm }) => {
                        exec_count += 1;
                        if exec_count <= 5 {
                            println!("  EXEC  pid={pid:<6} comm={comm}");
                        }
                    }
                    Some(EbpfEventSummary::Connect {
                        pid,
                        comm,
                        ip,
                        port,
                    }) => {
                        connect_count += 1;
                        if connect_count <= 5 {
                            println!("  CONN  pid={pid:<6} {comm} → {ip}:{port}");
                        }
                    }
                    None => {}
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!("\n═══════════════════════════════════════════════");
    println!("  Execve events:  {exec_count}");
    println!("  Connect events: {connect_count}");
    println!("  Total:          {}", exec_count + connect_count);
    println!("═══════════════════════════════════════════════");
    println!("\n🎉 eBPF sensor is working!");

    Ok(())
}

#[cfg(not(feature = "ebpf"))]
fn main() {
    eprintln!("{}", missing_ebpf_feature_message());
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u32, pid: u32, comm: &[u8], ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut data = vec![0; 102];
        data[0..4].copy_from_slice(&kind.to_ne_bytes());
        data[4..8].copy_from_slice(&pid.to_ne_bytes());
        let comm_len = comm.len().min(64);
        data[32..32 + comm_len].copy_from_slice(&comm[..comm_len]);
        data[96..100].copy_from_slice(&ip);
        data[100..102].copy_from_slice(&port.to_ne_bytes());
        data
    }

    #[test]
    fn summarize_exec_event_extracts_pid_and_nul_terminated_comm() {
        let data = event(1, 4242, b"bash\0ignored", [0, 0, 0, 0], 0);
        assert_eq!(
            summarize_event(&data),
            Some(EbpfEventSummary::Exec {
                pid: 4242,
                comm: "bash".to_string()
            })
        );
    }

    #[test]
    fn summarize_connect_event_extracts_endpoint_and_full_comm() {
        let data = event(2, 99, b"curl", [203, 0, 113, 8], 443);
        assert_eq!(
            summarize_event(&data),
            Some(EbpfEventSummary::Connect {
                pid: 99,
                comm: "curl".to_string(),
                ip: "203.0.113.8".to_string(),
                port: 443
            })
        );
    }

    #[test]
    fn summarize_event_ignores_unknown_kind_and_truncated_records() {
        assert_eq!(
            summarize_event(&event(9, 1, b"noop", [0, 0, 0, 0], 0)),
            None
        );
        assert_eq!(summarize_event(&[1, 0, 0]), None);
        assert_eq!(
            summarize_event(&event(2, 1, b"curl", [127, 0, 0, 1], 80)[..100]),
            None
        );
    }

    #[test]
    fn read_comm_replaces_invalid_utf8_with_placeholder() {
        let data = event(1, 1, &[0xff, 0xfe, 0], [0, 0, 0, 0], 0);
        assert_eq!(read_comm(&data), Some("?".to_string()));
    }

    #[test]
    fn missing_feature_message_includes_exact_build_command() {
        let message = missing_ebpf_feature_message();
        assert!(message.contains("requires the 'ebpf' feature"));
        assert!(message.contains(
            "cargo build --release --features ebpf -p innerwarden-sensor --bin test-ebpf"
        ));
    }
}
