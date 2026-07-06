use super::env::HardenEnv;
use super::types::{CheckResult, Finding, Severity};

pub(super) fn classify_loaded_modules(
    lsmod_output: &str,
    rootkit_modules: &[&str],
    known_good: &[&str],
) -> (Vec<String>, Vec<String>) {
    let mut rootkits = Vec::new();
    let mut unknowns = Vec::new();

    for line in lsmod_output.lines().skip(1) {
        let Some(module) = line.split_whitespace().next() else {
            continue;
        };
        if rootkit_modules
            .iter()
            .any(|rootkit| module.eq_ignore_ascii_case(rootkit))
        {
            rootkits.push(module.to_string());
            continue;
        }
        if !known_good.contains(&module) {
            unknowns.push(module.to_string());
        }
    }

    (rootkits, unknowns)
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

pub(super) fn check_kernel_modules(env: &impl HardenEnv) -> CheckResult {
    let mut passed = Vec::new();
    let mut findings = Vec::new();
    let cat = "Kernel Modules";

    // Known rootkit modules - always flag as Critical.
    let rootkit_modules: &[&str] = &[
        "diamorphine",
        "reptile",
        "jynx",
        "adore",
        "knark",
        "suterusu",
    ];

    // Known-good modules (common, legitimate kernel modules).
    let known_good: &[&str] = &[
        // Filesystems
        "ext4",
        "xfs",
        "btrfs",
        "vfat",
        "fat",
        "nfs",
        "nfsd",
        "cifs",
        "fuse",
        "overlay",
        "isofs",
        "squashfs",
        "udf",
        "ntfs",
        "ntfs3",
        // Networking
        "ip_tables",
        "ip6_tables",
        "iptable_filter",
        "iptable_nat",
        "iptable_mangle",
        "nf_conntrack",
        "nf_nat",
        "nf_tables",
        "nft_chain_nat",
        "nft_compat",
        "nf_conntrack_ftp",
        "nf_nat_ftp",
        "nf_conntrack_netlink",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_reject_ipv4",
        "nf_reject_ipv6",
        "nft_reject",
        "br_netfilter",
        "bridge",
        "stp",
        "llc",
        "veth",
        "tun",
        "tap",
        "bonding",
        "8021q",
        "vxlan",
        "geneve",
        "wireguard",
        "openvswitch",
        "tcp_bbr",
        "tcp_cubic",
        // Block / storage
        "dm_mod",
        "dm_crypt",
        "dm_mirror",
        "dm_snapshot",
        "dm_thin_pool",
        "dm_zero",
        "dm_log",
        "dm_region_hash",
        "raid0",
        "raid1",
        "raid10",
        "raid456",
        "md_mod",
        "loop",
        "nbd",
        "scsi_mod",
        "sd_mod",
        "sr_mod",
        "sg",
        "ahci",
        "libahci",
        "libata",
        "virtio_blk",
        "virtio_scsi",
        "nvme",
        "nvme_core",
        // Virtio / KVM / hypervisor
        "virtio",
        "virtio_pci",
        "virtio_net",
        "virtio_ring",
        "virtio_balloon",
        "virtio_console",
        "virtio_gpu",
        "virtio_mmio",
        "virtio_rng",
        "kvm",
        "kvm_intel",
        "kvm_amd",
        "vhost",
        "vhost_net",
        "vhost_vsock",
        "vmw_balloon",
        "vmw_vmci",
        "vmw_vsock_vmci_transport",
        "vmxnet3",
        "hv_vmbus",
        "hv_storvsc",
        "hv_netvsc",
        "hv_utils",
        "hv_balloon",
        "xen_blkfront",
        "xen_netfront",
        "xen_pcifront",
        // Input / HID
        "hid",
        "hid_generic",
        "usbhid",
        "evdev",
        "input_leds",
        "psmouse",
        "i2c_hid",
        "i2c_core",
        // USB
        "usbcore",
        "usb_common",
        "ehci_hcd",
        "ehci_pci",
        "ohci_hcd",
        "ohci_pci",
        "uhci_hcd",
        "xhci_hcd",
        "xhci_pci",
        // Graphics / DRM
        "drm",
        "drm_kms_helper",
        "fb_sys_fops",
        "syscopyarea",
        "sysfillrect",
        "sysimgblt",
        "i915",
        "amdgpu",
        "nouveau",
        "bochs",
        "cirrus",
        "qxl",
        // Sound
        "snd",
        "snd_pcm",
        "snd_timer",
        "snd_hda_intel",
        "snd_hda_core",
        "snd_hda_codec",
        "snd_hda_codec_generic",
        "snd_hda_codec_hdmi",
        "snd_hda_codec_realtek",
        "snd_hwdep",
        "soundcore",
        // Crypto
        "aes_x86_64",
        "aesni_intel",
        "aes_generic",
        "sha256_generic",
        "sha256_ssse3",
        "sha512_generic",
        "sha512_ssse3",
        "sha1_generic",
        "sha1_ssse3",
        "crc32c_intel",
        "crc32_pclmul",
        "crct10dif_pclmul",
        "ghash_clmulni_intel",
        "poly1305_x86_64",
        "chacha20_x86_64",
        "cryptd",
        "crypto_simd",
        "authenc",
        "echainiv",
        // ACPI / power / platform
        "acpi_cpufreq",
        "battery",
        "button",
        "thermal",
        "processor",
        "intel_rapl_msr",
        "intel_rapl_common",
        "intel_pstate",
        // Misc common
        "joydev",
        "serio_raw",
        "pcspkr",
        "lp",
        "ppdev",
        "parport",
        "parport_pc",
        "nls_utf8",
        "nls_iso8859_1",
        "nls_cp437",
        "configfs",
        "efivarfs",
        "autofs4",
        "sunrpc",
        "rpcsec_gss_krb5",
        "cuse",
        "vboxguest",
        "vboxsf",
        "vboxvideo",
        "ip_vs",
        "ip_vs_rr",
        "ip_vs_wrr",
        "ip_vs_sh",
        "xt_conntrack",
        "xt_MASQUERADE",
        "xt_addrtype",
        "xt_comment",
        "xt_mark",
        "xt_nat",
        "xt_tcpudp",
        "xt_multiport",
        "xt_state",
        "xt_LOG",
        "xt_limit",
        "xt_recent",
        "xt_set",
        "ip_set",
        "ip_set_hash_ip",
        "ip_set_hash_net",
        "cls_cgroup",
        "sch_fq_codel",
        "sch_htb",
        "rng_core",
        "tpm",
        "tpm_crb",
        "tpm_tis",
        "tpm_tis_core",
        "lz4",
        "lz4_compress",
        "lzo",
        "lzo_compress",
        "lzo_decompress",
        "zstd_compress",
        "zstd_decompress",
        "deflate",
        "zlib_deflate",
        "zlib_inflate",
        "af_packet",
        "unix",
        "ipv6",
        "mousedev",
        "mac_hid",
        "msr",
        "cpuid",
        "iscsi_tcp",
        "libiscsi",
        "libiscsi_tcp",
        "scsi_transport_iscsi",
        "ceph",
        "libceph",
        "rbd",
        // Docker / containerd common
        "xt_connmark",
        "xt_REDIRECT",
        "nf_log_syslog",
        "nf_log_ipv4",
        // Networking diagnostics / misc
        "tcp_diag",
        "inet_diag",
        "udp_diag",
        "tls",
        "xfrm_user",
        "xfrm_algo",
        "ip6t_REJECT",
        "ip6t_rt",
        "xt_hl",
        "nft_limit",
        "xt_owner",
        "nft_fib",
        "nft_fib_inet",
        "nft_fib_ipv4",
        "nft_fib_ipv6",
        "nft_ct",
        "nft_counter",
        "nft_log",
        "nft_masq",
        "nft_nat",
        "nft_reject",
        "nft_reject_inet",
        "nft_reject_ipv4",
        "nft_reject_ipv6",
        "ip6table_filter",
        "ip6table_nat",
        "ip6table_mangle",
        "ip6_tables",
        "iptable_raw",
        "ip_set_hash_ipport",
        "ip_set_hash_ipportnet",
        // Oracle Cloud / ARM common
        "veth",
        "dummy",
        "nfnetlink",
        "nfnetlink_queue",
        "nfnetlink_log",
        "nf_log_common",
        // ─────────────────────────────────────────────────────────────────
        // 2026-05-25 — Ubuntu 24.04+ / 26.04 LTS baseline additions.
        //
        // First-customer install on a fresh Ubuntu 26.04 cloud image
        // produced 27 FPs against this list. The entries below cover
        // exactly the names seen + close siblings that load together
        // via modprobe dependency resolution. The original list was
        // built against Ubuntu 22.04 / kernel 5.x defaults and missed
        // several modules that became baseline on 6.x kernels and on
        // Canonical's modern cloud images.
        // ─────────────────────────────────────────────────────────────────

        // Netfilter base (siblings of already-listed nft_* / iptable_*)
        "x_tables", // base for all xt_* / ipt_*
        "ipt_REJECT",
        "nf_log_arp",
        // Wireless / radio stack (loaded even on wired-only cloud images
        // when firmware is present — Hetzner / DO / Oracle all carry it)
        "cfg80211",
        "mac80211",
        "rfkill",
        // Bridge / 802.1ak attribute registration (load alongside `bridge`)
        "garp",
        "mrp",
        "bridge_stp",
        // Userland binary-format registration. Default on Ubuntu — used
        // by Wine, qemu-user, Docker buildx (multi-arch), Java loaders.
        "binfmt_misc",
        // Modern Intel CPU thermal / power / counter modules. Baseline
        // on every Xeon / Core machine from Skylake onwards.
        "intel_uncore_frequency",
        "intel_uncore_frequency_common",
        "intel_powerclamp",
        "intel_pmc_core",
        "coretemp",
        // 9p / VirtIO additions common in QEMU shared-folder + cloud
        "9p",
        "9pnet",
        "9pnet_virtio",
        "virtio_input",
        "virtio_iommu",
        // Crypto defaults on kernel 6.x+ (polyval is GCM-SIV's hash,
        // crc_t10dif is required by NVMe & some SATA paths).
        "polyval_clmulni",
        "polyval_generic",
        "crc_t10dif",
        "crct10dif_generic",
        // I2C / MEI (Intel Management Engine path — baseline on modern
        // Intel hardware, even on bare-metal cloud)
        "i2c_smbus",
        "i2c_dev",
        "mei",
        "mei_me",
        // Misc commonly loaded on Ubuntu cloud images
        "fscache",
        "watchdog",
        // 2026-06-14: cloud / virt platform drivers that a stock public-cloud
        // image loads at boot. Previously these raised a "12 unusual kernel
        // module(s)" low finding on a clean Azure (AMD EPYC) host — pure noise
        // that buries a real rogue module. Grouped by platform below.
        //
        // Microsoft Azure / Hyper-V (modern hv_* siblings + MANA NIC + DRM)
        "hid_hyperv",
        "hyperv_keyboard",
        "hyperv_drm",
        "hyperv_fb",
        "hv_sock",
        "mana",
        "mana_ib",
        // RDMA / InfiniBand core (Azure accelerated networking, HPC SKUs)
        "ib_core",
        "ib_uverbs",
        "ib_cm",
        "ib_umad",
        "ib_ipoib",
        "rdma_cm",
        "rdma_ucm",
        "iw_cm",
        "mlx5_core",
        "mlx5_ib",
        "mlx4_core",
        "mlx4_en",
        "mlxfw",
        // AMD platform (EPYC cloud hosts)
        "ccp",       // AMD Secure Processor / crypto co-processor
        "kvm_amd",   // (also above; harmless)
        "irqbypass", // KVM IRQ bypass, loaded by kvm on virt hosts
        // AWS / GCP NIC + storage drivers
        "ena",          // AWS Elastic Network Adapter
        "gve",          // Google Virtual NIC
        "nvme_fabrics", // NVMe-oF (cloud block storage)
        "nvme_tcp",
        "nvme_rdma",
        "failover",
        "net_failover", // accelerated-networking failover pair
        // Common physical NIC drivers (bare-metal / dedicated cloud)
        "e1000",
        "e1000e",
        "igb",
        "ixgbe",
        "i40e",
        "tg3",
        "bnxt_en",
        "r8169",
        // Multipath storage + SCSI device handlers
        "dm_multipath",
        "scsi_dh_alua",
        "scsi_dh_rdac",
        "scsi_dh_emc",
        // CRC / checksum helpers pulled in by the above
        "crc_itu_t",
        "crc_ccitt",
        // Persistent store (EFI crash logs) — ubiquitous on UEFI hosts
        "efi_pstore",
        "pstore",
        "pstore_blk",
        "ramoops",
    ];

    match env.command_stdout("lsmod", &[]) {
        Some(output) => {
            let (rootkits, unknown_modules) =
                classify_loaded_modules(&output, rootkit_modules, known_good);
            for module in &rootkits {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Critical,
                    title: format!("Known rootkit module loaded: {module}"),
                    fix: format!(
                        "Investigate immediately - remove with: sudo rmmod {module} && audit the system"
                    ),
                });
            }

            if !unknown_modules.is_empty() {
                findings.push(Finding {
                    category: cat,
                    severity: Severity::Low,
                    title: format!("{} unusual kernel module(s) loaded", unknown_modules.len()),
                    fix: format!(
                        "Review if expected: {}",
                        unknown_modules
                            .iter()
                            .take(10)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                });
            }

            if findings.is_empty() {
                passed.push("All loaded kernel modules are known-good".into());
            }
        }
        None => {
            passed.push("lsmod not available (skipped)".into());
        }
    }

    CheckResult {
        category: cat,
        passed,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harden::env::{DirEntry, HardenEnv};

    /// Simulates `lsmod` output: header line followed by one
    /// module-name line per module. Only the first column matters
    /// for `classify_loaded_modules`, so we keep the rest minimal.
    fn lsmod(modules: &[&str]) -> String {
        let mut s = String::from("Module                  Size  Used by\n");
        for m in modules {
            s.push_str(m);
            s.push_str("                16384  0\n");
        }
        s
    }

    /// Minimal mock so `check_kernel_modules` (the real function) can
    /// run end-to-end against canned lsmod output. We only need
    /// `command_stdout`; everything else returns the zero value.
    struct MockEnv {
        lsmod_output: String,
    }
    impl HardenEnv for MockEnv {
        fn read_to_string(&self, _: &str) -> Option<String> {
            None
        }
        fn read_bytes(&self, _: &str) -> Option<Vec<u8>> {
            None
        }
        fn read_dir(&self, _: &str) -> Vec<DirEntry> {
            Vec::new()
        }
        fn metadata_mode(&self, _: &str) -> Option<u32> {
            None
        }
        fn path_exists(&self, _: &str) -> bool {
            false
        }
        fn command_stdout(&self, _: &str, _: &[&str]) -> Option<String> {
            Some(self.lsmod_output.clone())
        }
    }

    /// 2026-05-25 anchor — Ubuntu 26.04 first-install FP fix.
    ///
    /// Pre-fix, the operator's first real client install on a fresh
    /// Ubuntu 26.04 LTS cloud image produced 27 "unusual kernel
    /// module(s) loaded" findings, all of which were standard
    /// Ubuntu modules. The list below is the exact sample the
    /// operator reported (10 visible names from the truncated
    /// output) plus the close siblings that load alongside via
    /// modprobe dependencies — together they cover the full set of
    /// names the original Ubuntu 22.04-era whitelist missed.
    ///
    /// This test pins that every one of those names is now in
    /// `known_good`, so the upgrade-to-26.04 FP cannot recur.
    #[test]
    fn ubuntu_26_04_baseline_modules_are_known_good() {
        let ubuntu_26_04_baseline = [
            // Operator-reported visible names
            "ipt_REJECT",
            "x_tables",
            "cfg80211",
            "garp",
            "mrp",
            "binfmt_misc",
            "intel_uncore_frequency_common",
            // Close siblings that load together
            "mac80211",
            "rfkill",
            "bridge_stp",
            "nf_log_arp",
            "intel_uncore_frequency",
            "intel_powerclamp",
            "intel_pmc_core",
            "coretemp",
            "9p",
            "9pnet",
            "9pnet_virtio",
            "virtio_input",
            "virtio_iommu",
            "polyval_clmulni",
            "polyval_generic",
            "crc_t10dif",
            "crct10dif_generic",
            "i2c_smbus",
            "i2c_dev",
            "mei",
            "mei_me",
            "fscache",
            "watchdog",
        ];

        let env = MockEnv {
            lsmod_output: lsmod(&ubuntu_26_04_baseline),
        };
        let result = check_kernel_modules(&env);
        assert!(
            result.findings.is_empty(),
            "every Ubuntu 26.04 baseline module must be in known_good; got {} findings: {:?}",
            result.findings.len(),
            result
                .findings
                .iter()
                .map(|f| f.title.clone())
                .collect::<Vec<_>>(),
        );
        assert!(result.passed.iter().any(|p| p.contains("known-good")));
    }

    /// Anti-regression: the rootkit detection MUST still fire even
    /// when the kernel-modules whitelist grows. Adding too much
    /// to `known_good` could in principle absorb a genuinely
    /// malicious name — pin that `diamorphine` (the canonical
    /// Linux rootkit teaching example) still produces a Critical
    /// finding regardless of how many benign names we whitelist.
    #[test]
    fn diamorphine_rootkit_still_fires_critical_after_whitelist_expansion() {
        let env = MockEnv {
            lsmod_output: lsmod(&["diamorphine", "ext4", "binfmt_misc"]),
        };
        let result = check_kernel_modules(&env);
        let critical_count = result
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        assert_eq!(
            critical_count, 1,
            "diamorphine must still fire Critical: {:?}",
            result.findings
        );
        assert!(result.findings.iter().any(|f| f.title.contains("rootkit")));
    }

    /// 2026-06-14 anchor — Azure (AMD EPYC) cloud-image FP fix.
    ///
    /// The exact 10 module names a clean Azure Spot host reported as
    /// "12 unusual kernel module(s) loaded" (plus the platform
    /// siblings that load with them). All are stock cloud/virt/NIC
    /// drivers; none should land in the unusual bucket anymore.
    #[test]
    fn azure_cloud_baseline_modules_are_known_good() {
        let azure_baseline = [
            "crc_itu_t",
            "mana_ib",
            "ib_uverbs",
            "ib_core",
            "ccp",
            "irqbypass",
            "hid_hyperv",
            "hyperv_keyboard",
            "hyperv_drm",
            "dm_multipath",
            // siblings
            "mana",
            "rdma_cm",
            "mlx5_core",
            "ena",
            "gve",
            "efi_pstore",
        ];
        let env = MockEnv {
            lsmod_output: lsmod(&azure_baseline),
        };
        let result = check_kernel_modules(&env);
        assert!(
            result.findings.is_empty(),
            "Azure cloud baseline must not flag any module: {:?}",
            result.findings
        );
    }

    /// Anti-regression on `classify_loaded_modules` itself: unknown
    /// modules go into the `unknowns` bucket, known-good ones do
    /// not. The expanded whitelist must keep that contract.
    #[test]
    fn classify_separates_known_good_from_unknown() {
        let lsmod_text = lsmod(&["ext4", "ipt_REJECT", "some_brand_new_module"]);
        let (rootkits, unknowns) =
            classify_loaded_modules(&lsmod_text, &["diamorphine"], &["ext4", "ipt_REJECT"]);
        assert!(rootkits.is_empty());
        assert_eq!(unknowns, vec!["some_brand_new_module".to_string()]);
    }
}
