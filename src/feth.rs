use std::fmt;
use std::process::Command;
use std::sync::Arc;

/// Errors that can occur during feth interface operations.
#[derive(Debug)]
pub enum Error {
    /// The ifconfig command failed with a non-zero exit code.
    IfconfigFailed { stderr: String },
    /// Failed to spawn the ifconfig process.
    Spawn(std::io::Error),
    /// Failed to parse ifconfig output.
    Parse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IfconfigFailed { stderr } => write!(f, "ifconfig failed: {stderr}"),
            Error::Spawn(e) => write!(f, "failed to spawn ifconfig: {e}"),
            Error::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spawn(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Spawn(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Trait abstracting ifconfig command execution, allowing mock implementations for testing.
pub trait Executor: fmt::Debug {
    fn run_ifconfig(&self, args: &[&str]) -> Result<String>;
}

/// Default executor that spawns a real `ifconfig` process.
#[derive(Debug, Clone)]
pub struct SystemExecutor;

impl Executor for SystemExecutor {
    fn run_ifconfig(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("ifconfig").args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(Error::IfconfigFailed { stderr });
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Status information for a feth interface.
#[derive(Debug, Clone)]
pub struct FethStatus {
    pub name: String,
    pub flags: String,
    pub mtu: Option<u32>,
    pub ether: Option<String>,
    pub peer: Option<String>,
    pub inet: Option<String>,
    pub netmask: Option<String>,
}

/// A handle representing a feth (fake ethernet) interface.
///
/// Created via [`Feth::create`] or [`Feth::from_existing`].
#[derive(Debug, Clone)]
pub struct Feth {
    name: String,
    executor: Arc<dyn Executor>,
}

impl Feth {
    /// Create a new feth interface with the given unit number.
    ///
    /// Runs `ifconfig feth<unit> create`.
    pub fn create(unit: u32) -> Result<Self> {
        Self::create_with(unit, Arc::new(SystemExecutor))
    }

    /// Create a new feth interface with an auto-assigned unit number.
    ///
    /// Runs `ifconfig feth create` and parses the returned interface name.
    pub fn create_auto() -> Result<Self> {
        Self::create_auto_with(Arc::new(SystemExecutor))
    }

    /// Create a new feth interface with a peer set at creation time.
    ///
    /// Runs `ifconfig feth<unit> create peer <peer_name>`.
    pub fn create_with_peer(unit: u32, peer_name: &str) -> Result<Self> {
        Self::create_with_peer_using(unit, peer_name, Arc::new(SystemExecutor))
    }

    /// Wrap an existing feth interface by name.
    pub fn from_existing(name: impl Into<String>) -> Self {
        Self::from_existing_with(name, Arc::new(SystemExecutor))
    }

    fn create_with(unit: u32, executor: Arc<dyn Executor>) -> Result<Self> {
        let name = format!("feth{unit}");
        executor.run_ifconfig(&[&name, "create"])?;
        Ok(Self { name, executor })
    }

    fn create_auto_with(executor: Arc<dyn Executor>) -> Result<Self> {
        let output = executor.run_ifconfig(&["feth", "create"])?;
        let name = output.trim().to_string();
        if name.is_empty() {
            return Err(Error::Parse("empty interface name from create".into()));
        }
        Ok(Self { name, executor })
    }

    fn create_with_peer_using(
        unit: u32,
        peer_name: &str,
        executor: Arc<dyn Executor>,
    ) -> Result<Self> {
        let name = format!("feth{unit}");
        executor.run_ifconfig(&[&name, "create", "peer", peer_name])?;
        Ok(Self { name, executor })
    }

    fn from_existing_with(name: impl Into<String>, executor: Arc<dyn Executor>) -> Self {
        Self {
            name: name.into(),
            executor,
        }
    }

    /// Return the interface name (e.g. `"feth0"`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Destroy this feth interface.
    ///
    /// Runs `ifconfig <name> destroy`.
    pub fn destroy(&self) -> Result<()> {
        self.executor.run_ifconfig(&[&self.name, "destroy"])?;
        Ok(())
    }

    /// Set the peer for this interface.
    ///
    /// Runs `ifconfig <name> peer <peer_name>`.
    pub fn set_peer(&self, peer_name: &str) -> Result<()> {
        self.executor
            .run_ifconfig(&[&self.name, "peer", peer_name])?;
        Ok(())
    }

    /// Remove the peer association.
    ///
    /// Runs `ifconfig <name> -peer`.
    pub fn remove_peer(&self) -> Result<()> {
        self.executor.run_ifconfig(&[&self.name, "-peer"])?;
        Ok(())
    }

    /// Set an IPv4 address with a prefix length on this interface.
    ///
    /// Runs `ifconfig <name> inet <addr>/<prefix>`.
    pub fn set_inet(&self, addr: &str, prefix_len: u8) -> Result<()> {
        let cidr = format!("{addr}/{prefix_len}");
        self.executor
            .run_ifconfig(&[&self.name, "inet", &cidr])?;
        Ok(())
    }

    /// Set the MTU for this interface.
    ///
    /// Runs `ifconfig <name> mtu <mtu>`.
    pub fn set_mtu(&self, mtu: u32) -> Result<()> {
        let mtu_str = mtu.to_string();
        self.executor
            .run_ifconfig(&[&self.name, "mtu", &mtu_str])?;
        Ok(())
    }

    /// Bring the interface up.
    ///
    /// Runs `ifconfig <name> up`.
    pub fn up(&self) -> Result<()> {
        self.executor.run_ifconfig(&[&self.name, "up"])?;
        Ok(())
    }

    /// Bring the interface down.
    ///
    /// Runs `ifconfig <name> down`.
    pub fn down(&self) -> Result<()> {
        self.executor.run_ifconfig(&[&self.name, "down"])?;
        Ok(())
    }

    /// Configure the interface in one shot: set peer, address, and bring it up.
    ///
    /// Runs `ifconfig <name> peer <peer> inet <addr>/<prefix> up`.
    pub fn configure(&self, peer_name: &str, addr: &str, prefix_len: u8) -> Result<()> {
        let cidr = format!("{addr}/{prefix_len}");
        self.executor
            .run_ifconfig(&[&self.name, "peer", peer_name, "inet", &cidr, "up"])?;
        Ok(())
    }

    /// Get the current status of this interface by parsing `ifconfig <name>` output.
    pub fn status(&self) -> Result<FethStatus> {
        let output = self.executor.run_ifconfig(&[&self.name])?;
        parse_status(&self.name, &output)
    }
}

/// Create a linked pair of feth interfaces with assigned addresses.
///
/// This is a convenience function that creates two feth interfaces, peers them,
/// assigns addresses, and brings both up.
pub fn create_pair(
    unit_a: u32,
    addr_a: &str,
    unit_b: u32,
    addr_b: &str,
    prefix_len: u8,
) -> Result<(Feth, Feth)> {
    create_pair_with(
        unit_a,
        addr_a,
        unit_b,
        addr_b,
        prefix_len,
        Arc::new(SystemExecutor),
    )
}

fn create_pair_with(
    unit_a: u32,
    addr_a: &str,
    unit_b: u32,
    addr_b: &str,
    prefix_len: u8,
    executor: Arc<dyn Executor>,
) -> Result<(Feth, Feth)> {
    let name_a = format!("feth{unit_a}");
    let name_b = format!("feth{unit_b}");
    let cidr_a = format!("{addr_a}/{prefix_len}");
    let cidr_b = format!("{addr_b}/{prefix_len}");

    executor.run_ifconfig(&[&name_a, "create", "peer", &name_b, "inet", &cidr_a, "up"])?;
    executor.run_ifconfig(&[&name_b, "create", "peer", &name_a, "inet", &cidr_b, "up"])?;

    Ok((
        Feth {
            name: name_a,
            executor: executor.clone(),
        },
        Feth {
            name: name_b,
            executor,
        },
    ))
}

fn parse_status(name: &str, output: &str) -> Result<FethStatus> {
    let mut status = FethStatus {
        name: name.to_string(),
        flags: String::new(),
        mtu: None,
        ether: None,
        peer: None,
        inet: None,
        netmask: None,
    };

    for line in output.lines() {
        let trimmed = line.trim();

        // First line: "feth0: flags=8843<UP,...> mtu 1500"
        if trimmed.starts_with(&format!("{name}:")) {
            if let Some(flags_start) = trimmed.find("flags=") {
                if let Some(flags_end) = trimmed[flags_start..].find('>') {
                    status.flags =
                        trimmed[flags_start + 6..flags_start + flags_end + 1].to_string();
                }
            }
            if let Some(mtu_idx) = trimmed.find("mtu ") {
                if let Some(mtu_val) = trimmed[mtu_idx + 4..].split_whitespace().next() {
                    status.mtu = mtu_val.parse().ok();
                }
            }
        } else if trimmed.starts_with("ether ") {
            status.ether = trimmed.strip_prefix("ether ").map(|s| s.trim().to_string());
        } else if trimmed.starts_with("peer: ") {
            let peer_val = trimmed.strip_prefix("peer: ").unwrap().trim();
            if peer_val != "<none>" {
                status.peer = Some(peer_val.to_string());
            }
        } else if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                status.inet = Some(parts[1].to_string());
            }
            if let Some(pos) = parts.iter().position(|&p| p == "netmask") {
                if pos + 1 < parts.len() {
                    status.netmask = Some(parts[pos + 1].to_string());
                }
            }
        }
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recorded invocation of ifconfig.
    #[derive(Debug, Clone, PartialEq)]
    struct Call {
        args: Vec<String>,
    }

    /// Mock executor that records calls and returns pre-configured responses.
    #[derive(Debug)]
    struct MockExecutor {
        calls: Mutex<Vec<Call>>,
        responses: Mutex<Vec<Result<String>>>,
    }

    impl MockExecutor {
        fn new(responses: Vec<std::result::Result<String, &str>>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(
                    responses
                        .into_iter()
                        .rev() // reverse so we can pop from the end
                        .map(|r| match r {
                            Ok(s) => Ok(s),
                            Err(e) => Err(Error::IfconfigFailed {
                                stderr: e.to_string(),
                            }),
                        })
                        .collect(),
                ),
            })
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Executor for MockExecutor {
        fn run_ifconfig(&self, args: &[&str]) -> Result<String> {
            self.calls.lock().unwrap().push(Call {
                args: args.iter().map(|s| s.to_string()).collect(),
            });
            self.responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(Ok(String::new()))
        }
    }

    fn args(a: &[&str]) -> Call {
        Call {
            args: a.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ── Creation tests ──

    #[test]
    fn test_create_with_unit() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::create_with(0, mock.clone()).unwrap();

        assert_eq!(feth.name(), "feth0");
        assert_eq!(mock.calls(), vec![args(&["feth0", "create"])]);
    }

    #[test]
    fn test_create_auto() {
        let mock = MockExecutor::new(vec![Ok("feth3\n".into())]);
        let feth = Feth::create_auto_with(mock.clone()).unwrap();

        assert_eq!(feth.name(), "feth3");
        assert_eq!(mock.calls(), vec![args(&["feth", "create"])]);
    }

    #[test]
    fn test_create_auto_empty_output() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let err = Feth::create_auto_with(mock).unwrap_err();

        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn test_create_with_peer() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::create_with_peer_using(0, "feth1", mock.clone()).unwrap();

        assert_eq!(feth.name(), "feth0");
        assert_eq!(
            mock.calls(),
            vec![args(&["feth0", "create", "peer", "feth1"])]
        );
    }

    #[test]
    fn test_create_ifconfig_failure() {
        let mock = MockExecutor::new(vec![Err("interface already exists")]);
        let err = Feth::create_with(0, mock).unwrap_err();

        match err {
            Error::IfconfigFailed { stderr } => {
                assert!(stderr.contains("interface already exists"));
            }
            other => panic!("expected IfconfigFailed, got: {other:?}"),
        }
    }

    // ── Destroy tests ──

    #[test]
    fn test_destroy() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.destroy().unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "destroy"])]);
    }

    #[test]
    fn test_destroy_failure() {
        let mock = MockExecutor::new(vec![Err("interface does not exist")]);
        let feth = Feth::from_existing_with("feth99", mock.clone());

        let err = feth.destroy().unwrap_err();
        assert!(matches!(err, Error::IfconfigFailed { .. }));
    }

    // ── Peer tests ──

    #[test]
    fn test_set_peer() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.set_peer("feth1").unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "peer", "feth1"])]);
    }

    #[test]
    fn test_remove_peer() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.remove_peer().unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "-peer"])]);
    }

    // ── Param setting tests ──

    #[test]
    fn test_set_inet() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.set_inet("10.0.0.1", 24).unwrap();
        assert_eq!(
            mock.calls(),
            vec![args(&["feth0", "inet", "10.0.0.1/24"])]
        );
    }

    #[test]
    fn test_set_mtu() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.set_mtu(9000).unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "mtu", "9000"])]);
    }

    #[test]
    fn test_up() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.up().unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "up"])]);
    }

    #[test]
    fn test_down() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.down().unwrap();
        assert_eq!(mock.calls(), vec![args(&["feth0", "down"])]);
    }

    #[test]
    fn test_configure() {
        let mock = MockExecutor::new(vec![Ok(String::new())]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        feth.configure("feth1", "10.0.0.1", 24).unwrap();
        assert_eq!(
            mock.calls(),
            vec![args(&["feth0", "peer", "feth1", "inet", "10.0.0.1/24", "up"])]
        );
    }

    // ── Status tests ──

    #[test]
    fn test_status() {
        let output = "\
feth0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 02:00:00:00:00:00
\tpeer: feth1
\tinet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255
"
        .to_string();
        let mock = MockExecutor::new(vec![Ok(output)]);
        let feth = Feth::from_existing_with("feth0", mock.clone());

        let st = feth.status().unwrap();
        assert_eq!(st.name, "feth0");
        assert_eq!(st.flags, "8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>");
        assert_eq!(st.mtu, Some(1500));
        assert_eq!(st.ether.as_deref(), Some("02:00:00:00:00:00"));
        assert_eq!(st.peer.as_deref(), Some("feth1"));
        assert_eq!(st.inet.as_deref(), Some("10.0.0.1"));
        assert_eq!(st.netmask.as_deref(), Some("0xffffff00"));
        assert_eq!(mock.calls(), vec![args(&["feth0"])]);
    }

    // ── create_pair tests ──

    #[test]
    fn test_create_pair() {
        let mock = MockExecutor::new(vec![Ok(String::new()), Ok(String::new())]);
        let (a, b) =
            create_pair_with(0, "10.0.0.1", 1, "10.0.0.2", 24, mock.clone()).unwrap();

        assert_eq!(a.name(), "feth0");
        assert_eq!(b.name(), "feth1");
        assert_eq!(
            mock.calls(),
            vec![
                args(&["feth0", "create", "peer", "feth1", "inet", "10.0.0.1/24", "up"]),
                args(&["feth1", "create", "peer", "feth0", "inet", "10.0.0.2/24", "up"]),
            ]
        );
    }

    #[test]
    fn test_create_pair_second_fails() {
        let mock = MockExecutor::new(vec![Ok(String::new()), Err("feth1 already exists")]);
        let err = create_pair_with(0, "10.0.0.1", 1, "10.0.0.2", 24, mock).unwrap_err();

        assert!(matches!(err, Error::IfconfigFailed { .. }));
    }

    // ── Parse tests ──

    #[test]
    fn test_parse_status_full() {
        let output = "\
feth0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 02:00:00:00:00:00
\tpeer: feth1
\tinet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255
";
        let status = parse_status("feth0", output).unwrap();
        assert_eq!(status.name, "feth0");
        assert_eq!(status.flags, "8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>");
        assert_eq!(status.mtu, Some(1500));
        assert_eq!(status.ether.as_deref(), Some("02:00:00:00:00:00"));
        assert_eq!(status.peer.as_deref(), Some("feth1"));
        assert_eq!(status.inet.as_deref(), Some("10.0.0.1"));
        assert_eq!(status.netmask.as_deref(), Some("0xffffff00"));
    }

    #[test]
    fn test_parse_status_no_peer() {
        let output = "\
feth0: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
\tether 02:00:00:00:00:00
\tpeer: <none>
";
        let status = parse_status("feth0", output).unwrap();
        assert!(status.peer.is_none());
        assert!(status.inet.is_none());
    }

    #[test]
    fn test_parse_status_minimal() {
        let output = "feth5: flags=0<> mtu 9000\n";
        let status = parse_status("feth5", output).unwrap();
        assert_eq!(status.name, "feth5");
        assert_eq!(status.flags, "0<>");
        assert_eq!(status.mtu, Some(9000));
        assert!(status.ether.is_none());
        assert!(status.peer.is_none());
    }
}
