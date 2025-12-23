use core::str;
use std::{
    ffi::{CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use anyhow::bail;
use serde::{ser::SerializeSeq, Serialize, Serializer};
use uuid::Uuid;

use crate::host_info::get_username;

use super::Event;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lineage {
    uid: u32,
    exe_path: PathBuf,
}

impl Lineage {
    /// Parse a `Lineage` object from a ringbuffer event.
    ///
    /// # Safety
    ///
    /// * The order of fields parsed must match the order used by the
    ///   BPF programs.
    fn parse(value: &[u8]) -> anyhow::Result<(Self, &[u8])> {
        let Some((uid, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse lineage uid");
        };
        let Some((exe_path, value)) = Event::parse_buffer(value) else {
            bail!("Failed to parse lineage exe_path");
        };
        let exe_path = OsStr::from_bytes(exe_path).into();

        let lineage = Lineage { uid, exe_path };

        Ok((lineage, value))
    }
}

impl From<Lineage> for fact_api::process_signal::LineageInfo {
    fn from(value: Lineage) -> Self {
        let Lineage { uid, exe_path } = value;
        Self {
            parent_uid: uid,
            parent_exec_file_path: exe_path.to_string_lossy().to_string(),
        }
    }
}

#[cfg(test)]
impl PartialEq for Lineage {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid && self.exe_path == other.exe_path
    }
}

fn serialize_lossy_string<S>(value: &CString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    value.to_string_lossy().serialize(serializer)
}

fn serialize_vector_lossy_string<S>(value: &Vec<CString>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(value.len()))?;
    for i in value {
        seq.serialize_element(&i.to_string_lossy().to_string())?;
    }
    seq.end()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Process {
    #[serde(serialize_with = "serialize_lossy_string")]
    comm: CString,
    #[serde(serialize_with = "serialize_vector_lossy_string")]
    args: Vec<CString>,
    exe_path: PathBuf,
    container_id: Option<String>,
    uid: u32,
    username: &'static str,
    gid: u32,
    login_uid: u32,
    pid: u32,
    in_root_mount_ns: bool,
    lineage: Vec<Lineage>,
}

impl Process {
    /// Create a representation of the current process as best as
    /// possible.
    #[cfg(test)]
    pub fn current() -> Self {
        use crate::host_info::{get_host_mount_ns, get_mount_ns};

        let exe_path = std::env::current_exe().expect("Failed to get current exe");
        let args = std::env::args()
            .map(|a| CString::new(a.into_bytes()).unwrap())
            .collect::<Vec<_>>();
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("Failed to read cgroup");
        let container_id = Process::extract_container_id(&cgroup);
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let pid = std::process::id();
        let login_uid = std::fs::read_to_string("/proc/self/loginuid")
            .expect("Failed to read loginuid")
            .parse()
            .expect("Failed to parse login_uid");

        let in_root_mount_ns = get_host_mount_ns() == get_mount_ns(&pid.to_string(), false);

        Self {
            comm: c"".into(),
            args,
            exe_path,
            container_id,
            uid,
            username: "",
            gid,
            login_uid,
            pid,
            in_root_mount_ns,
            lineage: vec![],
        }
    }

    fn extract_container_id(cgroup: &str) -> Option<String> {
        let cgroup = if let Some(i) = cgroup.rfind(".scope") {
            cgroup.split_at(i).0
        } else {
            cgroup
        };

        if cgroup.is_empty() || cgroup.len() < 65 {
            return None;
        }

        let cgroup = cgroup.split_at(cgroup.len() - 65).1;
        let (c, cgroup) = cgroup.split_at(1);
        if c != "/" && c != "-" {
            return None;
        }

        if cgroup.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(cgroup.split_at(12).0.to_owned())
        } else {
            None
        }
    }

    /// Parse the process comm value.
    ///
    /// For simplicity, the kernel side BPF program loads the result of
    /// calling the bpf_get_current_comm helper directly onto the event.
    /// The resulting value loaded in is 16 bytes with a guaranteed
    /// null terminator and null padding if needed.
    ///
    /// We could save a few bytes if we were to retrieve the string
    /// length in kernel side and load a generic buffer onto the event
    /// like `Event::parse_buffer` expects, but we would need to do a
    /// bit more work kernel side that is not worth it.
    fn parse_comm(s: &[u8]) -> Option<(CString, &[u8])> {
        let (val, s) = s.split_at_checked(16)?;
        let res = CStr::from_bytes_until_nul(val).ok()?;
        Some((res.to_owned(), s))
    }

    /// Parse the arguments of a process.
    ///
    /// The kernel stores arguments as a sequence of null terminated
    /// strings in a single buffer, we copy that blob directly onto the
    /// ringbuffer and prepend the actual length we copied in the same
    /// way `Event::parse_buffer` expects. This way we can read the
    /// buffer and then iterate over the null strings, mapping them to
    /// `CString`s in a vector.
    ///
    /// # Safety
    ///
    /// * The BPF program loading the arguments must ensure the last
    ///   portion ends with a null terminator, even if we truncate it
    ///   for performance reasons.
    fn parse_args(s: &[u8]) -> anyhow::Result<(Vec<CString>, &[u8])> {
        let Some((buf, s)) = Event::parse_buffer(s) else {
            bail!("Failed to get arguments length");
        };

        let args = buf
            .split_inclusive(|a| *a == 0)
            .map(|arg| CString::from_vec_with_nul(arg.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((args, s))
    }

    /// Parse a `Process` from a ringbuffer event.
    ///
    /// # Safety
    ///
    /// * The order of fields must match the order used by the BPF
    ///   programs.
    pub(super) fn parse(value: &[u8]) -> anyhow::Result<(Self, &[u8])> {
        let Some((uid, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse uid");
        };
        let username = get_username(uid);
        let Some((gid, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse gid");
        };
        let Some((login_uid, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse login_uid");
        };
        let Some((pid, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse pid");
        };
        let Some((comm, value)) = Process::parse_comm(value) else {
            bail!("Failed to parse comm");
        };
        let (args, value) = Process::parse_args(value)?;
        let Some((exe_path, value)) = Event::parse_buffer(value) else {
            bail!("Failed to parse exe_path");
        };
        let exe_path = OsStr::from_bytes(exe_path).into();
        let Some((cgroup, value)) = Event::parse_buffer(value) else {
            bail!("Failed to parse cgroup");
        };
        let cgroup = str::from_utf8(cgroup)?;
        let container_id = Process::extract_container_id(cgroup);
        let Some((in_root_mount_ns, value)) = Event::parse_int::<u8>(value) else {
            bail!("Failed to parse in_root_mount_ns");
        };
        let in_root_mount_ns = in_root_mount_ns != 0;
        let Some((lineage_len, mut value)) = Event::parse_int::<u16>(value) else {
            bail!("Failed to parse lineage length");
        };
        let mut lineage = Vec::with_capacity(lineage_len as usize);
        for _ in 0..lineage_len {
            let (l, v) = Lineage::parse(value)?;
            value = v;
            lineage.push(l);
        }

        let process = Process {
            comm,
            uid,
            username,
            gid,
            login_uid,
            pid,
            args,
            exe_path,
            container_id,
            in_root_mount_ns,
            lineage,
        };

        Ok((process, value))
    }
}

#[cfg(test)]
impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid
            && self.login_uid == other.login_uid
            && self.gid == other.gid
            && self.exe_path == other.exe_path
            && self.args == other.args
            && self.container_id == other.container_id
            && self.in_root_mount_ns == other.in_root_mount_ns
    }
}

impl From<Process> for fact_api::ProcessSignal {
    fn from(value: Process) -> Self {
        let Process {
            comm,
            args,
            exe_path,
            container_id,
            uid,
            username,
            gid,
            login_uid,
            pid,
            in_root_mount_ns,
            lineage,
        } = value;

        let container_id = container_id.unwrap_or("".to_string());

        let args = args
            .into_iter()
            .map(|a| a.to_string_lossy().to_string())
            .reduce(|acc, i| acc + " " + &i)
            .unwrap_or("".to_owned());

        Self {
            id: Uuid::new_v4().to_string(),
            container_id,
            creation_time: None,
            name: comm.to_string_lossy().to_string(),
            args,
            exec_file_path: exe_path.to_string_lossy().into_owned(),
            pid,
            uid,
            gid,
            scraped: false,
            lineage_info: lineage
                .into_iter()
                .map(fact_api::process_signal::LineageInfo::from)
                .collect(),
            login_uid,
            username: username.to_owned(),
            in_root_mount_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_container_id() {
        let tests = [
            ("", None),
            ("init.scope", None),
            (
                "/docker/951e643e3c241b225b6284ef2b79a37c13fc64cbf65b5d46bda95fcb98fe63a4",
                Some("951e643e3c24".to_string()),
            ),
            (
                "/kubepods/kubepods/besteffort/pod690705f9-df6e-11e9-8dc5-025000000001/c3bfd81b7da0be97190a74a7d459f4dfa18f57c88765cde2613af112020a1c4b",
                Some("c3bfd81b7da0".to_string()),
            ),
            (
                "/kubepods/burstable/pod7cd3dba6-e475-11e9-8f99-42010a8a00d2/2bc55a8cae1704a733ba5d785d146bbed9610483380507cbf00c96b32bb637e1",
                Some("2bc55a8cae17".to_string()),
            ),
            (
              "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podce705797_e47e_11e9_bd71_42010a000002.slice/docker-6525e65814a99d431b6978e8f8c895013176c6c58173b56639d4b020c14e6022.scope",
              Some("6525e65814a9".to_string()),
            ),
            (
                "/machine.slice/libpod-b6e375cfe46efa5cd90d095603dec2de888c28b203285819233040b5cf1212ac.scope/container",
                Some("b6e375cfe46e".to_string()),
            ),
            (
              "/machine.slice/libpod-cbdfa0f1f08763b1963c30d98e11e1f052cb67f1e9b7c0ab8a6ca6c70cbcad69.scope/container/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod6eab3b7b_f0a6_4bb8_bff2_d5bc9017c04b.slice/cri-containerd-5ebf11e02dbde102cda4b76bc0e3849a65f9edac7a12bdabfd34db01b9556101.scope",
              Some("5ebf11e02dbd".to_string()),
            ),
        ];

        for (input, expected) in tests {
            let id = Process::extract_container_id(input);
            assert_eq!(id, expected);
        }
    }

    #[test]
    fn test_parse_comm() {
        struct TestCase<'a> {
            input: &'a [u8],
            expected: Option<(CString, &'a [u8])>,
        }
        let tests = [
            TestCase {
                input: b"touch\0\0\0\0\0\0\0\0\0\0\0",
                expected: Some((CString::from(c"touch"), b"")),
            },
            TestCase {
                input: b"touch\0\0\0\0\0\0\0\0\0\0\0ignored",
                expected: Some((CString::from(c"touch"), b"ignored")),
            },
            TestCase {
                input: b"",
                expected: None,
            },
        ];

        for TestCase { input, expected } in tests {
            let res = Process::parse_comm(input);
            assert_eq!(res, expected, "input: {}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn test_parse_args() {
        struct TestCase<'a> {
            input: &'a [u8],
            expected: anyhow::Result<(Vec<CString>, &'a [u8])>,
        }
        let tests = [
            TestCase {
                input: b"\x00\x03id\0",
                expected: Ok((vec![CString::from(c"id")], b"")),
            },
            TestCase {
                input: b"\x00\x12rm\0-rf\0/some/path\0",
                expected: Ok((
                    vec![
                        CString::from(c"rm"),
                        CString::from(c"-rf"),
                        CString::from(c"/some/path"),
                    ],
                    b"",
                )),
            },
            TestCase {
                input: b"\x00\x12rm\0-rf\0/some/path\0ignored",
                expected: Ok((
                    vec![
                        CString::from(c"rm"),
                        CString::from(c"-rf"),
                        CString::from(c"/some/path"),
                    ],
                    b"ignored",
                )),
            },
            TestCase {
                input: b"\x00\x13rm\0-rf\0/some/path\0\0ignored",
                expected: Ok((
                    vec![
                        CString::from(c"rm"),
                        CString::from(c"-rf"),
                        CString::from(c"/some/path"),
                        CString::from(c""),
                    ],
                    b"ignored",
                )),
            },
            TestCase {
                input: b"",
                expected: Err(anyhow::anyhow!("Failed to get arguments length")),
            },
            TestCase {
                input: b"\x00\x11rm\0-rf\0/some/path",
                expected: Err(anyhow::anyhow!("data provided is not nul terminated")),
            },
        ];
        for TestCase { input, expected } in tests {
            let res = Process::parse_args(input);
            match (res, expected) {
                (Ok(res), Ok(expected)) => {
                    assert_eq!(res, expected, "input: '{}'", String::from_utf8_lossy(input))
                }
                (Err(res), Err(expected)) => {
                    let res = format!("{res:?}");
                    let expected = format!("{expected:?}");
                    assert_eq!(res, expected, "input: '{}'", String::from_utf8_lossy(input));
                }
                (left, right) => {
                    panic!(
                        "Result mismatch\nleft: {left:#?}\nright: {right:#?}\ninput: '{}'",
                        String::from_utf8_lossy(input)
                    )
                }
            }
        }
    }

    #[test]
    fn test_parse_lineage() {
        struct TestCase<'a> {
            input: &'a [u8],
            expected: anyhow::Result<(Lineage, &'a [u8])>,
        }
        let tests = [
            TestCase {
                input: b"\x00\x00\x03\xE8\x00\x0D/usr/bin/bash",
                expected: Ok((
                    Lineage {
                        exe_path: PathBuf::from("/usr/bin/bash"),
                        uid: 1000,
                    },
                    b"",
                )),
            },
            TestCase {
                input: b"\x00\x00\x03\xE8\x00\x0D/usr/bin/bashignored",
                expected: Ok((
                    Lineage {
                        exe_path: PathBuf::from("/usr/bin/bash"),
                        uid: 1000,
                    },
                    b"ignored",
                )),
            },
            TestCase {
                input: b"",
                expected: Err(anyhow::anyhow!("Failed to parse lineage uid")),
            },
            TestCase {
                input: b"\x00\x00\x03",
                expected: Err(anyhow::anyhow!("Failed to parse lineage uid")),
            },
            TestCase {
                input: b"\x00\x00\x03\xE8\x00\x0D/usr/bin/bas",
                expected: Err(anyhow::anyhow!("Failed to parse lineage exe_path")),
            },
        ];

        for TestCase { input, expected } in tests {
            let lineage = Lineage::parse(input);
            match (lineage, expected) {
                (Ok(lineage), Ok(expected)) => assert_eq!(
                    lineage,
                    expected,
                    "input: {}",
                    String::from_utf8_lossy(input)
                ),
                (Err(lineage), Err(expected)) => {
                    let lineage = format!("{lineage:?}");
                    let expected = format!("{expected:?}");
                    assert_eq!(
                        lineage,
                        expected,
                        "input: {}",
                        String::from_utf8_lossy(input)
                    );
                }
                (left, right) => {
                    panic!(
                        "Result mismatch\nleft: {left:#?}\nright: {right:#?}\ninput: '{}'",
                        String::from_utf8_lossy(input)
                    )
                }
            }
        }
    }
}
