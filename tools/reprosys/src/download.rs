//! Download an AMI's snapshots, copying them into the caller's account if needed.

use crate::ami::AmiInfo;
use crate::error::Result;
use aws_sdk_ebs::Client as EbsClient;
use aws_sdk_ec2::types::SnapshotState;
use aws_sdk_ec2::Client as Ec2Client;
use coldsnap::SnapshotDownloader;
use serde::{Deserialize, Serialize};
use snafu::{whatever, OptionExt, ResultExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const COPY_POLL_INTERVAL: Duration = Duration::from_secs(15);
const COPY_TIMEOUT: Duration = Duration::from_secs(3 * 60 * 60);
/// Consecutive DescribeSnapshots failures tolerated while waiting for a copy.
const MAX_DESCRIBE_FAILURES: u32 = 5;

/// Paths of the downloaded images.
#[derive(Debug, Serialize, Deserialize)]
pub struct Downloaded {
    pub root_image: PathBuf,
    pub data_image: Option<PathBuf>,
}

pub struct Downloader {
    ec2: Ec2Client,
    ebs: EbsClient,
    region: String,
    keep_copies: bool,
    /// Snapshot copies not yet deleted.
    copies: Mutex<Vec<String>>,
}

impl Downloader {
    pub fn new(ec2: Ec2Client, ebs: EbsClient, region: String, keep_copies: bool) -> Self {
        Self {
            ec2,
            ebs,
            region,
            keep_copies,
            copies: Mutex::new(Vec::new()),
        }
    }

    /// Delete the snapshot copies of an interrupted download, unless they are kept.
    pub async fn cleanup(&self) {
        let copies = std::mem::take(&mut *self.copies.lock().expect("lock poisoned"));
        for copy in copies {
            self.cleanup_copy(&copy).await;
        }
    }

    /// Finish handling a copy, applying the same retention policy on every exit path.
    async fn cleanup_copy(&self, copy: &str) {
        self.copies
            .lock()
            .expect("lock poisoned")
            .retain(|c| c != copy);
        if self.keep_copies {
            eprintln!("Keeping snapshot copy {copy}");
        } else {
            self.discard_copy(copy).await;
        }
    }

    /// Delete a snapshot copy, reporting failures so it can be deleted manually.
    async fn discard_copy(&self, copy: &str) {
        if let Err(e) = self.ec2.delete_snapshot().snapshot_id(copy).send().await {
            eprintln!(
                "Warning: failed to delete snapshot copy {copy}; delete it manually: {}",
                snafu::Report::from_error(e)
            );
        }
    }

    /// Download the AMI's root (and data, if present) snapshots into `out_dir`.
    pub async fn download(&self, info: &AmiInfo, out_dir: &Path) -> Result<Downloaded> {
        std::fs::create_dir_all(out_dir)
            .whatever_context(format!("failed to create {}", out_dir.display()))?;

        let root_image = out_dir.join("root.img");
        self.download_snapshot(info, &info.root_snapshot, &root_image)
            .await?;

        let data_image = match &info.data_snapshot {
            Some(snapshot) => {
                let path = out_dir.join("data.img");
                self.download_snapshot(info, snapshot, &path).await?;
                Some(path)
            }
            None => None,
        };

        Ok(Downloaded {
            root_image,
            data_image,
        })
    }

    async fn download_snapshot(&self, info: &AmiInfo, snapshot: &str, path: &Path) -> Result<()> {
        if info.owned_by_caller {
            eprintln!("Downloading {snapshot} to {}", path.display());
            return self.coldsnap(snapshot, path).await;
        }

        // EBS direct APIs only read snapshots owned by the caller, so copy it first.
        let copy = self.copy_snapshot(info, snapshot).await?;
        eprintln!(
            "Downloading {copy} (copy of {snapshot}) to {}",
            path.display()
        );
        let result = self.coldsnap(&copy, path).await;
        self.cleanup_copy(&copy).await;
        result
    }

    async fn coldsnap(&self, snapshot: &str, path: &Path) -> Result<()> {
        // coldsnap refuses to overwrite an existing file.
        if path.exists() {
            std::fs::remove_file(path)
                .whatever_context(format!("failed to remove {}", path.display()))?;
        }
        SnapshotDownloader::new(self.ebs.clone())
            .download_to_file(snapshot, path, None, None, None)
            .await
            .whatever_context(format!(
                "failed to download snapshot {snapshot}; the caller needs ebs:ListSnapshotBlocks and ebs:GetSnapshotBlock"
            ))
    }

    async fn copy_snapshot(&self, info: &AmiInfo, snapshot: &str) -> Result<String> {
        eprintln!(
            "Snapshot {snapshot} is owned by {}; copying it into this account",
            info.owner
        );
        let response = self
            .ec2
            .copy_snapshot()
            .source_region(&self.region)
            .source_snapshot_id(snapshot)
            .description(format!(
                "reprosys copy of {snapshot} from {} for verification",
                info.ami_id
            ))
            .send()
            .await
            .whatever_context(format!(
                "failed to copy snapshot {snapshot}; the caller needs ec2:CopySnapshot"
            ))?;
        let copy = response
            .snapshot_id()
            .whatever_context("CopySnapshot returned no snapshot ID")?
            .to_string();
        self.copies
            .lock()
            .expect("lock poisoned")
            .push(copy.clone());

        if let Err(e) = self.wait_for_snapshot(&copy).await {
            self.cleanup_copy(&copy).await;
            return Err(e);
        }
        Ok(copy)
    }

    async fn wait_for_snapshot(&self, snapshot: &str) -> Result<()> {
        let start = Instant::now();
        let mut failures = 0;
        loop {
            let response = match self
                .ec2
                .describe_snapshots()
                .snapshot_ids(snapshot)
                .send()
                .await
            {
                Ok(response) => {
                    failures = 0;
                    response
                }
                // A transient error should not end a wait that can last hours.
                Err(e) if failures + 1 < MAX_DESCRIBE_FAILURES => {
                    failures += 1;
                    eprintln!(
                        "Warning: failed to describe snapshot copy {snapshot} (attempt {failures} \
                         of {MAX_DESCRIBE_FAILURES}): {}",
                        snafu::Report::from_error(e)
                    );
                    tokio::time::sleep(COPY_POLL_INTERVAL).await;
                    continue;
                }
                Err(e) => {
                    return Err(e)
                        .whatever_context(format!("failed to describe snapshot {snapshot}"));
                }
            };
            let snap = response
                .snapshots()
                .first()
                .whatever_context(format!("snapshot {snapshot} not found"))?;
            match snap.state() {
                Some(SnapshotState::Completed) => return Ok(()),
                Some(SnapshotState::Error) => {
                    whatever!(
                        "snapshot copy {snapshot} failed: {}",
                        snap.state_message().unwrap_or("unknown error")
                    );
                }
                _ => {}
            }
            if start.elapsed() > COPY_TIMEOUT {
                whatever!("timed out waiting for snapshot copy {snapshot}");
            }
            eprintln!(
                "Waiting for snapshot copy {snapshot} ({})",
                snap.progress().unwrap_or("0%")
            );
            tokio::time::sleep(COPY_POLL_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::config::{BehaviorVersion, Credentials, Region};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn downloader(listener: &TcpListener, keep_copies: bool) -> Downloader {
        let config = aws_sdk_ec2::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-west-2"))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .endpoint_url(format!("http://{}", listener.local_addr().unwrap()))
            .build();
        Downloader::new(
            Ec2Client::from_conf(config),
            EbsClient::from_conf(
                aws_sdk_ebs::Config::builder()
                    .behavior_version(BehaviorVersion::latest())
                    .region(Region::new("us-west-2"))
                    .credentials_provider(Credentials::new("test", "test", None, None, "test"))
                    .build(),
            ),
            "us-west-2".into(),
            keep_copies,
        )
    }

    #[tokio::test]
    async fn cleanup_retains_copies_on_every_exit_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let downloader = downloader(&listener, true);
        downloader
            .copies
            .lock()
            .unwrap()
            .extend(["snap-finished".into(), "snap-interrupted".into()]);
        // Used both after a download and after a copy-wait failure.
        downloader.cleanup_copy("snap-finished").await;
        assert_eq!(*downloader.copies.lock().unwrap(), ["snap-interrupted"]);
        downloader.cleanup().await;
        assert!(downloader.copies.lock().unwrap().is_empty());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn cleanup_deletes_copies_on_every_exit_path() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let downloader = downloader(&listener, false);
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let len: usize = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + len {
                            requests.push(String::from_utf8(request[end + 4..].to_vec()).unwrap());
                            break;
                        }
                    }
                }
                let body = "<DeleteSnapshotResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><requestId>test</requestId><return>true</return></DeleteSnapshotResponse>";
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        downloader
            .copies
            .lock()
            .unwrap()
            .extend(["snap-finished".into(), "snap-interrupted".into()]);
        downloader.cleanup_copy("snap-finished").await;
        assert_eq!(*downloader.copies.lock().unwrap(), ["snap-interrupted"]);
        downloader.cleanup().await;
        assert!(downloader.copies.lock().unwrap().is_empty());
        let requests = server.join().unwrap();
        for (request, snapshot) in requests.iter().zip(["snap-finished", "snap-interrupted"]) {
            assert!(request.contains("Action=DeleteSnapshot"));
            assert!(request.contains(&format!("SnapshotId={snapshot}")));
        }
    }
}
