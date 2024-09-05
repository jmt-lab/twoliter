use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use once_cell::sync::Lazy;
use tempdir::TempDir;

use super::{run_command, test_projects_dir, TWOLITER_PATH};

const INFRA_TOML: &str = r#"
[vendor.primary]
registry = "localhost:5000"
[vendor.secondary]
registry = "localhost:5001"
"#;
const COMPOSE_YAML: &str = r#"
services:
  primary:
    image: registry:2.8.3
    environment:
      REGISTRY_HTTP_RELATIVEURLS: "true"
      REGISTRY_HTTP_ADDR: 0.0.0.0:5000
      REGISTRY_HTTP_TLS_CERTIFICATE: "/auth/certs/registry.crt"
      REGISTRY_HTTP_TLS_KEY: "/auth/certs/registry.key"
    volumes:
      - ./certs:/auth/certs:ro
    ports:
      - "5000:5000"
  secondary:
    image: registry:2.8.3
    environment:
      REGISTRY_HTTP_RELATIVEURLS: "true"
      REGISTRY_HTTP_ADDR: 0.0.0.0:5001
      REGISTRY_HTTP_TLS_CERTIFICATE: "/auth/certs/registry.crt"
      REGISTRY_HTTP_TLS_KEY: "/auth/certs/registry.key"
    volumes:
      - ./certs:/auth/certs:ro
    ports:
      - "5001:5001"
"#;

const NGINX_CONF: &str = r#"
events {}
http {
  server {
    listen 1443 ssl;
    server_name local.registry.dev;

    ssl_certificate /etc/nginx/certs/nginx.crt;
    ssl_certificate_key /etc/nginx/certs/nginx.key;

    location / {
      proxy_pass http://primary:5000;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }

  server {
    listen 2443 ssl;
    server_name local.registry.dev;

    ssl_certificate /etc/nginx/certs/nginx.crt;
    ssl_certificate_key /etc/nginx/certs/nginx.key;

    location / {
      proxy_pass http://primary:5001;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
    }
  }
}
"#;

const EXPECTED_LOCKFILE: &str = r#"schema-version = 1

[sdk]
name = "bottlerocket-sdk"
version = "0.42.0"
vendor = "bottlerocket"
source = "public.ecr.aws/bottlerocket/bottlerocket-sdk:v0.42.0"
digest = "myHHKE41h9qfeyR6V6HB0BfiLPwj3QEFLUFy4TXcR10="

[[kit]]
name = "extra-3-kit"
version = "1.0.0"
vendor = "primary"
source = "localhost:5000/extra-3-kit:v1.0.0"
digest = "vlTsAAbSCzXFZofVmw8pLLkRjnG/y8mtb2QsQBSz1zk="
"#;

const OVERRIDE_FILE: &str = r#"
[primary.extra-3-kit]
registry = "localhost:5001"
"#;

struct KitProvider {
    temp_dir: TempDir,
}

impl KitProvider {
    fn new() -> Self {
        let local_kit_dir = test_projects_dir().join("local-kit");
        let temp_dir =
            TempDir::new("registry").expect("failed to create path for oci registry spinup");
        let config_file = temp_dir.path().join("compose.yml");
        std::fs::write(&config_file, COMPOSE_YAML).expect("failed to write compose file");
        let cert_dir = temp_dir.path().join("certs");
        let cert_file = cert_dir.join("registry.crt");
        std::fs::create_dir_all(&cert_dir).expect("failed to create nginx dir");
        let output = run_command(
            "openssl",
            [
                "req",
                "-x509",
                "-nodes",
                "-days",
                "365",
                "-newkey",
                "rsa:2048",
                "-keyout",
                cert_dir.join("registry.key").to_str().unwrap(),
                "-out",
                cert_file.to_str().unwrap(),
                "-batch",
                "-addext",
                "subjectAltName=DNS:localhost",
            ],
            [],
        );
        assert!(
            output.status.success(),
            "generate openssl self-signed certificates"
        );
        let output = run_command(
            "docker",
            ["compose", "-f", config_file.to_str().unwrap(), "up", "-d"],
            [],
        );
        assert!(output.status.success(), "failed to start oci registry");

        // Prime the registry with kits

        std::fs::write(local_kit_dir.join("Infra.toml"), INFRA_TOML).ok();
        // First we want to build our kits and publish them
        let output = run_command(
            TWOLITER_PATH,
            [
                "update",
                "--project-path",
                local_kit_dir.join("Twoliter.toml").to_str().unwrap(),
            ],
            [],
        );
        assert!(output.status.success(), "update on local kit failed");
        let output = run_command(
            TWOLITER_PATH,
            [
                "fetch",
                "--project-path",
                local_kit_dir.join("Twoliter.toml").to_str().unwrap(),
                "--arch",
                "x86_64",
            ],
            [],
        );
        assert!(output.status.success(), "fetch on local kit failed");
        // Build the kits and publish them
        for kit in ["core-kit", "extra-1-kit", "extra-2-kit", "extra-3-kit"] {
            build_kit(&local_kit_dir, kit);
            publish_kit(&local_kit_dir, kit, "primary", &cert_file);
        }
        // Publish extra-3-kit to secondary as well
        publish_kit(&local_kit_dir, "extra-3-kit", "secondary", &cert_file);
        Self { temp_dir }
    }

    fn cert_file(&self) -> PathBuf {
        self.temp_dir
            .path()
            .join("certs/registry.crt")
            .to_path_buf()
    }
}

impl Drop for KitProvider {
    fn drop(&mut self) {
        let output = run_command(
            "docker",
            [
                "compose",
                "-f",
                self.temp_dir.path().join("compose.yml").to_str().unwrap(),
                "down",
            ],
            [],
        );
        assert!(output.status.success(), "failed to stop oci registry");
    }
}

static PROVIDER: Lazy<Arc<KitProvider>> = Lazy::new(|| Arc::new(KitProvider::new()));

fn build_kit<P: AsRef<Path>>(project_dir: P, kit_name: &str) {
    let output = run_command(
        TWOLITER_PATH,
        [
            "build",
            "kit",
            "--project-path",
            project_dir.as_ref().join("Twoliter.toml").to_str().unwrap(),
            kit_name,
        ],
        [],
    );

    assert!(output.status.success(), "failed to build kit {}", kit_name);
}

fn publish_kit<P: AsRef<Path>>(project_dir: P, kit_name: &str, vendor_name: &str, cert_file: P) {
    let output = run_command(
        TWOLITER_PATH,
        [
            "publish",
            "kit",
            "--project-path",
            project_dir.as_ref().join("Twoliter.toml").to_str().unwrap(),
            kit_name,
            vendor_name,
        ],
        [("SSL_CERT_FILE", cert_file.as_ref().to_str().unwrap())],
    );

    assert!(
        output.status.success(),
        "failed to publish kit {} to vendor",
        kit_name,
    );
}

#[test]
#[ignore]
fn test_twoliter_override_docker() {
    let provider = PROVIDER.clone();
    let test_dir = test_projects_dir().join("twoliter-overrides");
    let external_kit_dir = test_projects_dir().join("external-kit");
    let override_file = external_kit_dir.join("Twoliter.override");

    std::fs::create_dir_all(&test_dir).ok();
    std::fs::write(&override_file, OVERRIDE_FILE).ok();

    // Now we are ready to try and consume them
    let output = run_command(
        TWOLITER_PATH,
        [
            "update",
            "--project-path",
            external_kit_dir.join("Twoliter.toml").to_str().unwrap(),
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "docker"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "update on external kit failed");
    let output = run_command(
        TWOLITER_PATH,
        [
            "fetch",
            "--project-path",
            external_kit_dir.join("Twoliter.toml").to_str().unwrap(),
            "--arch",
            "x86_64",
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "docker"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "fetch on external kit failed");

    std::fs::remove_dir_all(&test_dir).ok();
}

#[test]
#[ignore]
fn test_twoliter_override_crane() {
    let provider = PROVIDER.clone();
    let test_dir = test_projects_dir().join("twoliter-overrides");
    let external_kit_dir = test_projects_dir().join("external-kit");
    let override_file = external_kit_dir.join("Twoliter.override");

    std::fs::create_dir_all(&test_dir).ok();
    std::fs::write(&override_file, OVERRIDE_FILE).ok();

    // Now we are ready to try and consume them
    let output = run_command(
        TWOLITER_PATH,
        [
            "update",
            "--project-path",
            external_kit_dir.join("Twoliter.toml").to_str().unwrap(),
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "crane"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "update on external kit failed");
    let output = run_command(
        TWOLITER_PATH,
        [
            "fetch",
            "--project-path",
            external_kit_dir.join("Twoliter.toml").to_str().unwrap(),
            "--arch",
            "x86_64",
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "crane"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );
    assert!(output.status.success(), "fetch on external kit failed");

    std::fs::remove_dir_all(&test_dir).ok();
}

#[test]
#[ignore]
/// Generates a Twoliter.lock file for the `external-kit` project using docker
fn test_twoliter_update_docker() {
    let provider = PROVIDER.clone();
    let external_kit = test_projects_dir().join("external-kit");
    let lockfile = external_kit.join("Twoliter.lock");
    std::fs::remove_file(&lockfile).ok();

    let output = run_command(
        TWOLITER_PATH,
        [
            "update",
            "--project-path",
            external_kit.join("Twoliter.toml").to_str().unwrap(),
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "docker"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );

    assert!(output.status.success());

    let lock_contents = std::fs::read_to_string(&lockfile).unwrap();
    assert_eq!(lock_contents, EXPECTED_LOCKFILE);

    std::fs::remove_file(&lockfile).ok();
}

#[test]
#[ignore]
/// Generates a Twoliter.lock file for the `external-kit` project using crane
fn test_twoliter_update_crane() {
    let provider = PROVIDER.clone();
    let external_kit = test_projects_dir().join("external-kit");

    let lockfile = external_kit.join("Twoliter.lock");
    std::fs::remove_file(&lockfile).ok();

    let output = run_command(
        TWOLITER_PATH,
        [
            "update",
            "--project-path",
            external_kit.join("Twoliter.toml").to_str().unwrap(),
        ],
        [
            ("TWOLITER_KIT_IMAGE_TOOL", "crane"),
            ("SSL_CERT_FILE", provider.cert_file().to_str().unwrap()),
        ],
    );

    assert!(output.status.success());

    let lock_contents = std::fs::read_to_string(&lockfile).unwrap();
    assert_eq!(lock_contents, EXPECTED_LOCKFILE);

    std::fs::remove_file(&lockfile).ok();
}
