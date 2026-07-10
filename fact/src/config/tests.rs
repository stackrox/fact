use std::{
    fmt::Display,
    sync::{Mutex, MutexGuard},
};

use super::*;

#[test]
fn parsing() {
    let tests = [
        ("", FactConfig::default()),
        (
            "paths:",
            FactConfig {
                paths: Some(Vec::new()),
                ..Default::default()
            },
        ),
        (
            "paths: [/etc,  /bin]",
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              url: 'http://localhost:9090'
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost:9090")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              certs: /etc/stackrox/certs
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 2
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(2)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                max: 30
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(30)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                jitter: false
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        jitter: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: 2
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(2.0),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: 3.5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(3.5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                retries: 5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        retries_max: Some(5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 0.5
                max: 120
                jitter: false
                multiplier: 2
                retries: 5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs_f64(0.5)),
                        max: Some(Duration::from_secs(120)),
                        jitter: Some(false),
                        multiplier: Some(2.0),
                        retries_max: Some(5),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            otel:
              endpoint: http://localhost:4317
            "#,
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some("http://localhost:4317".into()),
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              address: 0.0.0.0:8080
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 8080))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              address: 127.0.0.1:8080
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              address: '[::]:8080'
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from((
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        8080,
                    ))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              address: '[::1]:8080'
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from((
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        8080,
                    ))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              expose_metrics: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              expose_metrics: false
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              health_check: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              health_check: false
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "skip_pre_flight: true",
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            "skip_pre_flight: false",
            FactConfig {
                skip_pre_flight: Some(false),
                ..Default::default()
            },
        ),
        (
            "json: true",
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            "json: false",
            FactConfig {
                json: Some(false),
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
                ringbuf_size: 64
            "#,
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(64),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
                inodes_max: 64
            "#,
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(64),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "hotreload: true",
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
        ),
        (
            "hotreload: false",
            FactConfig {
                hotreload: Some(false),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 60",
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 30.5",
            FactConfig {
                scan_interval: Some(Duration::from_secs_f64(30.5)),
                ..Default::default()
            },
        ),
        (
            "rate_limit: 0",
            FactConfig {
                rate_limit: Some(0),
                ..Default::default()
            },
        ),
        (
            "rate_limit: 1000",
            FactConfig {
                rate_limit: Some(1000),
                ..Default::default()
            },
        ),
        (
            r#"
            paths:
            - /etc
            otel:
              endpoint: 'http://localhost:4317'
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
              certs: /etc/stackrox/certs
              backoff:
                initial: 0.5
                max: 120
                jitter: false
                multiplier: 2
                retries: 5
            endpoint:
              address: 0.0.0.0:8080
              expose_metrics: true
              health_check: true
            skip_pre_flight: false
            json: false
            bpf:
                ringbuf_size: 8192
                inodes_max: 64
            hotreload: false
            scan_interval: 60
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs_f64(0.5)),
                        max: Some(Duration::from_secs(120)),
                        jitter: Some(false),
                        multiplier: Some(2.0),
                        retries_max: Some(5),
                    },
                },
                otel: OTelConfig {
                    endpoint: Some("http://localhost:4317".into()),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 8080))),
                    expose_metrics: Some(true),
                    health_check: Some(true),
                },
                skip_pre_flight: Some(false),
                json: Some(false),
                bpf: BpfConfig {
                    ringbuf_size: Some(8192),
                    inodes_max: Some(64),
                },
                hotreload: Some(false),
                scan_interval: Some(Duration::from_secs(60)),
                rate_limit: None,
            },
        ),
    ];

    for (input, expected) in tests {
        let config = match FactConfig::try_from(input) {
            Ok(c) => c,
            Err(e) => panic!("Failed to parse configuration\n\tError: {e}\n\tinput: {input}"),
        };
        assert_eq!(config, expected);
    }
}

#[test]
fn parsing_errors() {
    let tests = [
        (
            "paths: true",
            "Invalid field 'paths' with value: Boolean(true)",
        ),
        (
            r#"
---
paths:
---
paths:
- /etc
            "#,
            "YAML file contains multiple documents",
        ),
        ("- something", "Wrong configuration type"),
        ("true: something", "key is not string: Boolean(true)"),
        ("4: something", "key is not string: Integer(4)"),
        ("paths: [4]", "Path has invalid type: Integer(4)"),
        (
            "grpc: true",
            "Invalid field 'grpc' with value: Boolean(true)",
        ),
        (
            r#"
            grpc:
              url: true
            "#,
            "url field has incorrect type: Boolean(true)",
        ),
        (
            r#"
            grpc:
              certs: true
            "#,
            "certs field has incorrect type: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff: true
            "#,
            "grpc.backoff section has incorrect type: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff:
                initial: true
            "#,
            "invalid grpc.backoff.initial: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff:
                max: true
            "#,
            "invalid grpc.backoff.max: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 0
            "#,
            "invalid grpc.backoff.initial: Integer(0)",
        ),
        (
            r#"
            grpc:
              backoff:
                initial: -1
            "#,
            "invalid grpc.backoff.initial: Integer(-1)",
        ),
        (
            r#"
            grpc:
              backoff:
                max: 0
            "#,
            "invalid grpc.backoff.max: Integer(0)",
        ),
        (
            r#"
            grpc:
              backoff:
                max: -5
            "#,
            "invalid grpc.backoff.max: Integer(-5)",
        ),
        (
            r#"
            grpc:
              backoff:
                jitter: 4
            "#,
            "grpc.backoff.jitter field has incorrect type: Integer(4)",
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: true
            "#,
            "invalid grpc.backoff.multiplier: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: 0.5
            "#,
            "invalid grpc.backoff.multiplier: Real(\"0.5\")",
        ),
        (
            r#"
            grpc:
              backoff:
                retries: 0.5
            "#,
            "invalid grpc.backoff.retries: Real(\"0.5\")",
        ),
        (
            r#"
            grpc:
              backoff:
                retries: true
            "#,
            "invalid grpc.backoff.retries: Boolean(true)",
        ),
        (
            r#"
            grpc:
              backoff:
                retries: -10
            "#,
            "invalid grpc.backoff.retries: Integer(-10)",
        ),
        (
            r#"
            grpc:
              backoff:
                unknown: 4
            "#,
            "Invalid field 'grpc.backoff.unknown' with value: Integer(4)",
        ),
        (
            r#"
            otel: 5
            "#,
            "Invalid field 'otel' with value: Integer(5)",
        ),
        (
            r#"
            otel:
              something: true
            "#,
            "Invalid field 'otel.something' with value: Boolean(true)",
        ),
        (
            r#"
            otel:
              endpoint: false
            "#,
            "otel.endpoint field has incorrect type: Boolean(false)",
        ),
        (
            "endpoint: true",
            "Invalid field 'endpoint' with value: Boolean(true)",
        ),
        (
            r#"
            endpoint:
              address: true
            "#,
            "endpoint.address field has incorrect type: Boolean(true)",
        ),
        (
            r#"
            endpoint:
              address: 127.0.0.1
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: :8080
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: 127.0.0.:8080
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: '[::]'
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: '[::1]'
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: '[:::1]:8080'
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              address: '[::cafe::1]:8080'
            "#,
            "Failed to parse endpoint.address: invalid socket address syntax",
        ),
        (
            r#"
            endpoint:
              expose_metrics: 4
            "#,
            "endpoint.expose_metrics field has incorrect type: Integer(4)",
        ),
        (
            r#"
            endpoint:
              health_check: 4
            "#,
            "endpoint.health_check field has incorrect type: Integer(4)",
        ),
        (
            r#"
            endpoint:
              unknown: 4
            "#,
            "Invalid field 'endpoint.unknown' with value: Integer(4)",
        ),
        (
            "skip_pre_flight: 4",
            "skip_pre_flight field has incorrect type: Integer(4)",
        ),
        ("json: 4", "json field has incorrect type: Integer(4)"),
        (
            r#"
            bpf:
              ringbuf_size: true
            "#,
            "ringbuf_size field has incorrect type: Boolean(true)",
        ),
        (
            r#"
            bpf:
              ringbuf_size: 0
            "#,
            "ringbuf_size out of range: 0",
        ),
        (
            r#"
            bpf:
              ringbuf_size: -128
            "#,
            "ringbuf_size out of range: -128",
        ),
        (
            &format!(
                r#"
                bpf:
                  ringbuf_size: {}
                "#,
                u32::MAX
            ),
            &format!("ringbuf_size out of range: {}", u32::MAX),
        ),
        (
            r#"
            bpf:
              ringbuf_size: 65
          "#,
            "ringbuf_size is not a power of 2: 65",
        ),
        (
            r#"
            bpf:
              inodes_max: true
            "#,
            "inodes_max field has incorrect type: Boolean(true)",
        ),
        (
            "hotreload: 4",
            "hotreload field has incorrect type: Integer(4)",
        ),
        (
            "scan_interval: true",
            "invalid scan_interval: Boolean(true)",
        ),
        (
            "scan_interval: -128",
            "invalid scan_interval: Integer(-128)",
        ),
        (
            "scan_interval: -128.5",
            "invalid scan_interval: Real(\"-128.5\")",
        ),
        ("unknown:", "Invalid field 'unknown' with value: Null"),
    ];
    for (input, expected) in tests {
        let Err(err) = FactConfig::try_from(input) else {
            panic!("Expected Error was not caught - expected: {expected}")
        };
        assert_eq!(format!("{}", err.root_cause()), expected);
    }
}

#[test]
fn update() {
    let tests = [
        ("", FactConfig::default(), FactConfig::default()),
        (
            "paths:",
            FactConfig::default(),
            FactConfig {
                paths: Some(Vec::new()),
                ..Default::default()
            },
        ),
        (
            "paths: [/etc, /bin]",
            FactConfig::default(),
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                ..Default::default()
            },
        ),
        (
            "paths: [/bin]",
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                ..Default::default()
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/bin")]),
                ..Default::default()
            },
        ),
        (
            "paths:",
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                ..Default::default()
            },
            FactConfig {
                paths: Some(Vec::new()),
                ..Default::default()
            },
        ),
        (
            "paths: [/etc, /bin]",
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                ..Default::default()
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              url: 'http://localhost'
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              url: 'http://localhost'
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              certs: /etc/stackrox/certs
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              certs: /etc/stackrox/certs
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              certs: /etc/stackrox/certs
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 5
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(2)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                initial: 5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                max: 120
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                max: 120
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(30)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                max: 120
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: 2
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(2.0),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                multiplier: 2
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(1.5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(2.0),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                retries: 5
            "#,
            FactConfig::default(),
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        retries_max: Some(5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            grpc:
              backoff:
                retries: 5
            "#,
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        retries_max: Some(10),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        retries_max: Some(5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            otel:
              endpoint: 'http://localhost:4317'
            "#,
            FactConfig::default(),
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:4317")),
                },
                ..Default::default()
            },
        ),
        (
            r#"
            otel:
              endpoint: 'http://localhost:4317'
            "#,
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:1234")),
                },
                ..Default::default()
            },
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:4317")),
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              expose_metrics: true
            "#,
            FactConfig::default(),
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              expose_metrics: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              expose_metrics: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              health_check: true
            "#,
            FactConfig::default(),
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              health_check: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            endpoint:
              health_check: true
            "#,
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "skip_pre_flight: true",
            FactConfig::default(),
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            "skip_pre_flight: true",
            FactConfig {
                skip_pre_flight: Some(false),
                ..Default::default()
            },
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            "skip_pre_flight: true",
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            "json: true",
            FactConfig::default(),
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            "json: true",
            FactConfig {
                json: Some(false),
                ..Default::default()
            },
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            "json: true",
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              ringbuf_size: 16384
            "#,
            FactConfig::default(),
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              ringbuf_size: 16384
            "#,
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(8192),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              ringbuf_size: 16384
            "#,
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              inodes_max: 16384
            "#,
            FactConfig::default(),
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              inodes_max: 16384
            "#,
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(8192),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            r#"
            bpf:
              inodes_max: 16384
            "#,
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(16384),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "hotreload: false",
            FactConfig::default(),
            FactConfig {
                hotreload: Some(false),
                ..Default::default()
            },
        ),
        (
            "hotreload: true",
            FactConfig {
                hotreload: Some(false),
                ..Default::default()
            },
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
        ),
        (
            "hotreload: true",
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 60",
            FactConfig::default(),
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 0.5",
            FactConfig::default(),
            FactConfig {
                scan_interval: Some(Duration::from_secs_f64(0.5)),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 60",
            FactConfig {
                scan_interval: Some(Duration::from_secs(30)),
                ..Default::default()
            },
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 25.5",
            FactConfig {
                scan_interval: Some(Duration::from_secs(30)),
                ..Default::default()
            },
            FactConfig {
                scan_interval: Some(Duration::from_secs_f64(25.5)),
                ..Default::default()
            },
        ),
        (
            "scan_interval: 60",
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        ),
        (
            r#"
            paths:
            - /etc
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
              certs: /etc/stackrox/certs
              backoff:
                initial: 0.5
                max: 120
                jitter: false
                multiplier: 3.0
                retries: 5
            otel:
              endpoint: 'http://localhost:4317'
            endpoint:
              address: 127.0.0.1:8080
              expose_metrics: true
              health_check: true
            skip_pre_flight: false
            json: false
            bpf:
              ringbuf_size: 16384
              inodes_max: 8192
            hotreload: false
            scan_interval: 60
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    certs: Some(PathBuf::from("/etc/certs")),
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(15)),
                        max: Some(Duration::from_secs(30)),
                        jitter: Some(true),
                        multiplier: Some(2.0),
                        retries_max: Some(20),
                    },
                },
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:1234")),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 9000))),
                    expose_metrics: Some(false),
                    health_check: Some(false),
                },
                skip_pre_flight: Some(true),
                json: Some(true),
                bpf: BpfConfig {
                    ringbuf_size: Some(64),
                    inodes_max: Some(4096),
                },
                hotreload: Some(true),
                scan_interval: Some(Duration::from_secs(30)),
                rate_limit: None,
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs_f64(0.5)),
                        max: Some(Duration::from_secs(120)),
                        jitter: Some(false),
                        multiplier: Some(3.0),
                        retries_max: Some(5),
                    },
                },
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:4317")),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
                    expose_metrics: Some(true),
                    health_check: Some(true),
                },
                skip_pre_flight: Some(false),
                json: Some(false),
                bpf: BpfConfig {
                    ringbuf_size: Some(16384),
                    inodes_max: Some(8192),
                },
                hotreload: Some(false),
                scan_interval: Some(Duration::from_secs(60)),
                rate_limit: None,
            },
        ),
    ];
    for (input, mut config, expected) in tests {
        let input = match FactConfig::try_from(input) {
            Ok(i) => i,
            Err(e) => panic!("Failed to parse configuration\n\tError: {e}\n\tinput: {input}"),
        };
        config.update(&input);
        assert_eq!(config, expected);
    }
}

#[test]
fn defaults() {
    let config = FactConfig::default();
    let default_paths: &[PathBuf] = &[];
    assert_eq!(config.paths(), default_paths);
    assert_eq!(config.grpc.url(), None);
    assert_eq!(config.grpc.certs(), None);
    assert_eq!(
        config.endpoint.address(),
        SocketAddr::from(([0, 0, 0, 0], 9000))
    );
    assert!(!config.endpoint.expose_metrics());
    assert!(!config.endpoint.health_check());
    assert!(!config.skip_pre_flight());
    assert!(!config.json());
    assert_eq!(config.bpf.ringbuf_size(), 8192);
    assert_eq!(config.bpf.inodes_max(), 65536);
    assert!(config.hotreload());
    assert_eq!(config.grpc.backoff.initial(), Duration::from_secs(1));
    assert_eq!(config.grpc.backoff.max(), Duration::from_secs(60));
    assert!(config.grpc.backoff.jitter());
    assert_eq!(config.grpc.backoff.multiplier(), 1.5);
    assert_eq!(config.grpc.backoff.retries(), 10);
    assert_eq!(config.otel.endpoint(), None);
}

static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that holds the `ENV_MUTEX` lock and removes the named environment
/// variable when dropped, ensuring both are released even if the test panics
/// after calling [`EnvVar::set`].
///
/// The mutex is released after the variable is removed, so no other test can
/// observe the env var in a partially-cleaned-up state.
struct EnvVarGuard {
    name: &'static str,
    _guard: MutexGuard<'static, ()>,
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(self.name) };
    }
}

/// An environment variable key-value pair used in tests to exercise env-var
/// bindings in [`FactCli`].
///
/// `std::env::set_var` is not safe to call from multi-threaded programs, as
/// other threads may be reading the environment concurrently. There is no
/// better alternative at the moment: the test binary is multi-threaded by
/// default, and the only truly sound options would be forcing
/// `RUST_TEST_THREADS=1` or switching to a single-threaded runtime, both of
/// which are more invasive than the mutex approach used here. [`EnvVar::set`]
/// acquires `ENV_MUTEX` to at least serialise all env-var mutations within our
/// own test suite.
#[derive(Clone, Copy)]
struct EnvVar {
    name: &'static str,
    value: &'static str,
}

impl EnvVar {
    /// Acquires `ENV_MUTEX`, sets the environment variable, and returns an
    /// [`EnvVarGuard`] that holds the lock and removes the variable on drop.
    fn set(self) -> EnvVarGuard {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var(self.name, self.value) };
        EnvVarGuard {
            name: self.name,
            _guard,
        }
    }
}

impl Display for EnvVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

fn with_env_var(env: EnvVar) -> Result<FactConfig, clap::Error> {
    let _guard = env.set();
    FactCli::try_parse_from(["fact"]).map(|cli| cli.into_config())
}

#[test]
fn env_vars() {
    let tests = [
        (
            EnvVar {
                name: "FACT_INODES_MAX",
                value: "1024",
            },
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(1024),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_RINGBUF_SIZE",
                value: "128",
            },
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(128),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_PATHS",
                value: "/etc:/var/log",
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/var/log")]),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_JSON",
                value: "true",
            },
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_SCAN_INTERVAL",
                value: "45.5",
            },
            FactConfig {
                scan_interval: Some(Duration::from_secs_f64(45.5)),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_SCAN_INTERVAL",
                value: "0",
            },
            FactConfig {
                scan_interval: Some(Duration::ZERO),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_RATE_LIMIT",
                value: "500",
            },
            FactConfig {
                rate_limit: Some(500),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_URL",
                value: "https://svc.sensor.stackrox:9090",
            },
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_CERTS",
                value: "/etc/stackrox/certs",
            },
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_INITIAL_DURATION",
                value: "5",
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MAX_DURATION",
                value: "120",
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_JITTER",
                value: "false",
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        jitter: Some(false),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MULTIPLIER",
                value: "2.5",
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        multiplier: Some(2.5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_RETRIES_MAX",
                value: "5",
            },
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        retries_max: Some(5),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_OTEL_ENDPOINT",
                value: "http://localhost:4317",
            },
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:4317")),
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_ADDRESS",
                value: "0.0.0.0:8080",
            },
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 8080))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_EXPOSE_METRICS",
                value: "true",
            },
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_HEALTH_CHECK",
                value: "true",
            },
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_SKIP_PRE_FLIGHT",
                value: "true",
            },
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_HOTRELOAD",
                value: "true",
            },
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
        ),
    ];
    for (env, expected) in tests {
        let config = with_env_var(env).expect("env-var CLI parse failed");
        assert_eq!(config, expected, "env var {env}");
    }
}

#[test]
fn env_vars_override_yaml() {
    let tests = [
        (
            EnvVar {
                name: "FACT_INODES_MAX",
                value: "2048",
            },
            "bpf:\n  inodes_max: 1024",
            FactConfig {
                bpf: BpfConfig {
                    inodes_max: Some(2048),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_RINGBUF_SIZE",
                value: "256",
            },
            "bpf:\n  ringbuf_size: 128",
            FactConfig {
                bpf: BpfConfig {
                    ringbuf_size: Some(256),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_URL",
                value: "https://override:9090",
            },
            "grpc:\n  url: 'https://original:9090'",
            FactConfig {
                grpc: GrpcConfig {
                    url: Some(String::from("https://override:9090")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_INITIAL_DURATION",
                value: "5",
            },
            "grpc:\n  backoff:\n    initial: 2",
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        initial: Some(Duration::from_secs(5)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MAX_DURATION",
                value: "120",
            },
            "grpc:\n  backoff:\n    max: 30",
            FactConfig {
                grpc: GrpcConfig {
                    backoff: BackoffConfig {
                        max: Some(Duration::from_secs(120)),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_OTEL_ENDPOINT",
                value: "http://localhost:4317",
            },
            r#"
            otel:
              endpoint: 'http://localhost:1234'
            "#,
            FactConfig {
                otel: OTelConfig {
                    endpoint: Some(String::from("http://localhost:4317")),
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_PATHS",
                value: "/var/log",
            },
            "paths:\n- /etc",
            FactConfig {
                paths: Some(vec![PathBuf::from("/var/log")]),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_JSON",
                value: "true",
            },
            "json: false",
            FactConfig {
                json: Some(true),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_SCAN_INTERVAL",
                value: "60",
            },
            "scan_interval: 30",
            FactConfig {
                scan_interval: Some(Duration::from_secs(60)),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_RATE_LIMIT",
                value: "1000",
            },
            "rate_limit: 500",
            FactConfig {
                rate_limit: Some(1000),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_CERTS",
                value: "/etc/override/certs",
            },
            "grpc:\n  certs: /etc/original/certs",
            FactConfig {
                grpc: GrpcConfig {
                    certs: Some(PathBuf::from("/etc/override/certs")),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_ADDRESS",
                value: "127.0.0.1:9090",
            },
            "endpoint:\n  address: 0.0.0.0:8080",
            FactConfig {
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([127, 0, 0, 1], 9090))),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_EXPOSE_METRICS",
                value: "true",
            },
            "endpoint:\n  expose_metrics: false",
            FactConfig {
                endpoint: EndpointConfig {
                    expose_metrics: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_HEALTH_CHECK",
                value: "true",
            },
            "endpoint:\n  health_check: false",
            FactConfig {
                endpoint: EndpointConfig {
                    health_check: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_SKIP_PRE_FLIGHT",
                value: "true",
            },
            "skip_pre_flight: false",
            FactConfig {
                skip_pre_flight: Some(true),
                ..Default::default()
            },
        ),
        (
            EnvVar {
                name: "FACT_HOTRELOAD",
                value: "true",
            },
            "hotreload: false",
            FactConfig {
                hotreload: Some(true),
                ..Default::default()
            },
        ),
    ];
    for (env, yaml, expected) in tests {
        let mut config = match FactConfig::try_from(yaml) {
            Ok(c) => c,
            Err(e) => panic!("Failed to parse YAML\n\tError: {e}\n\tyaml: {yaml}"),
        };
        config.update(&with_env_var(env).expect("env-var CLI parse failed"));
        assert_eq!(config, expected, "env var {env} should override yaml",);
    }
}

#[test]
fn env_vars_invalid_values() {
    fn first_line(err: clap::Error) -> String {
        let err = err.to_string();
        let Some((line, _)) = err.split_once('\n') else {
            panic!("Error did not have a newline: {err}");
        };

        line.to_string()
    }

    let tests = [
        (
            EnvVar {
                name: "FACT_INODES_MAX",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--inodes-max <INODES_MAX>': invalid digit found in string",
        ),
        (
            EnvVar {
                name: "FACT_RINGBUF_SIZE",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--ringbuf-size <RINGBUF_SIZE>': invalid digit found in string",
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_ADDRESS",
                value: "not_an_address",
            },
            "error: invalid value 'not_an_address' for '--address <ADDRESS>': invalid socket address syntax",
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_EXPOSE_METRICS",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--expose-metrics'",
        ),
        (
            EnvVar {
                name: "FACT_ENDPOINT_HEALTH_CHECK",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--health-check'",
        ),
        (
            EnvVar {
                name: "FACT_SCAN_INTERVAL",
                value: "not_a_float",
            },
            "error: invalid value 'not_a_float' for '--scan-interval <SCAN_INTERVAL>': invalid float literal",
        ),
        (
            EnvVar {
                name: "FACT_RATE_LIMIT",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--rate-limit <RATE_LIMIT>': invalid digit found in string",
        ),
        (
            EnvVar {
                name: "FACT_JSON",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--json'",
        ),
        (
            EnvVar {
                name: "FACT_SKIP_PRE_FLIGHT",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--skip-pre-flight'",
        ),
        (
            EnvVar {
                name: "FACT_HOTRELOAD",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--hotreload'",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_INITIAL_DURATION",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--backoff-initial <BACKOFF_INITIAL>': invalid float literal",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MAX_DURATION",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--backoff-max <BACKOFF_MAX>': invalid float literal",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_INITIAL_DURATION",
                value: "0",
            },
            "error: invalid value '0' for '--backoff-initial <BACKOFF_INITIAL>': value must be greater than zero",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MAX_DURATION",
                value: "0",
            },
            "error: invalid value '0' for '--backoff-max <BACKOFF_MAX>': value must be greater than zero",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_INITIAL_DURATION",
                value: "-1",
            },
            "error: invalid value '-1' for '--backoff-initial <BACKOFF_INITIAL>': value must be a non-negative finite number, got -1",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MAX_DURATION",
                value: "-1",
            },
            "error: invalid value '-1' for '--backoff-max <BACKOFF_MAX>': value must be a non-negative finite number, got -1",
        ),
        (
            EnvVar {
                name: "FACT_SCAN_INTERVAL",
                value: "-1",
            },
            "error: invalid value '-1' for '--scan-interval <SCAN_INTERVAL>': value must be a non-negative finite number, got -1",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_JITTER",
                value: "not_a_boolean",
            },
            "error: invalid value 'not_a_boolean' for '--backoff-jitter <BACKOFF_JITTER>'",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MULTIPLIER",
                value: "not_a_number",
            },
            "error: invalid value 'not_a_number' for '--backoff-multiplier <BACKOFF_MULTIPLIER>': invalid float literal",
        ),
        (
            EnvVar {
                name: "FACT_GRPC_BACKOFF_MULTIPLIER",
                value: "0.5",
            },
            "error: invalid value '0.5' for '--backoff-multiplier <BACKOFF_MULTIPLIER>': multiplier must be > 1.0, got 0.5",
        ),
    ];
    for (env, expected) in tests {
        let Err(err) = with_env_var(env) else {
            panic!("Expected Error was not caught - expected: {expected}");
        };
        let err = first_line(err);
        assert_eq!(err, expected);
    }
}
