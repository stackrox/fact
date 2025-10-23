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
            "ringbuf_size: 64",
            FactConfig {
                ringbuf_size: Some(64),
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
            r#"
            paths:
            - /etc
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
              certs: /etc/stackrox/certs
            endpoint:
              address: 0.0.0.0:8080
              expose_metrics: true
              health_check: true
            skip_pre_flight: false
            json: false
            ringbuf_size: 8192
            hotreload: false
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 8080))),
                    expose_metrics: Some(true),
                    health_check: Some(true),
                },
                skip_pre_flight: Some(false),
                json: Some(false),
                ringbuf_size: Some(8192),
                hotreload: Some(false),
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
            "ringbuf_size: true",
            "ringbuf_size field has incorrect type: Boolean(true)",
        ),
        ("ringbuf_size: 0", "ringbuf_size out of range: 0"),
        ("ringbuf_size: -128", "ringbuf_size out of range: -128"),
        (
            &format!("ringbuf_size: {}", u32::MAX),
            &format!("ringbuf_size out of range: {}", u32::MAX),
        ),
        ("ringbuf_size: 65", "ringbuf_size is not a power of 2: 65"),
        (
            "hotreload: 4",
            "hotreload field has incorrect type: Integer(4)",
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
            r#"
            paths:
            - /etc
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
              certs: /etc/stackrox/certs
            endpoint:
              address: 127.0.0.1:8080
              expose_metrics: true
              health_check: true
            skip_pre_flight: false
            json: false
            ringbuf_size: 16384
            hotreload: false
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                grpc: GrpcConfig {
                    url: Some(String::from("http://localhost")),
                    certs: Some(PathBuf::from("/etc/certs")),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([0, 0, 0, 0], 9000))),
                    expose_metrics: Some(false),
                    health_check: Some(false),
                },
                skip_pre_flight: Some(true),
                json: Some(true),
                ringbuf_size: Some(64),
                hotreload: Some(true),
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                grpc: GrpcConfig {
                    url: Some(String::from("https://svc.sensor.stackrox:9090")),
                    certs: Some(PathBuf::from("/etc/stackrox/certs")),
                },
                endpoint: EndpointConfig {
                    address: Some(SocketAddr::from(([127, 0, 0, 1], 8080))),
                    expose_metrics: Some(true),
                    health_check: Some(true),
                },
                skip_pre_flight: Some(false),
                json: Some(false),
                ringbuf_size: Some(16384),
                hotreload: Some(false),
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
    assert_eq!(config.ringbuf_size(), 8192);
    assert!(config.hotreload());
}
