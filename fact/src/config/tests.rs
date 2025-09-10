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
            "url: http://localhost:9090",
            FactConfig {
                url: Some(String::from("http://localhost:9090")),
                ..Default::default()
            },
        ),
        (
            "certs: /etc/stackrox/certs",
            FactConfig {
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                ..Default::default()
            },
        ),
        (
            "health_check: true",
            FactConfig {
                health_check: Some(true),
                ..Default::default()
            },
        ),
        (
            "health_check: false",
            FactConfig {
                health_check: Some(false),
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
            paths:
            - /etc
            url: https://svc.sensor.stackrox:9090
            certs: /etc/stackrox/certs
            health_check: true
            skip_pre_flight: false
            json: false
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                url: Some(String::from("https://svc.sensor.stackrox:9090")),
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                health_check: Some(true),
                skip_pre_flight: Some(false),
                json: Some(false),
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
        ("url: true", "url field has incorrect type: Boolean(true)"),
        (
            "certs: true",
            "certs field has incorrect type: Boolean(true)",
        ),
        (
            "health_check: 4",
            "health_check field has incorrect type: Integer(4)",
        ),
        (
            "skip_pre_flight: 4",
            "skip_pre_flight field has incorrect type: Integer(4)",
        ),
        ("json: 4", "json field has incorrect type: Integer(4)"),
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
            "url: http://localhost",
            FactConfig::default(),
            FactConfig {
                url: Some(String::from("http://localhost")),
                ..Default::default()
            },
        ),
        (
            "url: 'https://svc.sensor.stackrox:9090'",
            FactConfig {
                url: Some(String::from("http://localhost")),
                ..Default::default()
            },
            FactConfig {
                url: Some(String::from("https://svc.sensor.stackrox:9090")),
                ..Default::default()
            },
        ),
        (
            "url: http://localhost",
            FactConfig {
                url: Some(String::from("http://localhost")),
                ..Default::default()
            },
            FactConfig {
                url: Some(String::from("http://localhost")),
                ..Default::default()
            },
        ),
        (
            "certs: /etc/stackrox/certs",
            FactConfig::default(),
            FactConfig {
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                ..Default::default()
            },
        ),
        (
            "certs: /etc/stackrox/certs",
            FactConfig {
                certs: Some(PathBuf::from("/etc/certs")),
                ..Default::default()
            },
            FactConfig {
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                ..Default::default()
            },
        ),
        (
            "certs: /etc/stackrox/certs",
            FactConfig {
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                ..Default::default()
            },
            FactConfig {
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                ..Default::default()
            },
        ),
        (
            "health_check: true",
            FactConfig::default(),
            FactConfig {
                health_check: Some(true),
                ..Default::default()
            },
        ),
        (
            "health_check: true",
            FactConfig {
                health_check: Some(false),
                ..Default::default()
            },
            FactConfig {
                health_check: Some(true),
                ..Default::default()
            },
        ),
        (
            "health_check: true",
            FactConfig {
                health_check: Some(true),
                ..Default::default()
            },
            FactConfig {
                health_check: Some(true),
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
            paths:
            - /etc
            url: https://svc.sensor.stackrox:9090
            certs: /etc/stackrox/certs
            health_check: true
            skip_pre_flight: false
            json: false
            "#,
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc"), PathBuf::from("/bin")]),
                url: Some(String::from("http://localhost")),
                certs: Some(PathBuf::from("/etc/certs")),
                health_check: Some(false),
                skip_pre_flight: Some(true),
                json: Some(true),
            },
            FactConfig {
                paths: Some(vec![PathBuf::from("/etc")]),
                url: Some(String::from("https://svc.sensor.stackrox:9090")),
                certs: Some(PathBuf::from("/etc/stackrox/certs")),
                health_check: Some(true),
                skip_pre_flight: Some(false),
                json: Some(false),
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
