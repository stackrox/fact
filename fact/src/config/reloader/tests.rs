use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::config::BackoffConfig;

use super::*;

/// Assert the value in the watch::Receiver matches the expected one or
/// it hasn't been updated.
///
/// This is not part of the generate_test macro in order to help the
/// macro in doing type inference properly when the expected value is
/// None.
fn assert_reload<T>(result: watch::Receiver<T>, expected: Option<T>)
where
    T: Debug + PartialEq,
{
    match expected {
        Some(expected) => {
            assert!(result.has_changed().unwrap());
            assert_eq!(*result.borrow(), expected);
        }
        None => {
            assert!(!result.has_changed().unwrap());
        }
    }
}

macro_rules! generate_test {
    ($testname:ident, $channel:ident, $old:expr, $new:expr, $expected:expr) => {
        #[test]
        fn $testname() {
            let reloader = Reloader::from($old);
            let channel = reloader.$channel();
            reloader.send_updates($new);

            assert_reload(channel, $expected);
        }
    };
}

macro_rules! generate_paths_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, paths, $old, $new, $expected);
    };
}

generate_paths_test! {
    test_reloader_paths_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}
generate_paths_test! {
    test_reloader_paths_from_default_to_empty,
    FactConfig::default(),
    FactConfig {
        paths: PathsConfig::default(),
        ..Default::default()
    },
    None
}
generate_paths_test! {
    test_reloader_paths_config_change,
    FactConfig {
        paths: ["/home".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    FactConfig {
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    Some([PathBuf::from("/etc")].as_slice().try_into().unwrap())
}
generate_paths_test! {
    test_reloader_paths_no_config_change,
    FactConfig {
        paths: ["/home".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    FactConfig {
        paths: ["/home".into()].as_slice().try_into().unwrap(),
        scan_interval: Some(Duration::from_secs(10)),
        ..Default::default()
    },
    None
}

macro_rules! generate_scan_interval_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, scan_interval, $old, $new, $expected);
    };
}

generate_scan_interval_test! {
    test_reloader_scan_interval_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}
generate_scan_interval_test! {
    test_reloader_scan_interval_from_default,
    FactConfig::default(),
    FactConfig {
        scan_interval: Some(Duration::from_secs(10)),
        ..Default::default()
    },
    Some(Duration::from_secs(10))
}
generate_scan_interval_test! {
    test_reloader_scan_interval_to_default,
    FactConfig {
        scan_interval: Some(Duration::from_secs(10)),
        ..Default::default()
    },
    FactConfig::default(),
    Some(Duration::from_secs(30))
}
generate_scan_interval_test! {
    test_reloader_scan_interval_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        scan_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    },
    None
}
generate_scan_interval_test! {
    test_reloader_scan_interval_to_default_from_explicit_default,
    FactConfig {
        scan_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    },
    FactConfig::default(),
    None
}
generate_scan_interval_test! {
    test_reloader_scan_interval_changed,
    FactConfig {
        scan_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    },
    FactConfig {
        scan_interval: Some(Duration::from_secs(60)),
        ..Default::default()
    },
    Some(Duration::from_secs(60))
}
generate_scan_interval_test! {
    test_reloader_scan_interval_no_change,
    FactConfig {
        scan_interval: Some(Duration::from_secs(60)),
        ..Default::default()
    },
    FactConfig {
        scan_interval: Some(Duration::from_secs(60)),
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    None
}

macro_rules! generate_rate_limit_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, rate_limit, $old, $new, $expected);
    };
}

generate_rate_limit_test! {
    test_reloader_rate_limit_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}
generate_rate_limit_test! {
    test_reloader_rate_limit_from_default,
    FactConfig::default(),
    FactConfig {
        rate_limit: Some(5000),
        ..Default::default()
    },
    Some(5000)
}
generate_rate_limit_test! {
    test_reloader_rate_limit_to_default,
    FactConfig {
        rate_limit: Some(5000),
        ..Default::default()
    },
    FactConfig::default(),
    Some(0)
}
generate_rate_limit_test! {
    test_reloader_rate_limit_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        rate_limit: Some(0),
        ..Default::default()
    },
    None
}
generate_rate_limit_test! {
    test_reloader_rate_limit_to_default_from_explicit_default,
    FactConfig {
        rate_limit: Some(0),
        ..Default::default()
    },
    FactConfig::default(),
    None
}
generate_rate_limit_test! {
    test_reloader_rate_limit_changed,
    FactConfig {
        rate_limit: Some(1000),
        ..Default::default()
    },
    FactConfig {
        rate_limit: Some(5000),
        ..Default::default()
    },
    Some(5000)
}
generate_rate_limit_test! {
    test_reloader_rate_limit_no_change,
    FactConfig {
        rate_limit: Some(1000),
        ..Default::default()
    },
    FactConfig {
        rate_limit: Some(1000),
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    None
}

macro_rules! generate_endpoint_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, endpoint, $old, $new, $expected);
    };
}

generate_endpoint_test! {
    test_reloader_endpoint_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}
generate_endpoint_test! {
    test_reloader_endpoint_no_change,
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_DEFAULT),
            expose_metrics: Some(true),
            health_check: Some(true),
            introspection: Some(true),
        },
        ..Default::default()
    },
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_DEFAULT),
            expose_metrics: Some(true),
            health_check: Some(true),
            introspection: Some(true),
        },
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    None
}

const ENDPOINT_ADDRESS_DEFAULT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9000);
const ENDPOINT_ADDRESS_LOCAL: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

generate_endpoint_test! {
    test_reloader_endpoint_address_from_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_LOCAL),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        address: Some(ENDPOINT_ADDRESS_LOCAL),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_address_to_default,
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_LOCAL),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_address_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        address: Some(ENDPOINT_ADDRESS_DEFAULT),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_address_to_default_from_explicit_default,
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_address_changed,
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(ENDPOINT_ADDRESS_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        endpoint: EndpointConfig {
            address: Some(SocketAddr::from(([0,0,0,0], 8000))),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        address: Some(SocketAddr::from(([0,0,0,0], 8000))),
        ..Default::default()
    })
}

generate_endpoint_test! {
    test_reloader_endpoint_expose_metrics_from_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            expose_metrics: Some(true),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        expose_metrics: Some(true),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_expose_metrics_to_default,
    FactConfig {
        endpoint: EndpointConfig {
            expose_metrics: Some(true),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_expose_metrics_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            expose_metrics: Some(false),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        expose_metrics: Some(false),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_expose_metrics_to_default_from_explicit_default,
    FactConfig {
        endpoint: EndpointConfig {
            expose_metrics: Some(false),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_expose_metrics_changed,
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
    Some(EndpointConfig {
        expose_metrics: Some(true),
        ..Default::default()
    })
}

generate_endpoint_test! {
    test_reloader_endpoint_health_check_from_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            health_check: Some(true),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        health_check: Some(true),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_health_check_to_default,
    FactConfig {
        endpoint: EndpointConfig {
            health_check: Some(true),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_health_check_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        endpoint: EndpointConfig {
            health_check: Some(false),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(EndpointConfig {
        health_check: Some(false),
        ..Default::default()
    })
}
generate_endpoint_test! {
    test_reloader_endpoint_health_check_to_default_from_explicit_default,
    FactConfig {
        endpoint: EndpointConfig {
            health_check: Some(false),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(EndpointConfig::default())
}
generate_endpoint_test! {
    test_reloader_endpoint_health_check_changed,
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
    Some(EndpointConfig {
        health_check: Some(true),
        ..Default::default()
    })
}

macro_rules! generate_grpc_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, grpc, $old, $new, $expected);
    };
}

generate_grpc_test! {
    test_reloader_grpc_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}

generate_grpc_test! {
    test_reloader_grpc_no_change,
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_NEW.into()),
            certs: Some(GRPC_CERTS_NEW.into()),
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                max: Some(GRPC_BACKOFF_MAX_NEW),
                jitter: Some(false),
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
            }
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_NEW.into()),
            certs: Some(GRPC_CERTS_NEW.into()),
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                max: Some(GRPC_BACKOFF_MAX_NEW),
                jitter: Some(false),
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
            }
        },
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    None
}

const GRPC_URL_OLD: &str = "https://old.example.com";
const GRPC_URL_NEW: &str = "https://new.example.com";

generate_grpc_test! {
    test_reloader_grpc_url_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        url: Some(GRPC_URL_NEW.into()),
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_url_to_default,
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_url_changed,
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        url: Some(GRPC_URL_NEW.into()),
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_url_no_change,
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            url: Some(GRPC_URL_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

const GRPC_CERTS_OLD: &str = "/etc/stackrox/old-certs";
const GRPC_CERTS_NEW: &str = "/etc/stackrox/new-certs";

generate_grpc_test! {
    test_reloader_grpc_certs_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        certs: Some(GRPC_CERTS_NEW.into()),
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_certs_to_default,
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_certs_changed,
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_NEW.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        certs: Some(GRPC_CERTS_NEW.into()),
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_certs_no_change,
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            certs: Some(GRPC_CERTS_OLD.into()),
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

const GRPC_BACKOFF_INITIAL_DEFAULT: Duration = Duration::from_secs(1);
const GRPC_BACKOFF_INITIAL_OLD: Duration = Duration::from_secs(5);
const GRPC_BACKOFF_INITIAL_NEW: Duration = Duration::from_secs(10);

generate_grpc_test! {
    test_reloader_grpc_backoff_initial_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            initial: Some(GRPC_BACKOFF_INITIAL_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_initial_to_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_initial_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            initial: Some(GRPC_BACKOFF_INITIAL_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_initial_to_default_from_explicit_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_initial_changed,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_OLD),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            initial: Some(GRPC_BACKOFF_INITIAL_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_initial_no_change,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                initial: Some(GRPC_BACKOFF_INITIAL_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

const GRPC_BACKOFF_MAX_DEFAULT: Duration = Duration::from_secs(60);
const GRPC_BACKOFF_MAX_OLD: Duration = Duration::from_secs(5);
const GRPC_BACKOFF_MAX_NEW: Duration = Duration::from_secs(10);

generate_grpc_test! {
    test_reloader_grpc_backoff_max_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            max: Some(GRPC_BACKOFF_MAX_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_max_to_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_max_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            max: Some(GRPC_BACKOFF_MAX_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_max_to_default_from_explicit_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_max_changed,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_OLD),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            max: Some(GRPC_BACKOFF_MAX_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_max_no_change,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                max: Some(GRPC_BACKOFF_MAX_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_from_default,
    FactConfig::default(),
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
    Some(GrpcConfig {
        backoff: BackoffConfig {
            jitter: Some(false),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_to_default,
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
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                jitter: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            jitter: Some(true),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_to_default_from_explicit_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                jitter: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_changed,
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
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                jitter: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            jitter: Some(true),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_jitter_no_change,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                jitter: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                jitter: Some(true),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

const GRPC_BACKOFF_MULTIPLIER_DEFAULT: f64 = 1.5;
const GRPC_BACKOFF_MULTIPLIER_OLD: f64 = 5.0;
const GRPC_BACKOFF_MULTIPLIER_NEW: f64 = 3.5;

generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_to_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            multiplier: Some(GRPC_BACKOFF_MULTIPLIER_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_to_default_from_explicit_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_changed,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_OLD),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_multiplier_no_change,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                multiplier: Some(GRPC_BACKOFF_MULTIPLIER_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

const GRPC_BACKOFF_RETRIES_DEFAULT: u64 = 10;
const GRPC_BACKOFF_RETRIES_OLD: u64 = 20;
const GRPC_BACKOFF_RETRIES_NEW: u64 = 5;

generate_grpc_test! {
    test_reloader_grpc_backoff_retries_from_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_retries_to_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_retries_from_default_to_explicit_default,
    FactConfig::default(),
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            retries_max: Some(GRPC_BACKOFF_RETRIES_DEFAULT),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_retries_to_default_from_explicit_default,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_DEFAULT),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(GrpcConfig::default())
}
generate_grpc_test! {
    test_reloader_grpc_backoff_retries_changed,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_OLD),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    Some(GrpcConfig {
        backoff: BackoffConfig {
            retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
            ..Default::default()
        },
        ..Default::default()
    })
}
generate_grpc_test! {
    test_reloader_grpc_backoff_retries_no_change,
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    FactConfig {
        grpc: GrpcConfig {
            backoff: BackoffConfig {
                retries_max: Some(GRPC_BACKOFF_RETRIES_NEW),
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    },
    None
}

macro_rules! generate_otel_test {
    ($testname:ident, $old:expr, $new:expr, $expected:expr) => {
        generate_test!($testname, otel, $old, $new, $expected);
    };
}

const OTEL_ENDPOINT_OLD: &str = "http://old:4317";
const OTEL_ENDPOINT_NEW: &str = "http://new:4317";

generate_otel_test! {
    test_reloader_otel_default,
    FactConfig::default(),
    FactConfig::default(),
    None
}
generate_otel_test! {
    test_reloader_otel_endpoint_from_default,
    FactConfig::default(),
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_NEW.into()),
        },
        ..Default::default()
    },
    Some(OTelConfig {
        endpoint: Some(OTEL_ENDPOINT_NEW.into()),
    })
}
generate_otel_test! {
    test_reloader_otel_endpoint_to_default,
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_NEW.into()),
        },
        ..Default::default()
    },
    FactConfig::default(),
    Some(OTelConfig::default())
}
generate_otel_test! {
    test_reloader_otel_endpoint_changed,
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_OLD.into()),
        },
        ..Default::default()
    },
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_NEW.into()),
        },
        ..Default::default()
    },
    Some(OTelConfig {
        endpoint: Some(OTEL_ENDPOINT_NEW.into()),
    })
}
generate_otel_test! {
    test_reloader_otel_endpoint_no_change,
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_NEW.into()),
        },
        ..Default::default()
    },
    FactConfig {
        otel: OTelConfig {
            endpoint: Some(OTEL_ENDPOINT_NEW.into()),
        },
        paths: ["/etc".into()].as_slice().try_into().unwrap(),
        ..Default::default()
    },
    None
}
