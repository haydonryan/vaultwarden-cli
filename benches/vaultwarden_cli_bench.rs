#![allow(dead_code)]

use argy::FromArgs;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use serde_json::json;
use std::fmt::Write;
use std::hint::black_box;
use std::time::Duration;
use vaultwarden_cli::models::{
    Cipher, CipherData, CipherId, CipherOutput, CollectionId, FieldData, FieldOutput, FieldType,
    FolderId, LoginData, OrgId, SyncResponse, UriData,
};

const WORKLOADS: [(&str, usize); 3] = [("small", 16), ("medium", 256), ("large", 1024)];

#[derive(FromArgs)]
/// vaultwarden-cli
struct Cli {
    /// allow insecure HTTP connections
    #[argy(switch, global)]
    allow_insecure_http: bool,
    /// allow plaintext JSON output
    #[argy(switch, global)]
    allow_plaintext_json: bool,
    #[argy(subcommand)]
    command: Commands,
}

#[derive(FromArgs)]
#[argy(subcommand)]
enum Commands {
    List(ListCommand),
    Get(GetCommand),
    Run(RunCommand),
    Status(StatusCommand),
    Unlock(UnlockCommand),
}

#[derive(FromArgs)]
#[argy(subcommand, name = "list")]
/// list items
struct ListCommand {
    /// filter by type
    #[argy(option, short = 't')]
    r#type: Option<String>,
    /// output JSON
    #[argy(switch)]
    json: bool,
    /// search term
    #[argy(option, short = 's')]
    search: Option<String>,
    /// organization
    #[argy(option)]
    org: Option<String>,
    /// collection
    #[argy(option, short = 'c')]
    collection: Option<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "get")]
/// get an item
struct GetCommand {
    /// item id or name
    #[argy(positional)]
    item: String,
    /// output format
    #[argy(option, short = 'f')]
    format: Option<String>,
    /// output password only
    #[argy(switch, short = 'p')]
    password: bool,
    /// output username only
    #[argy(switch, short = 'u')]
    username: bool,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "run")]
/// run a command with secrets
struct RunCommand {
    /// item name(s)
    #[argy(option, short = 'n')]
    name: Vec<String>,
    /// organization
    #[argy(option)]
    org: Option<String>,
    /// collection
    #[argy(option, short = 'c')]
    collection: Option<String>,
    /// command to run
    #[argy(positional, last)]
    command: Vec<String>,
}

#[derive(FromArgs)]
#[argy(subcommand, name = "status")]
/// show status
struct StatusCommand {}

#[derive(FromArgs)]
#[argy(subcommand, name = "unlock")]
/// unlock the vault
struct UnlockCommand {
    /// master password
    #[argy(option, short = 'p')]
    password: Option<String>,
}

fn command_args() -> Vec<Vec<&'static str>> {
    vec![
        vec!["vaultwarden-cli", "status"],
        vec![
            "vaultwarden-cli",
            "list",
            "--type",
            "login",
            "--search",
            "service-99",
        ],
        vec![
            "vaultwarden-cli",
            "list",
            "--json",
            "--collection",
            "collection-3",
        ],
        vec!["vaultwarden-cli", "get", "service-42", "--format", "json"],
        vec![
            "vaultwarden-cli",
            "run",
            "--name",
            "service-42",
            "--collection",
            "collection-2",
            "--",
            "env",
        ],
        vec![
            "vaultwarden-cli",
            "unlock",
            "--password",
            "benchmark-password",
        ],
    ]
}

fn fixture_ciphers(count: usize) -> Vec<Cipher> {
    (0..count)
        .map(|i| Cipher {
            id: CipherId::new(format!("cipher-{i:04}")).unwrap(),
            organization_id: Some(OrgId::new(format!("org-{}", i % 4)).unwrap()),
            deleted_date: None,
            name: Some(format!("service-{i:04}")),
            notes: Some(format!("deterministic note {i}")),
            folder_id: Some(FolderId::new(format!("folder-{}", i % 8)).unwrap()),
            collection_ids: vec![CollectionId::new(format!("collection-{}", i % 6)).unwrap()],
            fields: Some(vec![FieldData {
                name: Some("api-token".to_string()),
                value: Some(format!("token-{i:04}")),
                r#type: FieldType::Hidden,
            }]),
            data: None,
            cipher_data: Some(CipherData::Login(LoginData {
                username: Some(format!("user-{i}@example.com")),
                password: Some(format!("password-{i:04}")),
                totp: None,
                uris: Some(vec![UriData {
                    uri: Some(format!("https://service-{i:04}.example.com/login")),
                    r#match: None,
                }]),
            })),
        })
        .collect()
}

fn fixture_outputs(ciphers: &[Cipher]) -> Vec<CipherOutput> {
    ciphers
        .iter()
        .map(|cipher| CipherOutput {
            id: cipher.id.to_string(),
            cipher_type: "login".to_string(),
            name: cipher.get_name().unwrap_or_default().to_string(),
            username: cipher.get_username().map(str::to_string),
            password: cipher.get_password().map(str::to_string),
            uri: cipher.get_uri().map(str::to_string),
            notes: cipher.get_notes().map(str::to_string),
            fields: cipher.get_fields().map(|fields| {
                fields
                    .iter()
                    .map(|field| FieldOutput {
                        name: field.name.clone().unwrap_or_default(),
                        value: field.value.clone().unwrap_or_default(),
                        hidden: field.r#type == FieldType::Hidden,
                    })
                    .collect()
            }),
            ssh_public_key: None,
            ssh_private_key: None,
            ssh_fingerprint: None,
        })
        .collect()
}

fn sync_json_fixture(count: usize) -> String {
    let ciphers: Vec<_> = (0..count)
        .map(|i| {
            json!({
                "id": format!("cipher-{i:04}"),
                "type": 1,
                "organizationId": format!("org-{}", i % 4),
                "name": format!("service-{i:04}"),
                "notes": format!("deterministic note {i}"),
                "folderId": format!("folder-{}", i % 8),
                "collectionIds": [format!("collection-{}", i % 6)],
                "login": {
                    "username": format!("user-{i}@example.com"),
                    "password": format!("password-{i:04}"),
                    "uris": [{"uri": format!("https://service-{i:04}.example.com/login")}]
                },
                "fields": [{"name": "api-token", "value": format!("token-{i:04}"), "type": 1}]
            })
        })
        .collect();

    json!({
        "ciphers": ciphers,
        "folders": [{"id": "folder-0", "name": "Folder 0"}],
        "collections": [{"id": "collection-0", "name": "Collection 0", "organizationId": "org-0"}],
        "profile": {
            "id": "profile-0",
            "email": "bench@example.com",
            "name": "Benchmark User",
            "organizations": [{"id": "org-0", "name": "Org 0"}]
        }
    })
    .to_string()
}

fn filter_and_search(ciphers: &[Cipher], collection_id: &str, search: &str) -> usize {
    ciphers
        .iter()
        .filter(|cipher| cipher.collection_ids.iter().any(|id| id == collection_id))
        .filter(|cipher| {
            cipher.get_name().is_some_and(|name| name.contains(search))
                || cipher
                    .get_username()
                    .is_some_and(|username| username.contains(search))
                || cipher.get_uri().is_some_and(|uri| uri.contains(search))
        })
        .count()
}

fn export_env(outputs: &[CipherOutput]) -> String {
    let mut env = String::new();
    for output in outputs {
        let prefix = output.name.to_uppercase().replace('-', "_");
        if let Some(username) = &output.username {
            writeln!(env, "{prefix}_USERNAME={username}").unwrap();
        }
        if let Some(password) = &output.password {
            writeln!(env, "{prefix}_PASSWORD={password}").unwrap();
        }
        if let Some(uri) = &output.uri {
            writeln!(env, "{prefix}_URI={uri}").unwrap();
        }
    }
    env
}

fn bench_command_parsing(c: &mut Criterion) {
    let args = command_args();
    c.bench_function("command parsing matrix", |b| {
        b.iter_batched(
            || (),
            |()| {
                for argv in &args {
                    black_box(Cli::from_args(&["vaultwarden-cli"], &argv[1..]).unwrap());
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_filtering_and_search(c: &mut Criterion) {
    for (name, count) in WORKLOADS {
        let ciphers = fixture_ciphers(count);
        c.bench_function(&format!("filter search {name}"), |b| {
            b.iter(|| black_box(filter_and_search(&ciphers, "collection-3", "service-09")));
        });
    }
}

fn bench_import_export(c: &mut Criterion) {
    for (name, count) in WORKLOADS {
        let sync_json = sync_json_fixture(count);
        let ciphers = fixture_ciphers(count);
        let outputs = fixture_outputs(&ciphers);

        c.bench_function(&format!("import sync json {name}"), |b| {
            b.iter(|| black_box(serde_json::from_str::<SyncResponse>(&sync_json).unwrap()));
        });

        c.bench_function(&format!("export output json {name}"), |b| {
            b.iter(|| black_box(serde_json::to_string(&outputs).unwrap()));
        });

        c.bench_function(&format!("export env {name}"), |b| {
            b.iter(|| black_box(export_env(&outputs)));
        });
    }
}

fn benchmark_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(50))
        .measurement_time(Duration::from_millis(200))
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_command_parsing, bench_filtering_and_search, bench_import_export
}
criterion_main!(benches);
