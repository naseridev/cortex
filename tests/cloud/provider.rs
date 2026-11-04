use cortex::cloud::provider::ProviderSettings;

#[test]
fn nextcloud_endpoint_normalizes_standard_and_full_dav_urls() {
    assert_eq!(
        ProviderSettings::nextcloud_dav_endpoint("https://cloud.example.com", "alice"),
        "https://cloud.example.com/remote.php/dav/files/alice"
    );
    assert_eq!(
        ProviderSettings::nextcloud_dav_endpoint("https://cloud.example.com/nextcloud/", "bob"),
        "https://cloud.example.com/nextcloud/remote.php/dav/files/bob"
    );
    assert_eq!(
        ProviderSettings::nextcloud_dav_endpoint(
            "https://cloud.example.com/remote.php/dav/files/alice/",
            "alice"
        ),
        "https://cloud.example.com/remote.php/dav/files/alice"
    );
}

#[test]
fn normalize_root_always_prefixes_with_slash() {
    assert_eq!(ProviderSettings::normalize_root(None, "/cortex"), "/cortex");
    assert_eq!(
        ProviderSettings::normalize_root(Some("  "), "/cortex"),
        "/cortex"
    );
    assert_eq!(
        ProviderSettings::normalize_root(Some("vaults"), "/cortex"),
        "/vaults"
    );
    assert_eq!(
        ProviderSettings::normalize_root(Some("/custom/path"), "/cortex"),
        "/custom/path"
    );
}

#[test]
fn provider_summaries_and_kinds_match_specifications() {
    let nextcloud = ProviderSettings::Nextcloud {
        url: "https://nc.example.com".to_string(),
        username: "nima".to_string(),
        root: "/cortex".to_string(),
    };
    assert_eq!(nextcloud.kind(), "nextcloud");
    assert_eq!(
        nextcloud.summary(),
        "nextcloud https://nc.example.com/cortex (user: nima)"
    );

    let s3 = ProviderSettings::S3 {
        bucket: "my-vault".to_string(),
        region: "eu-central-1".to_string(),
        endpoint: None,
        prefix: "/cortex".to_string(),
    };
    assert_eq!(s3.kind(), "s3");
    assert_eq!(s3.summary(), "s3://my-vault/cortex (region: eu-central-1)");
}
