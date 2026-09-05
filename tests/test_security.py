from xray_e2e_prober.security import redact_text, redact_url, safe_display_name


def test_redacts_subscription_secrets() -> None:
    raw = (
        "failed vless://550e8400-e29b-41d4-a716-446655440000@example.test:443?"
        "security=reality&pbk=secret#name Authorization: Bearer-abc"
    )
    output = redact_text(raw)
    assert "550e8400" not in output
    assert "pbk=secret" not in output
    assert "Bearer-abc" not in output


def test_redacts_complete_authorization_values_and_any_uuid_variant() -> None:
    raw = (
        "Authorization: Bearer TOP_SECRET with-spaces\n"
        "Proxy-Authorization=Basic dXNlcjpwYXNz\n"
        "retry with Bearer STANDALONE and Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n"
        "candidate 11111111-2222-7333-c444-555555555555"
    )
    output = redact_text(raw)
    for secret in (
        "TOP_SECRET",
        "with-spaces",
        "dXNlcjpwYXNz",
        "STANDALONE",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "11111111-2222-7333-c444-555555555555",
    ):
        assert secret not in output


def test_redacts_xray_key_and_short_id_field_forms() -> None:
    raw = (
        "publicKey=REALITY_PUBLIC privateKey: 'REALITY_PRIVATE' "
        'shortId: deadbeef pbk=QUERY_KEY sid="SHORT_ID" '
        'key=["PEM_SECRET", "PEM_SECRET_2"] uuid=opaque-credential'
    )
    output = redact_text(raw)
    for secret in (
        "REALITY_PUBLIC",
        "REALITY_PRIVATE",
        "deadbeef",
        "QUERY_KEY",
        "SHORT_ID",
        "PEM_SECRET",
        "PEM_SECRET_2",
        "opaque-credential",
    ):
        assert secret not in output


def test_redact_url_drops_userinfo_and_query() -> None:
    assert redact_url("https://user:pass@example.test/feed?token=abc") == (
        "https://example.test"
    )
    assert redact_url("https://[2001:db8::1]:8443/private/path#fragment") == (
        "https://[2001:db8::1]:8443"
    )


def test_safe_display_name_removes_controls() -> None:
    assert safe_display_name("good\n\x1b[31mbad") == "good [31mbad"


def test_oversized_diagnostic_fails_closed_before_redaction_work() -> None:
    assert redact_text("x" * 20_000) == "[diagnostic redacted]"
