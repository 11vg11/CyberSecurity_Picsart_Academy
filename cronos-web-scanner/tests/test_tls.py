from unittest.mock import MagicMock, patch

import ssl

from checks import ssl_check


def test_protocol_probe_restricts_handshake_to_requested_tls_version():
    context = MagicMock()
    connection = MagicMock()
    connection.__enter__.return_value = MagicMock()

    with (
        patch("checks.ssl_check.ssl.SSLContext", return_value=context),
        patch("checks.ssl_check.socket.create_connection", return_value=connection),
    ):
        assert ssl_check._supports_protocol(
            "authorized.example", 443, ssl.TLSVersion.TLSv1_1
        )

    assert context.minimum_version == ssl.TLSVersion.TLSv1_1
    assert context.maximum_version == ssl.TLSVersion.TLSv1_1
    context.wrap_socket.assert_called_once()


def test_protocol_probe_treats_rejected_legacy_handshake_as_not_supported():
    with patch(
        "checks.ssl_check.socket.create_connection",
        side_effect=OSError("connection refused"),
    ):
        assert not ssl_check._supports_protocol(
            "authorized.example", 443, ssl.TLSVersion.TLSv1
        )
