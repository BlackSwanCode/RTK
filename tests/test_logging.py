import logging
import io
from rtk.core.logging.logger import SecureJSONFormatter, _mask_secrets


def test_mask_secrets():
    text = "My key is AKIAIOSFODNN7EXAMPLE and token: abcdefghijklmnop1234"
    masked = _mask_secrets(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "HASH:" in masked
    assert "abcdefghijklmnop1234" not in masked


def test_json_formatter_masks_secrets():
    formatter = SecureJSONFormatter()
    record = logging.LogRecord(
        name="rtk.test", level=logging.INFO, pathname="", lineno=0,
        msg="Connecting with AKIAIOSFODNN7EXAMPLE", args=(), exc_info=None
    )
    record.__dict__["correlation_id"] = "corr-123"

    output = formatter.format(record)
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    assert "HASH:" in output
