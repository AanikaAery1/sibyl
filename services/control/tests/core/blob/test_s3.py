"""S3-API BlobStore: shared contract on a signature-checking fake, SigV4 vectors, retries.

``SIBYL_TEST_S3_ENDPOINT`` (e.g. a local ``moto_server`` or MinIO) runs the contract against a
real S3 implementation too; it is never a cloud account.
"""

from __future__ import annotations

import os
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

import httpx
import pytest
from sibyl_control.core.blob.base import BlobError, BlobExists
from sibyl_control.core.blob.s3 import (
    EMPTY_SHA256,
    S3BlobStore,
    S3Config,
    presign_get_url,
    sigv4_authorization,
)

from .blob_contract import BlobStoreContract, key_for
from .fake_s3 import FakeS3

# The worked examples in the AWS SigV4 documentation for Amazon S3 (examplebucket, 2013-05-24).
AWS_EXAMPLE = S3Config(
    endpoint_url="https://examplebucket.s3.amazonaws.com",
    bucket="examplebucket",
    region="us-east-1",
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # noqa: S106  (AWS doc example)
    path_style=False,
)

LOCAL = S3Config(
    endpoint_url="http://127.0.0.1:9000",
    bucket="sibyl-blob",
    region="eu-west-1",
    access_key_id="AKIDLOCALTEST",
    secret_access_key="local-test-secret",  # noqa: S106
    key_prefix="dev/",
)


def test_sigv4_authorization_matches_the_aws_get_object_example() -> None:
    auth = sigv4_authorization(
        "GET",
        "https://examplebucket.s3.amazonaws.com/test.txt",
        {
            "range": "bytes=0-9",
            "x-amz-content-sha256": EMPTY_SHA256,
            "x-amz-date": "20130524T000000Z",
        },
        EMPTY_SHA256,
        config=AWS_EXAMPLE,
        amz_date="20130524T000000Z",
    )
    assert auth == (
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


def test_presigned_get_matches_the_aws_query_string_example() -> None:
    url = presign_get_url(
        "https://examplebucket.s3.amazonaws.com/test.txt",
        config=AWS_EXAMPLE,
        amz_date="20130524T000000Z",
        expires_s=86400,
    )
    query = dict(parse_qsl(urlsplit(url).query))
    assert query["X-Amz-Signature"] == (
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    )
    assert query["X-Amz-SignedHeaders"] == "host"


@pytest.fixture
def fake() -> FakeS3:
    return FakeS3(LOCAL)


@pytest.fixture
async def store(fake: FakeS3):
    client = httpx.AsyncClient(transport=fake.transport())
    yield S3BlobStore(LOCAL, client=client, retry_backoff_s=0)
    await client.aclose()


class TestS3Contract(BlobStoreContract):
    pass


async def test_objects_live_under_the_configured_prefix(fake: FakeS3, store: S3BlobStore) -> None:
    key = key_for()
    await store.put(key, b"x", content_type="application/octet-stream")
    assert list(fake.objects) == [f"dev/{key}"]
    assert await store.list_prefix("tenant/") == [key]


async def test_list_follows_continuation_tokens(fake: FakeS3, store: S3BlobStore) -> None:
    fake.page_size = 2
    keys = sorted(key_for() for _ in range(5))
    for key in keys:
        await store.put(key, b"x", content_type="application/octet-stream")
    assert await store.list_prefix("tenant/") == keys
    assert await store.list_prefix("tenant/", limit=3) == keys[:3]


async def test_transient_5xx_is_retried(fake: FakeS3, store: S3BlobStore) -> None:
    key = key_for()
    await store.put(key, b"x", content_type="application/octet-stream")
    fake.faults["GET"] = [503]
    assert await store.get(key) == b"x"


async def test_persistent_errors_surface_without_credentials(
    fake: FakeS3, store: S3BlobStore
) -> None:
    fake.faults["GET"] = [500, 500, 500]
    with pytest.raises(BlobError) as caught:
        await store.get(key_for())
    assert LOCAL.secret_access_key not in str(caught.value)
    assert "500" in str(caught.value)


async def test_bad_signature_is_an_error_not_a_miss(fake: FakeS3) -> None:
    wrong = S3Config(**{**LOCAL.__dict__, "secret_access_key": "nope"})
    async with httpx.AsyncClient(transport=fake.transport()) as client:
        store = S3BlobStore(wrong, client=client, retry_backoff_s=0)
        with pytest.raises(BlobError, match="403"):
            await store.get(key_for())


async def test_put_retry_after_lost_response_is_idempotent(fake: FakeS3) -> None:
    """The first PUT lands but its response is lost; the retry sees 412 for our own bytes."""
    attempts = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        response = fake.handle(request)
        if request.method == "PUT" and attempts["n"] == 0:
            attempts["n"] += 1
            raise httpx.ReadTimeout("lost", request=request)
        return response

    async with httpx.AsyncClient(transport=httpx.MockTransport(flaky)) as client:
        store = S3BlobStore(LOCAL, client=client, retry_backoff_s=0)
        key = key_for()
        info = await store.put(key, b"body", content_type="application/octet-stream")
        assert info.size == 4
        with pytest.raises(BlobExists):
            await store.put(key, b"other", content_type="application/octet-stream")


async def test_presigned_get_is_offered(store: S3BlobStore) -> None:
    url = await store.presigned_get(key_for(), expires_s=300)
    assert url is not None
    query = dict(parse_qsl(urlsplit(url).query))
    assert query["X-Amz-Expires"] == "300"
    assert LOCAL.secret_access_key not in url
    with pytest.raises(ValueError):
        await store.presigned_get(key_for(), expires_s=8 * 24 * 3600)


def test_plain_http_is_refused_off_loopback() -> None:
    with pytest.raises(ValueError, match="https"):
        S3Config(**{**LOCAL.__dict__, "endpoint_url": "http://s3.internal.example"})
    S3Config(**{**LOCAL.__dict__, "endpoint_url": "http://s3.internal.example", "allow_http": True})


def test_config_repr_hides_secrets() -> None:
    cfg = S3Config(**{**LOCAL.__dict__, "session_token": "tok-123"})
    assert "local-test-secret" not in repr(cfg)
    assert "tok-123" not in repr(cfg)


def test_config_from_env() -> None:
    env = {
        "SIBYL_S3_ENDPOINT": "https://s3.eu-west-1.amazonaws.com",
        "SIBYL_S3_BUCKET": "b",
        "SIBYL_S3_REGION": "eu-west-1",
        "SIBYL_S3_ACCESS_KEY_ID": "AKID",
        "SIBYL_S3_SECRET_ACCESS_KEY": "s",
        "SIBYL_S3_PREFIX": "p/",
        "SIBYL_S3_PATH_STYLE": "false",
    }
    cfg = S3Config.from_env(env)
    assert (cfg.bucket, cfg.region, cfg.key_prefix, cfg.path_style) == (
        "b",
        "eu-west-1",
        "p/",
        False,
    )
    with pytest.raises(ValueError, match="SIBYL_S3_BUCKET"):
        S3Config.from_env({k: v for k, v in env.items() if k != "SIBYL_S3_BUCKET"})


def test_virtual_host_addressing() -> None:
    store = S3BlobStore(AWS_EXAMPLE)
    assert store.object_url("a/b.bin") == "https://examplebucket.s3.amazonaws.com/a/b.bin"
    path_store = S3BlobStore(LOCAL)
    assert path_store.object_url("a/b.bin") == "http://127.0.0.1:9000/sibyl-blob/dev/a/b.bin"


_LIVE = os.environ.get("SIBYL_TEST_S3_ENDPOINT")


if _LIVE:  # collected only against a local moto/MinIO server, never a cloud account

    class TestLiveS3Contract(BlobStoreContract):
        @pytest.fixture
        async def store(self):
            cfg = S3Config(
                endpoint_url=_LIVE or "",
                bucket=os.environ.get("SIBYL_TEST_S3_BUCKET", "sibyl-test"),
                region="us-east-1",
                access_key_id=os.environ.get("SIBYL_TEST_S3_ACCESS_KEY_ID", "testing"),
                secret_access_key=os.environ.get("SIBYL_TEST_S3_SECRET_ACCESS_KEY", "testing"),
                key_prefix=f"run-{uuid4().hex[:8]}/",
            )
            async with httpx.AsyncClient() as client:
                yield S3BlobStore(cfg, client=client)
