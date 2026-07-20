import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


os.environ.setdefault(
    "YPS_PRIVATE_KEY",
    "6BDBFA438D73128E311ACA4666CC9F9BA08A92E55FC435CFA74F58656A9B91E9",
)
os.environ.setdefault(
    "DDP_REQUEST_SIGNING_KEY",
    "test-request-signing-key-not-for-production",
)

module_path = Path(__file__).parents[1] / "api" / "yps_balance.py"
spec = importlib.util.spec_from_file_location("yps_balance", module_path)
yps_balance = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(yps_balance)


class YpsBalanceTests(unittest.TestCase):
    def setUp(self):
        yps_balance._seen_nonces.clear()

    def test_request_body_matches_working_python_contract(self):
        body = yps_balance._build_upstream_body(
            "1118101011000178669", now=1_784_549_382.185
        )

        self.assertEqual(body["joininstid"], "20000002")
        self.assertEqual(body["joininstssn"], "1784549382185")
        self.assertEqual(body["reqdate"], "20260720")
        self.assertEqual(body["reqtime"], "183942")
        self.assertEqual(body["mchntid"], "000400900000003")
        self.assertEqual(body["reqlangid"], "EN")
        self.assertEqual(body["data"], {"cardno": "1118101011000178669"})
        self.assertRegex(body["sign"], r"^[0-9a-f]{128}$")

    @patch.object(yps_balance.requests, "post")
    def test_query_returns_real_yps_success_shape(self, post: Mock):
        response = Mock()
        response.json.return_value = {
            "result": "0000",
            "data": {
                "crdbalance": "143000",
                "cardno": "1118101011000178669",
                "status": "3",
            },
            "resultdesc": "成功",
        }
        post.return_value = response

        result = yps_balance._query_yps("1118101011000178669")

        self.assertEqual(result["result"], "0000")
        self.assertEqual(result["data"]["crdbalance"], "143000")
        post.assert_called_once()

    def test_accepts_a_fresh_valid_request_signature(self):
        timestamp = "1784549382185"
        nonce = "0123456789abcdef0123456789abcdef"
        message = (
            f"{timestamp}\n{nonce}\n1118101011000178669".encode("utf-8")
        )
        import hashlib
        import hmac

        signature = hmac.new(
            os.environ["DDP_REQUEST_SIGNING_KEY"].encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()

        yps_balance._verify_request_signature(
            "1118101011000178669",
            timestamp,
            nonce,
            signature,
            now=1_784_549_382.185,
        )

    def test_rejects_replayed_request_signature(self):
        timestamp = "1784549382185"
        nonce = "0123456789abcdef0123456789abcdef"
        message = (
            f"{timestamp}\n{nonce}\n1118101011000178669".encode("utf-8")
        )
        import hashlib
        import hmac

        signature = hmac.new(
            os.environ["DDP_REQUEST_SIGNING_KEY"].encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()
        arguments = (
            "1118101011000178669",
            timestamp,
            nonce,
            signature,
        )

        yps_balance._verify_request_signature(
            *arguments, now=1_784_549_382.185
        )
        with self.assertRaisesRegex(ValueError, "replayed"):
            yps_balance._verify_request_signature(
                *arguments, now=1_784_549_382.185
            )


if __name__ == "__main__":
    unittest.main()
