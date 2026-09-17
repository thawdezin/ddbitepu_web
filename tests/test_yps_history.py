import hashlib
import hmac
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

module_path = Path(__file__).parents[1] / "api" / "yps_history.py"
spec = importlib.util.spec_from_file_location("yps_history", module_path)
yps_history = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(yps_history)


class YpsHistoryTests(unittest.TestCase):
    def setUp(self):
        yps_history._seen_nonces.clear()

    def test_request_body_matches_working_txn_detail_contract(self):
        body = yps_history._build_upstream_body(
            "1118101011000178669", "1", now=1_784_549_382.185
        )

        self.assertEqual(body["joininstid"], "20000002")
        self.assertEqual(body["joininstssn"], "1784549382185")
        self.assertEqual(body["reqdate"], "20260720")
        self.assertEqual(body["reqtime"], "183942")
        self.assertEqual(body["mchntid"], "000400900000003")
        self.assertEqual(body["reqlangid"], "EN")
        self.assertEqual(
            body["data"], {"cardno": "1118101011000178669", "pageno": "1"}
        )
        self.assertRegex(body["sign"], r"^[0-9a-f]{128}$")

    @patch.object(yps_history.requests, "post")
    def test_query_returns_real_yps_history_shape(self, post: Mock):
        response = Mock()
        response.json.return_value = {
            "result": "0000",
            "data": {
                "recdnum": 10,
                "totalnum": 13,
                "pageno": 1,
                "pagenum": 2,
                "txninfo": [
                    {
                        "errcode": 0,
                        "censeq": "000633531006",
                        "errdesc": "Successful trading",
                        "afteramt": 135000,
                        "Txncode": "8451",
                        "txnterm": "00020005",
                        "txntime": "134414",
                        "cardno": "1118101011000178669",
                        "txndate": "20260325",
                        "beforeamt": 165000,
                        "txnamt": 30000,
                    }
                ],
            },
            "resultdesc": "成功",
        }
        post.return_value = response

        result = yps_history._query_yps("1118101011000178669", "1")

        self.assertEqual(result["result"], "0000")
        self.assertEqual(len(result["data"]["txninfo"]), 1)
        post.assert_called_once()

    def test_normalize_page_accepts_string_and_int(self):
        self.assertEqual(yps_history._normalize_page("1"), "1")
        self.assertEqual(yps_history._normalize_page(2), "2")
        self.assertIsNone(yps_history._normalize_page("0"))
        self.assertIsNone(yps_history._normalize_page("101"))
        self.assertIsNone(yps_history._normalize_page("abc"))
        self.assertIsNone(yps_history._normalize_page(True))

    def test_accepts_a_fresh_valid_request_signature(self):
        timestamp = "1784549382185"
        nonce = "0123456789abcdef0123456789abcdef"
        message = (
            f"{timestamp}\n{nonce}\n1118101011000178669\n1".encode("utf-8")
        )
        signature = hmac.new(
            os.environ["DDP_REQUEST_SIGNING_KEY"].encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()

        yps_history._verify_request_signature(
            "1118101011000178669",
            "1",
            timestamp,
            nonce,
            signature,
            now=1_784_549_382.185,
        )

    def test_rejects_signature_bound_to_another_page(self):
        timestamp = "1784549382185"
        nonce = "0123456789abcdef0123456789abcdef"
        message = (
            f"{timestamp}\n{nonce}\n1118101011000178669\n2".encode("utf-8")
        )
        signature = hmac.new(
            os.environ["DDP_REQUEST_SIGNING_KEY"].encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()

        with self.assertRaisesRegex(ValueError, "invalid request signature"):
            yps_history._verify_request_signature(
                "1118101011000178669",
                "1",
                timestamp,
                nonce,
                signature,
                now=1_784_549_382.185,
            )


if __name__ == "__main__":
    unittest.main()
