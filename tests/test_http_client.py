import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from app.http_client import download_json_bytes


URL = "https://example.invalid/test"


def successful_response(body=b'{"status":"OK"}'):
    response = MagicMock()
    response.status = 200
    response.geturl.return_value = URL
    response.read.return_value = body
    response.__enter__.return_value = response
    return response


def http_error(code, headers=None):
    return urllib.error.HTTPError(
        URL,
        code,
        "Synthetic test error",
        headers or {},
        None,
    )


class HttpClientTests(unittest.TestCase):
    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_temporary_server_error_is_retried(self, open_url, sleep):
        open_url.side_effect = [
            http_error(503),
            successful_response(),
        ]

        raw, final_url = download_json_bytes(URL, 1024)

        self.assertEqual(raw, b'{"status":"OK"}')
        self.assertEqual(final_url, URL)
        self.assertEqual(open_url.call_count, 2)
        sleep.assert_called_once_with(1)

    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_permanent_error_is_not_retried(self, open_url, sleep):
        open_url.side_effect = http_error(404)

        with self.assertRaises(urllib.error.HTTPError):
            download_json_bytes(URL, 1024)

        self.assertEqual(open_url.call_count, 1)
        sleep.assert_not_called()

    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_network_failure_stops_after_three_attempts(
        self, open_url, sleep
    ):
        open_url.side_effect = urllib.error.URLError(
            "Synthetic network failure"
        )

        with self.assertRaises(urllib.error.URLError):
            download_json_bytes(URL, 1024)

        self.assertEqual(open_url.call_count, 3)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [1, 2],
        )

    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_numeric_retry_after_is_respected(self, open_url, sleep):
        open_url.side_effect = [
            http_error(429, {"Retry-After": "5"}),
            successful_response(),
        ]

        download_json_bytes(URL, 1024)

        sleep.assert_called_once_with(5)

    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_long_retry_after_stops_automatic_retry(
        self, open_url, sleep
    ):
        open_url.side_effect = http_error(
            429, {"Retry-After": "120"}
        )

        with self.assertRaisesRegex(RuntimeError, "retry window"):
            download_json_bytes(URL, 1024)

        self.assertEqual(open_url.call_count, 1)
        sleep.assert_not_called()

    @patch("app.http_client.time.sleep")
    @patch("app.http_client.urllib.request.urlopen")
    def test_oversized_response_is_rejected(self, open_url, sleep):
        response = successful_response(b"12345")
        open_url.return_value = response

        with self.assertRaisesRegex(ValueError, "size limit"):
            download_json_bytes(URL, 4)

        response.read.assert_called_once_with(5)
        self.assertEqual(open_url.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()