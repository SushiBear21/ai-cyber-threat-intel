import time
import urllib.error
import urllib.request


RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def download_json_bytes(url, max_bytes):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ai-cyber-threat-intel-portfolio/0.1",
            "Accept": "application/json",
        },
    )

    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as result:
                if result.status != 200:
                    raise ValueError("Source did not return HTTP 200.")

                final_url = result.geturl()
                raw = result.read(max_bytes + 1)

            if len(raw) > max_bytes:
                raise ValueError("Response exceeds download size limit.")

            return raw, final_url

        except urllib.error.HTTPError as error:
            retryable = error.code in RETRYABLE_STATUS_CODES
            retry_after = error.headers.get("Retry-After", "")
            error.close()

            if not retryable or attempt == 2:
                raise

            delay = 2 ** attempt

            if retry_after:
                try:
                    requested_delay = int(retry_after)
                except ValueError:
                    # HTTP-date Retry-After handling is not implemented.
                    raise RuntimeError(
                        "Retry-After requires a later manual retry."
                    ) from None

                if requested_delay < 0 or requested_delay > 30:
                    raise RuntimeError(
                        "Retry-After is outside the automatic retry window."
                    ) from None

                delay = max(delay, requested_delay)

        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
            delay = 2 ** attempt

        time.sleep(delay)

    raise RuntimeError("Download attempts exhausted.")