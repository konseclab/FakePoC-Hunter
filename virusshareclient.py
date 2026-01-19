import requests
from typing import Dict, Any


class VirusShareAPIError(Exception):
    """VirusShare API 用例外"""
    pass


class VirusShareClient:
    BASE_URL = "https://virusshare.com/apiv2"

    def __init__(self, api_key: str, timeout: int = 10):
        if not api_key:
            raise ValueError("api_key must not be empty")

        self.api_key = api_key
        self.timeout = timeout

    def _get(self, endpoint: str, params: Dict[str, str]) -> Dict[str, Any]:
        url = f"{self.BASE_URL}/{endpoint}"

        params["apikey"] = self.api_key

        try:
            response = requests.get(url, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise requests.RequestException(
                f"Failed to connect to VirusShare API: {e}"
            )

        if response.status_code == 204:
            raise VirusShareAPIError(
                "Rate limit exceeded (HTTP 204). Slow down your requests."
            )

        if response.status_code != 200:
            raise VirusShareAPIError(
                f"VirusShare API returned HTTP {response.status_code}"
            )

        try:
            data = response.json()
        except ValueError:
            raise VirusShareAPIError(
                f"Invalid JSON response: {response.text}"
            )

        return data

    def get_file_report(self, hash_value: str) -> Dict[str, Any]:
        """
        /file
        ファイルの詳細レポートを取得
        """
        data = self._get(
            endpoint="file",
            params={"hash": hash_value}
        )

        if data.get("response") == 0:
            raise VirusShareAPIError("File not found in VirusShare database")

        return data

    def quick_check(self, hash_value: str) -> int:
        """
        /quick
        0: unknown, 1: malware, 2: benign
        """
        data = self._get(
            endpoint="quick",
            params={"hash": hash_value}
        )

        if "response" not in data:
            raise VirusShareAPIError("Malformed quick response")

        return data["response"]

    def get_source_info(self, sha256: str) -> Dict[str, Any]:
        """
        /source
        配布元URL情報を取得（sha256のみ）
        """
        data = self._get(
            endpoint="source",
            params={"hash": sha256}
        )

        if data.get("response") == 0:
            raise VirusShareAPIError("Source information not found")

        return data

    def pretty_print_report(self, r: dict):
        print("=== File Summary ===")
        print(f"SHA256   : {r.get('sha256')}")
        print(f"MD5      : {r.get('md5')}")
        print(f"Type     : {r.get('filetype')}")
        print(f"Extension: {r.get('extension')}")
        print(f"Size     : {r.get('size'):,} bytes")
        print(f"MIME     : {r.get('mimetype')}")
        print(f"Added    : {r.get('added_timestamp')}")

        vt = r.get("virustotal", {})
        print("\n=== VirusTotal ===")
        print(f"Detected : {vt.get('positives')} / {vt.get('total')}")
        print(f"ScanDate : {vt.get('scan_date')}")

if __name__ == "__main__":
    client = VirusShareClient(api_key="ByT9r6mak3O4lzNLSyWrUe0OPK9ALC9L")

    report = client.get_file_report(
        "036eef46db1f85a5c499d363e0f4d3b40051c9ef81ccd3f2173008c0c5dea4f4"
    )

    client.pretty_print_report(report)
