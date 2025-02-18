import datetime
import requests
import os

from time import sleep
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

directory = os.path.join(BASE_DIR, "samples")

class VirusShare:
    def __init__(self, api_key=None, requests_per_minute=4):
        """Initialize class

        :param requests_per_minute: Integer representing the number of requests per minute allowed by your API
        """
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSSHARE_API_KEY")
        self.uri = "https://virusshare.com/apiv2"
        self.requests_per_minute = requests_per_minute
        self.rate_limit_buffer = 0.01

        self._last_request = None
        self._rate_limit = float(60.0 / requests_per_minute) + self.rate_limit_buffer

    def _sleep(self):
        """Provide rate limiting based on API requests per minute.

        This executes immediately before each request to the API

        :return: None
        """
        if self._last_request is None:
            self._last_request = datetime.datetime.now()
            return

        elapsed_time = (datetime.datetime.now() - self._last_request).total_seconds()
        # If less than the rate limit has passed, sleep for the remainder
        if elapsed_time < self._rate_limit:
            sleep(self._rate_limit - elapsed_time)

    def _request(self, endpoint, hash_value):
        """Execute the API request and return the result.

        Incorporates the rate limiter.
`
        :param endpoint (str): A valid API endpoint. One of file, quick, download, source

        :return: Response from GET request.
        """
        if not self.api_key:
            raise ValueError("Required API key not provided")
        self._sleep()
        resp = requests.get(
            "{}/{}".format(self.uri, endpoint),
            params={"apikey": self.api_key, "hash": hash_value},
        )
        # If successful, return the results
        if resp.status_code == 200:
            return resp
        # If rate limited, sleep then try again
        if resp.status_code == 204:
            self._sleep()
            return self._request(endpoint, hash_value)

        # Otherwise raise the HTTP error
        resp.raise_for_status()

    @staticmethod
    def _add_metadata(response_data):
        response_data["_exists"] = (
            True if response_data.get("response", 0) in (1, 2) else False
        )
        response_data["_detected"] = (
            True if response_data.get("response", 0) == 1 else False
        )
        return response_data

    def file_exists(self, hash_value):
        response = self._request("quick", hash_value)
        resp_data = response.json()
        resp_data = self._add_metadata(resp_data)
        return resp_data

    def file_report(self, hash_value):
        response = self._request("file", hash_value)
        resp_data = response.json()
        resp_data = self._add_metadata(resp_data)
        return resp_data

    def file_source(self, hash_value, convert_timestamps=False):
        if len(hash_value) != 64:
            raise ValueError("Please provide a SHA256 value")
        response = self._request("source", hash_value)
        resp_data = response.json()
        if (
            convert_timestamps
            and isinstance(resp_data.get("urllist"), list)
            and len(resp_data.get("urllist")) > 0
        ):
            new_url_list = []
            for entry in resp_data.get("urllist", []):
                new_url_list.append(
                    {
                        "url": entry.get("url"),
                        "timestamp": entry.get("timestamp"),
                        "datetime": datetime.datetime.utcfromtimestamp(
                            entry.get("timestamp")
                        ),
                    }
                )
            resp_data["urllist"] = new_url_list
        return resp_data

    def file_download(self, hash_value, save_directory, filename=None):
        try:
            download = self._request("download", hash_value)
            if not os.path.exists(save_directory):
                os.makedirs(save_directory)

            file_name = filename if filename else hash_value
            temp_path = os.path.join(save_directory, file_name + ".gz")

            with open(temp_path, "wb") as file:
                for chunk in download.iter_content(chunk_size=8192):
                    file.write(chunk)
            return True

        except requests.RequestException as e:
            print(f"Error downloading file: {e}")
            return False