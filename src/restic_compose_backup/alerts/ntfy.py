import logging
import os

import requests
from requests.auth import HTTPBasicAuth
from restic_compose_backup.alerts.base import BaseAlert

logger = logging.getLogger(__name__)


class NtfyWebhookAlert(BaseAlert):
    name = "ntfy_webhook"

    def __init__(self, ntfy_webhook_url):
        # The URL is now in the format 'http://host/topic' or 'https://host/topic'
        self.ntfy_webhook_url = ntfy_webhook_url
        self.host, self.topic = self.parse_ntfy_url(ntfy_webhook_url)

        # If credentials are required, they are parsed here
        self.auth = None
        if "@" in self.host:  # Check if credentials are included in the URL
            self.auth, self.host = self.extract_auth(self.host)

        # Construct the full URL to send notifications
        self.ntfy_url = f"{self.ntfy_webhook_url}"

    @classmethod
    def create_from_env(cls):
        # Fetch the ntfy webhook URL from the environment variable
        ntfy_webhook_url = os.environ.get("NTFY_WEBHOOK")

        if ntfy_webhook_url and cls.properly_configured(ntfy_webhook_url):
            return cls(ntfy_webhook_url)

        return None

    @staticmethod
    def properly_configured(ntfy_webhook_url: str) -> bool:
        # Ensure the URL starts with 'http://' or 'https://'
        return ntfy_webhook_url.startswith("http://") or ntfy_webhook_url.startswith(
            "https://"
        )

    def parse_ntfy_url(self, url):
        """Parses the 'http://host/topic' or 'https://host/topic' URL"""
        parsed_url = url.split("/", 1)
        host = parsed_url[0]
        topic = parsed_url[1] if len(parsed_url) > 1 else ""
        return host, topic

    def extract_auth(self, host_with_auth):
        """Extracts credentials from the URL if included in the format 'user:password@host'"""
        auth_part, host = host_with_auth.split("@", 1)
        user, password = auth_part.split(":", 1)
        return HTTPBasicAuth(user, password), host

    def send(self, subject: str = None, body: str = None, alert_type: str = None):
        """Send notification using the standard HTTP(S) API."""
        logger.info("Triggering ntfy notification")

        # Prepare the message and title
        message = body if body else ""
        title = f"[{alert_type}] {subject}" if subject else "Alert"

        # Prepare headers
        headers = {
            "Title": title,
            "Priority": "urgent",  # You can adjust this as needed
            "Tags": "warning,skull",  # You can customize this as needed
        }

        # Send the POST request to ntfy.sh (or custom FQDN)
        try:
            response = requests.post(
                self.ntfy_url, data=message, headers=headers, auth=self.auth
            )

            if response.status_code == 200:
                logger.info("Ntfy notification sent successfully")
            else:
                logger.error("Failed to send ntfy notification: %s", response.text)
        except Exception as e:
            logger.error(
                "Exception occurred while sending ntfy notification: %s", str(e)
            )
