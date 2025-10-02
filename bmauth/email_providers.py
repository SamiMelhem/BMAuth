"""
Email provider implementations for BMAuth
"""
from abc import ABC, abstractmethod


class EmailProvider(ABC):
    """Base email provider interface"""

    def __init__(self, from_email: str):
        self.from_email = from_email

    @abstractmethod
    async def send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """Send email and return success status"""
        pass


class SendGridProvider(EmailProvider):
    """SendGrid email provider (API-based)"""

    def __init__(self, api_key: str, from_email: str):
        super().__init__(from_email)
        self.api_key = api_key
        self.api_url = "https://api.sendgrid.com/v3/mail/send"

    async def send_email(self, to_email: str, subject: str, html_content: str) -> bool:
        """Send email via SendGrid API"""
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "personalizations": [{"to": [{"email": to_email}]}],
                        "from": {"email": self.from_email},
                        "subject": subject,
                        "content": [{"type": "text/html", "value": html_content}],
                    },
                    timeout=10.0,
                )
                
                return response.status_code == 202
        except Exception as e:
            print(f"SendGrid email failed: {e}")
            return False
