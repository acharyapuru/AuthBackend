import threading
from django.core.mail import EmailMultiAlternatives

class EmailThread(threading.Thread):
    def __init__(self, subject, message, from_email, recipient_list):
        self.subject = subject
        self.message = message
        self.from_email = from_email
        self.recipient_list = recipient_list
        threading.Thread.__init__(self)

    def run(self):
        try:
            email = EmailMultiAlternatives(
                self.subject, self.message, self.from_email, self.recipient_list
            )
            email.send()
        except Exception as e:
            print(f"Failed to send email: {e}")
