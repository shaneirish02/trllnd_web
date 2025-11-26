from django.utils import timezone
from firebase_admin import messaging
from core.models import Notification, DeviceToken
from core.firebase import initialize_firebase

# Initialize Firebase Admin
initialize_firebase()

def run_scheduled_notifications():
    now = timezone.now()

    # Find notifications that should be sent
    due_notifications = Notification.objects.filter(
        is_sent=False,
        scheduled_at__lte=now
    ).select_related("user")

    sent_count = 0

    for notif in due_notifications:
        token_entry = DeviceToken.objects.filter(user=notif.user).last()
        if not token_entry:
            continue

        try:
            # Build FCM message
            message = messaging.Message(
                notification=messaging.Notification(
                    title=notif.title,
                    body=notif.message
                ),
                token=token_entry.token
            )

            messaging.send(message)

            # Mark as sent
            notif.is_sent = True
            notif.save()

            sent_count += 1

        except Exception as e:
            print(f"Failed to send notification: {e}")

    return sent_count
