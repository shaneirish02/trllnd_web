from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
import os

User = get_user_model()

class Command(BaseCommand):
    help = "Creates a superuser automatically using environment variables on Render."

    def handle(self, *args, **options):
        username = os.getenv("ADMIN_USERNAME")
        password = os.getenv("ADMIN_PASSWORD")

        # Safety checks
        if not username or not password:
            self.stdout.write(self.style.WARNING(
                "ADMIN_USERNAME or ADMIN_PASSWORD is missing. Skipping admin creation."
            ))
            return

        # Create admin if it does not exist
        if not User.objects.filter(username=username).exists():
            User.objects.create_superuser(
                username=username,
                email="",
                password=password
            )
            self.stdout.write(self.style.SUCCESS(f"Admin user '{username}' created!"))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"Admin '{username}' already exists. No action taken."
            ))
