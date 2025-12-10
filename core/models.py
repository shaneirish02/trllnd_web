from django.db import models
from django.contrib.auth.models import User
from django.db.models import Max
from django.db import transaction

def generate_global_transaction_id():
    last_res = Reservation.objects.aggregate(m=Max("transaction_id"))["m"]
    last_ab = AdminBorrow.objects.aggregate(m=Max("transaction_id"))["m"]

    candidates = []

    if last_res and last_res.startswith("T"):
        try:
            candidates.append(int(last_res[1:]))
        except:
            pass

    if last_ab and last_ab.startswith("T"):
        try:
            candidates.append(int(last_ab[1:]))
        except:
            pass

    last_num = max(candidates) if candidates else 0
    return f"T{last_num + 1:06d}"


class UserBorrower(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=20)
    address = models.TextField()
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True) 
    behavior_score = models.IntegerField(default=0)
    late_count = models.IntegerField(default=0)
    borrower_status = models.CharField(max_length=10, default='Good')

    def __str__(self):
        return self.user.username

    behavior_total_score = models.IntegerField(default=0)
    violation_count = models.IntegerField(default=0)
    
    
class Item(models.Model):
    item_id = models.AutoField(primary_key=True, db_column='item_id')
    name = models.CharField(max_length=100)
    qty = models.PositiveIntegerField()
    category = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='items/', blank=True, null=True)
    owner = models.CharField(max_length=100, default="Barangay Kauswagan")
    
    status = models.CharField(
        max_length=20,
        choices=[('Available', 'Available'), ('Not Available', 'Not Available')],
        default='Available'
    )

    class Meta:
        db_table = 'core_item'

    def __str__(self):
        return self.name
    
class Reservation(models.Model):

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('in use', 'In Use'),
        ('returned', 'Returned'),
        ('declined', 'Declined'),
        ('cancelled', 'Cancelled'),
    ]

    transaction_id = models.CharField(max_length=20, default="T000000")
    userborrower = models.ForeignKey(UserBorrower, on_delete=models.CASCADE, null=True)
    letter_text = models.TextField(blank=True, null=True)
    signature_image = models.ImageField(upload_to='signatures/', blank=True, null=True)
    id_card_image = models.ImageField(upload_to='id_cards/', blank=True, null=True)

    # USER REQUESTED DATE RANGE
    date_borrowed = models.DateField()
    date_return = models.DateField()

    # SYSTEM TRACKED DATES (for scoring)
    borrow_date = models.DateField(null=True, blank=True)               
    actual_claimed_date = models.DateField(null=True, blank=True)       
    expected_return_date = models.DateField(null=True, blank=True)      
    actual_return_date = models.DateField(null=True, blank=True)        

    # COMPUTED PRIORITY SCORE
    priority_score = models.FloatField(default=0)

    PRIORITY_CHOICES = [
        ('High', 'High'),
        ('Low', 'Low'),
    ]
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='Low')
    priority_detail = models.CharField(max_length=255, blank=True, null=True)

    letter_image = models.ImageField(upload_to='reservation_letters/', blank=True, null=True)
    valid_id_image = models.ImageField(upload_to='reservation_ids/', blank=True, null=True)

    message = models.TextField(blank=True, null=True)
    contact = models.CharField(max_length=30, default="N/A", blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    report_type = models.CharField(
        max_length=20,
        choices=[("None", "None"), ("Damage", "Damage"), ("Loss", "Loss")],
        default="None"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    date_receive = models.DateTimeField(null=True, blank=True)
    date_returned = models.DateTimeField(null=True, blank=True)

    delivered_by = models.CharField(max_length=255, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.transaction_id or self.transaction_id == "T000000":
            from .models import TransactionCounter
            self.transaction_id = TransactionCounter.next_id()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Reservation {self.transaction_id} ({self.date_borrowed} → {self.date_return})"


class ReservationItem(models.Model):
    reservation = models.ForeignKey(Reservation, on_delete=models.CASCADE, related_name="items")
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    item_name = models.CharField(max_length=255, default="")
    quantity = models.PositiveIntegerField(default=1)

    def __str__(self):
        return f"{self.item_name} x{self.quantity}"


class Notification(models.Model):
    user = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    reservation = models.ForeignKey(Reservation, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=100)
    message = models.TextField()
    reason = models.TextField(blank=True, null=True)
    qr_code = models.ImageField(upload_to='qr_codes/', null=True, blank=True)
    type = models.CharField(max_length=50, default='general')
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    scheduled_at = models.DateTimeField(null=True, blank=True)
    is_sent = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.full_name} - {self.title}"

    
class DeviceToken(models.Model):
    user = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.full_name} - {self.token[:10]}..."


class Feedback(models.Model):
    reservation = models.ForeignKey(Reservation, on_delete=models.CASCADE)
    userborrower = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    comment = models.TextField(blank=True, null=True)
    
    return_status = models.CharField(max_length=20, choices=[
        ('On Time', 'On Time'),
        ('Late', 'Late Return'),
        ('Not Returned', 'Not Returned')
    ])
    
    created_at = models.DateTimeField(auto_now_add=True)

class DamageReport(models.Model):
    REPORT_TYPES = [
        ('Damage', 'Damage'),
        ('Loss', 'Loss'),
    ]

    item = models.ForeignKey(Item, on_delete=models.CASCADE, null=True, blank=True)
    reservation = models.ForeignKey(Reservation, on_delete=models.CASCADE, related_name="damage_reports", null=True, blank=True)
    reported_by = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES, default='Damage')

    location = models.CharField(max_length=255)
    quantity_affected = models.PositiveIntegerField()
    description = models.TextField()
    image = models.ImageField(upload_to='damage_reports/', blank=True, null=True)
    date_reported = models.DateTimeField(auto_now_add=True)

    status = models.CharField(
        max_length=20,
        choices=[
            ('Pending', 'Pending'),
            ('Reviewed', 'Reviewed'),
            ('Resolved', 'Resolved'),
            ('Verified', 'Verified'),
            ('Settled', 'Settled'),
        ],
        default='Pending'
    )

    qty_deducted = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        old_status = None
        if self.pk:
            old = DamageReport.objects.filter(pk=self.pk).first()
            if old:
                old_status = old.status

        super().save(*args, **kwargs)

        if self.status in ["Resolved", "Settled"] and old_status != self.status:
            borrower = self.reported_by
            item = self.item
            reservation = self.reservation

            # Apply violation points
            if self.report_type == "Damage":
                borrower.late_count += 1
                borrower.behavior_score -= 4

            elif self.report_type == "Loss":
                borrower.late_count += 2
                borrower.behavior_score -= 6

            # Set borrower status
            if borrower.late_count >= 3 or borrower.behavior_score <= -10:
                borrower.borrower_status = "Bad"
            elif borrower.late_count >= 1:
                borrower.borrower_status = "Warning"

            borrower.save()

            # Auto-deduct item for Loss
            if self.report_type == "Loss" and not self.qty_deducted:
                item.qty = max(0, item.qty - self.quantity_affected)
                item.save()

                self.qty_deducted = True
                super().save(update_fields=["qty_deducted"])

            # Create notification
            Notification.objects.create(
                user=borrower,
                reservation=reservation,
                title=f"{self.report_type} Report {self.status}",
                message=f"Your {self.report_type.lower()} report has been processed. Violations: {borrower.late_count}.",
                type="loss_report" if self.report_type == "Loss" else "damage_report",
            )

    def __str__(self):
        return f"{self.report_type} - {self.reported_by.full_name} - {self.status}"



class BlockedDate(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name='blocked_dates')
    date = models.DateField()
    reason = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.item.name} - {self.date}"
    
class AdminBorrow(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="admin_borrows")

    date = models.DateField()
    return_date = models.DateField()

    quantity = models.PositiveIntegerField()

    borrower_name = models.CharField(max_length=255)
    contact_number = models.CharField(max_length=50)
    address = models.TextField(blank=True, null=True)
    purpose = models.TextField(blank=True, null=True)
    delivered_by = models.CharField(max_length=255)

    status = models.CharField(
        max_length=20,
        choices=[("In Use", "In Use"), ("Returned", "Returned")],
        default="In Use",
    )

    # SAME FORMAT AS RESERVATION
    transaction_id = models.CharField(max_length=20, unique=True, default="T000000")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]

    def save(self, *args, **kwargs):
        if not self.transaction_id or self.transaction_id == "T000000":
            from .models import TransactionCounter
            self.transaction_id = TransactionCounter.next_id()
        super().save(*args, **kwargs)



    def __str__(self):
        return f"{self.item.name} - {self.quantity} pcs ({self.date} → {self.return_date})"


class TransactionCounter(models.Model):
    last_number = models.PositiveIntegerField(default=0)

    @classmethod
    @transaction.atomic
    def next_id(cls):
        counter, created = cls.objects.get_or_create(id=1)
        counter.last_number += 1
        counter.save()
        return f"T{counter.last_number:06d}"
