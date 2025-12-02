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
    late_count = models.IntegerField(default=0)
    borrower_status = models.CharField(max_length=10, default='Good')

    def __str__(self):
        return self.user.username
    
    
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

    # NEW — DATE RANGE
    date_borrowed = models.DateField()
    date_return = models.DateField()

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
    reservation = models.ForeignKey(Reservation,on_delete=models.CASCADE,related_name="damage_reports", null=True, blank=True)
    reported_by = models.ForeignKey(UserBorrower, on_delete=models.CASCADE)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES, default='Damage')  # ✅ NEW

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
            ('Resolved', 'Resolved')
        ],
        default='Pending'
    )
    
    qty_deducted = models.BooleanField(default=False)
    

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
