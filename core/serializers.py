from rest_framework import serializers
from .models import Reservation, ReservationItem

class ReservationItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReservationItem
        fields = "__all__"

class ReservationSerializer(serializers.ModelSerializer):
    items = ReservationItemSerializer(many=True, required=False)

    class Meta:
        model = Reservation
        fields = "__all__"