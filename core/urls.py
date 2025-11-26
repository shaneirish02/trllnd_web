from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    CheckAvailabilityView, CreateReservationView,
    forgot_password, verify_reset_code, run_scheduler_api # ✅ make sure these are imported
)
from . import views

urlpatterns = [
    # Web page login
    path("login/", views.admin_login, name="login"),

    # Admin web views
    path("dashboard/", views.dashboard, name="dashboard"),
    
    # Forgot password + reset code
    path("forgot_password/", views.forgot_password, name="forgot_password"),
    path("verify_reset_code/", views.verify_reset_code, name="verify_reset_code"),


    # Inventory & others
    path("inventory/", views.inventory, name="inventory"),
    path("inventory/create/", views.inventory_createitem, name="inventory-createitem"),
    path("inventory/detail/<int:item_id>/", views.inventory_detail, name="inventory_detail"),
    path("inventory/edit/<int:item_id>/", views.inventory_edit, name="inventory_edit"),
    path("inventory/delete/<int:item_id>/", views.inventory_delete, name="inventory_delete"),

    path("verification/", views.verification, name="verification"),
    path("transaction_history/", views.transaction_log, name="transaction_log"),
    path("statistics/", views.statistics, name="statistics"),
    path('change_password/', views.change_password, name='change_password'),
    path("list_of_users/", views.list_of_users, name="list_of_users"),
    path("logout/", views.logout, name="logout"),

    # API endpoints
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),


    path("api/register/", views.api_register),
    path("api/verify-email/<uidb64>/<token>/", views.verify_email, name="verify_email"),
    path("api/login/", views.api_login),
    path("api/inventory_list/", views.api_inventory_list),
    path("api/inventory_detail/<int:id>/", views.api_inventory_detail),
    path("api/reservations/check/", CheckAvailabilityView.as_view()),
    path("api/create_reservation/", CreateReservationView.as_view()),
    path("api/items/<int:item_id>/availability/", views.item_availability, name="item-availability"),
    path("api/items/<int:item_id>/availability-map/", views.item_availability_map, name="item-availability-map"),

    path('api/pending-requests/', views.pending_requests_api, name='pending_requests_api'),
    path("api/reservation_detail/<int:pk>/", views.reservation_detail_api, name="reservation_detail_api"),
    path("api/reservation_update/<int:pk>/", views.reservation_update_api, name="reservation_update_api"),
    path("api/user_profile/", views.user_profile, name="api-user-profile"),
    path("api/update_profile/", views.update_profile, name="api-update-profile"),

    path('api/save_token/', views.save_device_token, name='save_device_token'),
    path('api/notifications/', views.get_user_notifications, name='get_user_notifications'),
    path('api/notifications/<int:pk>/read/', views.mark_notification_as_read, name='mark_notification_as_read'),
    path('api/notifications/mark_all_read/', views.mark_all_notifications_as_read, name='mark_all_notifications_as_read'),
    path('api/notifications/add-delayed/', views.add_delayed_notification, name='add_delayed_notification'),
    path('api/notifications/delete/<int:pk>/', views.delete_notification, name='delete_notification'),
    path('api/notifications/trigger_due_reminders/', views.trigger_due_soon_notifications),

    #NEW
    path('api/user_reservations/', views.user_reservations, name='user_reservations'),
    path('api/reservations/<int:pk>/cancel/', views.cancel_reservation, name='cancel_reservation'),

    #verification
    path("verify_qr/", views.verify_qr, name="verify_qr"),
    path('verify_qr/<str:mode>/<str:code>/', views.verify_qr, name='verify_qr'),
    path('update_reservation/<str:mode>/<str:code>/', views.update_reservation, name='update_reservation'),

    path('submit_feedback/', views.submit_feedback, name='submit_feedback'),
    path('monthly_reset/', views.monthly_reset, name='monthly_reset'),  # optional

    path('damage_report/', views.damage_loss_report_list, name='damage_loss_report_list'),
    path("api/in-use-items/", views.get_in_use_items, name="get_in_use_items"),
    path('api/damage-report/', views.submit_damage_loss_report, name='submit_damage_loss_report'),
    path('api/item/<int:item_id>/calendar/', views.get_item_calendar, name='get_item_calendar'),
    path('api/item/<int:item_id>/block-toggle/', views.toggle_block_date, name='toggle_block_date'),
    path("api/item/<int:item_id>/cancel-reservations/", views.cancel_reservations_for_date),

    path("statistics/data/", views.statistics_data, name="statistics_data"),
    path("statistics/export/excel/", views.export_excel, name="export_excel"),
    path("statistics/export/pdf/", views.export_pdf, name="export_pdf"),
    path("statistics/export/docx/", views.export_docx, name="export_docx"),


    path("api/me_borrower/", views.me_borrower),
    path("api/late-history/", views.borrower_late_history, name="borrower_late_history"),

    path("api/item/<int:item_id>/admin-borrow/", views.create_admin_borrow, name="create_admin_borrow"),
    path("api/admin-borrow/<int:pk>/update/", views.update_admin_borrow, name="update_admin_borrow"),
    path("api/admin-borrow/<int:pk>/delete/", views.delete_admin_borrow, name="delete_admin_borrow"),
    # ------------ ADMIN BORROW ------------
    # Create new direct borrow
    path("api/item/<int:item_id>/admin-borrow/", views.create_admin_borrow),

    # List direct borrows for a date
    path("api/item/<int:item_id>/admin-borrow/list/", views.admin_borrow_list),

    # Mark direct borrow as returned
    path("api/admin-borrow/<int:pk>/return/", views.return_admin_borrow),

    path("api/suggest-items/", views.suggest_items, name="suggest-items"),
    path("damage-report/update-status/<int:report_id>/", views.update_report_status, name='update_report_status'),
    path("api/item/<int:item_id>/admin-borrow/", views.admin_borrow_create, name="admin_borrow_create"),
    path("api/run-scheduler/", run_scheduler_api),




]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
