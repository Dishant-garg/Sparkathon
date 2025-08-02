from django.urls import path
from .views import scan_vulnerability, nikto_scan

urlpatterns = [
    path('scan/', scan_vulnerability, name='scan_vulnerability'),
    path('nikto/', nikto_scan, name='nikto_scan'),
]
