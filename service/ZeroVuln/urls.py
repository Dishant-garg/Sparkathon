from django.urls import path
from .views import scan_ports, get_nmap_arguments, sqlmap_scan, wpscan_scan, generate_ai_report

urlpatterns = [
    path('scan/', scan_ports, name='scan_ports'),
    path('arguments/', get_nmap_arguments, name='get_nmap_arguments'),
    path('sqlmap/', sqlmap_scan, name='sqlmap_scan'),
    path('wpscan/', wpscan_scan, name='wpscan_scan'),
    path('report/generate/', generate_ai_report, name='generate_ai_report'),
]