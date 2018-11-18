from django.urls import path
from .views import MainVulners

urlpatterns = [
    path('', MainVulners.as_view(), name="main page")
]
