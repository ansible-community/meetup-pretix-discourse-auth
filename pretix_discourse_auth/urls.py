from django.urls import path
from . import views

urlpatterns = [
    path('_discourse/login/return/', views.return_view, name='return'),

]
