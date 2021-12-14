from django.urls import path
from .views import IncomeDetailAPIView, IncomeListAPIView

urlpatterns = [
    path('', IncomeListAPIView.as_view(), name="incomes"),
    path('<int:id>/', IncomeDetailAPIView.as_view(), name="income"),
]