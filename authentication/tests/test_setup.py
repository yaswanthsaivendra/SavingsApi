from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    def setUp(self) -> None:
        self.register_url = reverse('register')
        self.login_url = reverse('login')

        self.user_data = {
            'email' : 'email@gmail.com',
            'username' : 'email',
            'password' : 'email@gmail.com',
        }
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()