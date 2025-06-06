from rest_framework.test import APITestCase
from rest_framework import status
from .models import User


class BaseAPITestCase(APITestCase):
    VALID_USER_DATA = {
        'email': 'test@gmail.com',
        'password': 'A12345678a@'
    }
    INVALID_EMAIL_DATA = {
        'email': 'test@gma.il.com',
        'password': 'A12345678a@'
    }
    INVALID_PASSWORD_DATA = {
        'email': 'test@gmail.com',
        'password': 'A12345678a'
    }


class UserCreateTests(BaseAPITestCase):
    def test_create_user_with_valid_data(self):
        """تست ساخت کاربر با داده‌های معتبر"""
        response = self.client.post(
            '/api/users/', self.VALID_USER_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json()['email'],
                         self.VALID_USER_DATA['email'])
        self.assertEqual(User.objects.count(), 1)

    def test_create_user_with_invalid_email(self):
        """تست ساخت کاربر با ایمیل نامعتبر"""
        response = self.client.post(
            '/api/users/', self.INVALID_EMAIL_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.json())

    def test_create_user_with_invalid_password(self):
        """تست ساخت کاربر با رمز عبور نامعتبر"""
        response = self.client.post(
            '/api/users/', self.INVALID_PASSWORD_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.json())


class TokenObtainTests(BaseAPITestCase):
    def setUp(self):
        self.client.post('/api/users/', self.VALID_USER_DATA, format='json')

    def test_obtain_token_with_valid_credentials(self):
        """تست گرفتن توکن با اطلاعات معتبر"""
        response = self.client.post(
            '/api/token/', self.VALID_USER_DATA, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.json())
        self.assertIn('refresh', response.json())

    def test_obtain_token_with_invalid_password(self):
        """تست گرفتن توکن با رمز اشتباه"""
        data = self.VALID_USER_DATA.copy()
        data['password'] = 'WrongPass123!'
        response = self.client.post('/api/token/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshAndVerifyTests(BaseAPITestCase):
    def setUp(self):
        self.client.post('/api/users/', self.VALID_USER_DATA, format='json')
        response = self.client.post(
            '/api/token/', self.VALID_USER_DATA, format='json')
        self.refresh_token = response.json()['refresh']
        self.access_token = response.json()['access']

    def test_refresh_token(self):
        """تست رفرش کردن توکن"""
        data = {'refresh': self.refresh_token}
        response = self.client.post('/api/token/refresh/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.json())

    def test_verify_token(self):
        """تست اعتبارسنجی توکن"""
        data = {'token': self.access_token}
        response = self.client.post('/api/token/verify/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UserListTests(BaseAPITestCase):
    def setUp(self):
        User.objects.create_superuser(
            email='admin@gmail.com', password='A12345678a@')
        response = self.client.post('/api/token/', {
            'email': 'admin@gmail.com',
            'password': 'A12345678a@'
        }, format='json')
        self.access_token = response.json()['access']

    def test_list_users_as_admin(self):
        """تست لیست کاربران با دسترسی ادمین"""
        response = self.client.get(
            '/api/users/', HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_users_without_token(self):
        """تست لیست کاربران بدون توکن"""
        response = self.client.get('/api/users/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_user_while_authenticated(self):
        """تست ساخت کاربر وقتی لاگین هستی (باید خطا بده)"""
        response = self.client.post('/api/users/', self.VALID_USER_DATA,
                                    HTTP_AUTHORIZATION=f'Bearer {self.access_token}', format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class UserDetailTests(BaseAPITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@gmail.com', password='A12345678a@')
        response = self.client.post(
            '/api/token/', self.VALID_USER_DATA, format='json')
        self.access_token = response.json()['access']

    def test_get_user_detail(self):
        """تست گرفتن جزئیات کاربر"""
        response = self.client.get(
            '/api/users/1/', HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['email'],
                         self.VALID_USER_DATA['email'])

    def test_get_user_detail_without_token(self):
        """تست گرفتن جزئیات کاربر بدون توکن"""
        response = self.client.get('/api/users/1/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_user_detail(self):
        """تست به‌روزرسانی جزئیات کاربر"""
        update_data = {
            'email': 'test@gmail.com',
            'first_name': 'Test',
            'last_name': 'Testy'
        }
        response = self.client.patch('/api/users/1/', update_data,
                                     HTTP_AUTHORIZATION=f'Bearer {self.access_token}', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['first_name'], 'Test')
        self.assertEqual(response.json()['last_name'], 'Testy')


class LogoutTests(BaseAPITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@gmail.com', password='A12345678a@')
        response = self.client.post(
            '/api/token/', self.VALID_USER_DATA, format='json')
        self.refresh_token = response.json()['refresh']
        self.access_token = response.json()['access']

    def test_logout_with_valid_refresh_token(self):
        """تست خروج با refresh token معتبر"""
        data = {'refresh': self.refresh_token}
        response = self.client.post('/api/logout/', data, format='json',
                                    HTTP_AUTHORIZATION=f'Bearer {self.access_token}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()['status'], 'You have logged out')

    def test_logout_without_token(self):
        """تست خروج بدون توکن (باید خطا بده)"""
        response = self.client.post(
            '/api/logout/', {'refresh': self.refresh_token}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
