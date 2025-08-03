from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, Mock

User = get_user_model()


class UserTestFixtures:
    """Test fixtures for user data"""

    @staticmethod
    def valid_user_data():
        return {
            'email': 'test@example.com',
            'password': 'A12345678a@'
        }

    @staticmethod
    def invalid_email_data():
        return {
            'email': 'invalid-email',
            'password': 'A12345678a@'
        }

    @staticmethod
    def invalid_password_data():
        return {
            'email': 'test@example.com',
            'password': '12345678'  # Too weak password
        }

    @staticmethod
    def admin_user_data():
        return {
            'email': 'admin@example.com',
            'password': 'AdminPass123@'
        }


class UserServiceTests(TestCase):
    """Unit tests for user services/business logic"""

    def setUp(self):
        self.fixtures = UserTestFixtures()

    def test_user_creation_service(self):
        """Test user creation through model"""
        user_data = self.fixtures.valid_user_data()
        user = User.objects.create_user(**user_data)

        self.assertIsNotNone(user.id)
        self.assertEqual(user.email, user_data['email'])
        self.assertTrue(user.check_password(user_data['password']))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_superuser_creation_service(self):
        """Test superuser creation"""
        admin_data = self.fixtures.admin_user_data()
        admin = User.objects.create_superuser(**admin_data)

        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)
        self.assertEqual(admin.email, admin_data['email'])

    @patch('api.models.User.objects.create_user')
    def test_user_creation_service_with_mock(self, mock_create):
        """Test user creation service with mocking"""
        mock_user = Mock()
        mock_user.id = 1
        mock_user.email = 'test@example.com'
        mock_create.return_value = mock_user

        user_data = self.fixtures.valid_user_data()
        result = User.objects.create_user(**user_data)

        mock_create.assert_called_once_with(**user_data)
        self.assertEqual(result.email, 'test@example.com')


class BaseAPITestCase(APITestCase):
    """Base class for API tests with common fixtures"""

    def setUp(self):
        self.fixtures = UserTestFixtures()
        self.client = APIClient()

    def create_user(self, user_data=None):
        """Helper method to create a user"""
        if user_data is None:
            user_data = self.fixtures.valid_user_data()
        return User.objects.create_user(**user_data)

    def create_admin_user(self):
        """Helper method to create an admin user"""
        admin_data = self.fixtures.admin_user_data()
        return User.objects.create_superuser(**admin_data)

    def get_tokens_for_user(self, user):
        """Helper method to get JWT tokens for a user"""
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def authenticate_user(self, user):
        """Helper method to authenticate a user"""
        tokens = self.get_tokens_for_user(user)
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        return tokens


class UserCreateAPITests(BaseAPITestCase):
    """API tests for user creation"""

    def test_create_user_with_valid_data(self):
        """Test creating user with valid data"""
        user_data = self.fixtures.valid_user_data()
        response = self.client.post('/api/users/', user_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], user_data['email'])
        self.assertEqual(User.objects.count(), 1)

    def test_create_user_with_invalid_email(self):
        """Test creating user with invalid email"""
        invalid_data = self.fixtures.invalid_email_data()
        response = self.client.post('/api/users/', invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_create_user_with_invalid_password(self):
        """Test creating user with invalid password"""
        invalid_data = self.fixtures.invalid_password_data()
        response = self.client.post('/api/users/', invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_create_duplicate_user(self):
        """Test creating user with existing email"""
        user_data = self.fixtures.valid_user_data()

        # Create first user
        self.create_user(user_data)

        # Try to create duplicate
        response = self.client.post('/api/users/', user_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class TokenAPITests(BaseAPITestCase):
    """API tests for JWT token operations"""

    def setUp(self):
        super().setUp()
        self.user = self.create_user()

    def test_obtain_token_with_valid_credentials(self):
        """Test obtaining token with valid credentials"""
        user_data = self.fixtures.valid_user_data()
        response = self.client.post('/api/token/', user_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_obtain_token_with_invalid_credentials(self):
        """Test obtaining token with invalid credentials"""
        invalid_data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post('/api/token/', invalid_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_token(self):
        """Test refreshing access token"""
        tokens = self.get_tokens_for_user(self.user)
        data = {'refresh': tokens['refresh']}

        response = self.client.post('/api/token/refresh/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_verify_token(self):
        """Test verifying access token"""
        tokens = self.get_tokens_for_user(self.user)
        data = {'token': tokens['access']}

        response = self.client.post('/api/token/verify/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class UserListAPITests(BaseAPITestCase):
    """API tests for user list operations"""

    def setUp(self):
        super().setUp()
        self.admin_user = self.create_admin_user()
        self.regular_user = self.create_user()

    def test_list_users_as_admin(self):
        """Test listing users as admin"""
        self.authenticate_user(self.admin_user)
        response = self.client.get('/api/users/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, dict)

    def test_list_users_as_regular_user(self):
        """Test listing users as regular user (should be forbidden)"""
        self.authenticate_user(self.regular_user)
        response = self.client.get('/api/users/')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_list_users_without_authentication(self):
        """Test listing users without authentication"""
        response = self.client.get('/api/users/')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UserDetailAPITests(BaseAPITestCase):
    """API tests for user detail operations"""

    def setUp(self):
        super().setUp()
        self.user = self.create_user()
        self.tokens = self.authenticate_user(self.user)

    def test_get_user_detail(self):
        """Test getting user detail"""
        response = self.client.get(f'/api/users/{self.user.id}/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)

    def test_update_user_detail(self):
        """Test updating user detail"""
        update_data = {
            'first_name': 'Updated',
            'last_name': 'User'
        }
        response = self.client.patch(
            f'/api/users/{self.user.id}/',
            update_data,
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Updated')
        self.assertEqual(response.data['last_name'], 'User')

    def test_get_user_detail_without_authentication(self):
        """Test getting user detail without authentication"""
        self.client.credentials()  # Remove authentication
        response = self.client.get(f'/api/users/{self.user.id}/')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutAPITests(BaseAPITestCase):
    """API tests for logout functionality"""

    def setUp(self):
        super().setUp()
        self.user = self.create_user()
        self.tokens = self.authenticate_user(self.user)

    def test_logout_with_valid_token(self):
        """Test logout with valid refresh token"""
        data = {'refresh': self.tokens['refresh']}
        response = self.client.post('/api/logout/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_without_authentication(self):
        """Test logout without authentication"""
        self.client.credentials()  # Remove authentication
        data = {'refresh': self.tokens['refresh']}
        response = self.client.post('/api/logout/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_with_invalid_token(self):
        """Test logout with invalid refresh token"""
        data = {'refresh': 'invalid-token'}
        response = self.client.post('/api/logout/', data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
