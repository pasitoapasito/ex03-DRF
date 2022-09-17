from rest_framework.test             import APITestCase
from rest_framework_simplejwt.tokens import OutstandingToken

from unittest.mock import patch
from unittest      import mock

from users.models  import User


class KakaoSignInTest(APITestCase):
    
    maxDiff = None
    
    @classmethod
    def setUpTestData(cls):
        User.objects\
            .create(
                email    = 'test@example.com',
                nickname = 'test',
                kakao_id = 123456789
            )
    
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_success_user_kakao_signin_first_case(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'id': 12345678910,
                    'kakao_account': {
                        'email'  : 'user@example.com',
                        'profile': {
                            'nickname': 'user'
                        }
                    }
                }
                
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
        
        user = User.objects\
                   .get(email='user@example.com')
        
        token = OutstandingToken.objects\
                                .get(user=user)\
                                .token
                                
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()['refresh'], token)
        self.assertIn('refresh', response.json())
        self.assertIn('access', response.json())
    
    @patch('core.utils.get_obj_n_check_err.requests')    
    def test_success_user_kakao_signin_second_case(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'id': 123456789,
                    'kakao_account': {
                        'email'  : 'test@example.com',
                        'profile': {
                            'nickname': 'test'
                        }
                    }
                }
        
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
        
        user = User.objects\
                   .get(email='test@example.com')
                   
        token = OutstandingToken.objects\
                                .get(user=user)\
                                .token
                                
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['refresh'], token)
        self.assertIn('refresh', response.json())
        self.assertIn('access', response.json())
    
    @patch('core.utils.get_obj_n_check_err.requests')      
    def test_fail_user_kakao_signin_due_to_invalid_kakao_token(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'id': 123456789,
                    'kakao_account': {
                        'email'  : 'test@example.com',
                        'profile': {
                            'nickname': 'test'
                        }
                    }
                }
        
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': None}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'detail': '유효하지 않거나 만료된 토큰입니다.'
            }
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_kakao_signin_due_to_no_kakao_user_data(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'code': -401
                }
        
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '카카오 계정의 유저정보를 가져올 수 없습니다.'
            }
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_kakao_signin_due_to_not_existed_kakao_id(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'kakao_account': {
                        'email'  : 'test@example.com',
                        'profile': {
                            'nickname': 'test'
                        }
                    }
                }
        
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '카카오 계정의 유저정보를 가져올 수 없습니다.'
            }
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_kakao_signin_due_to_not_existed_email(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'id': 123456789,
                    'kakao_account': {
                        'profile': {
                            'nickname': 'test'
                        }
                    }
                }
        
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '카카오 계정의 유저정보를 가져올 수 없습니다.'
            }
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_kakao_signin_due_to_not_existed_nickname(self, mocked_requests):
        
        class MockedResponse:
            def json(self):
                return {
                    'id': 123456789,
                    'kakao_account': {
                        'email'  : 'test@example.com',
                        'profile': {}
                    }
                }
                
        mocked_requests.get = mock.MagicMock(return_value = MockedResponse())
        
        headers  = {'HTTP_Authorization': 'kakao token'}
        response = self.client\
                       .get('/api/users/kakao-signin', **headers, content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '카카오 계정의 유저정보를 가져올 수 없습니다.'
            }
        )    