import json

from rest_framework.test             import APITestCase, APIClient
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken

from unittest.mock import patch
from unittest      import mock

from users.models  import User


class UserSignOutTest(APITestCase):
    
    maxDiff = None
    
    @classmethod
    def setUpTestData(cls):
        cls.f_user = User.objects\
                         .create(
                             email    = 'user@example.com',
                             nickname = 'user',
                             kakao_id = 12345678910
                         )
                         
        cls.s_user = User.objects\
                         .create(
                             email    = 'test@example.com',
                             nickname = 'test',
                             kakao_id = 123456789
                         )
           
        cls.f_client = APIClient()
        cls.f_client.force_authenticate(user=cls.f_user)        
            
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_success_user_signout(self, mocked_requests):
        
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
                   
        refresh = OutstandingToken.objects\
                                  .get(user=user)
        
        data = {
            'refresh_token': refresh.token
        }
        
        response = self.f_client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        blacklist_token = BlacklistedToken.objects\
                                          .get(token_id=refresh.id)
                                          
        self.assertEqual(response.status_code, 204)
        self.assertEqual(refresh.id, blacklist_token.token_id)
        
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_signout_due_to_unauthorized_user(self, mocked_requests):
        
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
                   
        refresh = OutstandingToken.objects\
                                  .get(user=user)
        
        data = {
            'refresh_token': refresh.token
        }
        
        response = self.client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '자격 인증데이터(authentication credentials)가 제공되지 않았습니다.'
            }
        )
        
    def test_fail_user_signout_due_to_refresh_token_required(self):
        data = {}
        
        response = self.f_client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'detail': '유효하지 않거나 만료된 토큰입니다.'
            }
        )
        
    def test_fail_user_signout_due_to_refresh_token_mismatch(self):
        data = {
            'refresh_token': 'fake token'
        }
        
        response = self.f_client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'detail': '유효하지 않거나 만료된 토큰입니다.'
            }
        )
        
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_signout_due_to_token_type_mismatch(self, mocked_requests):
        
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
                       
        access = response.json()['access']
        
        data = {
            'refresh_token': access
        }
        
        response = self.f_client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'detail': '유효하지 않거나 만료된 토큰입니다.'
            }
        )
        
    @patch('core.utils.get_obj_n_check_err.requests')
    def test_fail_user_signout_due_to_not_own_refresh_token(self, mocked_requests):
        
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
                   
        refresh = OutstandingToken.objects\
                                  .get(user=user)
        
        data = {
            'refresh_token': refresh.token
        }
        
        response = self.f_client\
                       .post('/api/users/signout', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'detail': '유저의 토큰정보가 유효하지 않습니다.'
            }
        )