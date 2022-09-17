import json

from rest_framework.test             import APITestCase
from rest_framework_simplejwt.tokens import OutstandingToken

from unittest.mock import patch
from unittest      import mock

from users.models  import User


class UserRefreshTokenTest(APITestCase):
    
    maxDiff = None
    
    @classmethod
    def setUpTestData(cls):
        User.objects.create(
            email    = 'user@example.com',
            nickname = 'user',
            kakao_id = 12345678910
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')    
    def test_success_user_refresh_token(self, mocked_requests):
        
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
            'refresh': refresh.token
        }
        
        response = self.client\
                       .post('/api/users/token-refresh', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.json())
        self.assertNotIn('refresh', response.json())
        
    def test_fail_user_refresh_token_due_to_refresh_token_required(self):
        data = {}
        
        response = self.client\
                       .post('/api/users/token-refresh', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'refresh': [
                    '이 필드는 필수 항목입니다.'
                ]
            }
        )
        
    def test_fail_user_refresh_token_due_to_invalid_refresh_token(self):
        data = {
            'refresh': ' '
        }
        
        response = self.client\
                       .post('/api/users/token-refresh', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                'refresh': [
                    '이 필드는 blank일 수 없습니다.'
                ]
            }
        )
    
    def test_fail_user_refresh_token_due_to_refresh_token_mismatch(self):
        data = {
            'refresh': 'fake token'
        }
        
        response = self.client\
                       .post('/api/users/token-refresh', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '유효하지 않거나 만료된 토큰',
                'code'  : 'token_not_valid'
            }
        )
    
    @patch('core.utils.get_obj_n_check_err.requests')        
    def test_fail_user_refresh_token_due_to_token_type_mismatch(self, mocked_requests):
        
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
            'refresh': access
        }
        
        response = self.client\
                       .post('/api/users/token-refresh', data=json.dumps(data), content_type='application/json')
                       
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.json(),
            {
                'detail': '잘못된 토큰 타입',
                'code'  : 'token_not_valid'
            }
        )