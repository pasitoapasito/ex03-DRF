from rest_framework.views                 import APIView
from rest_framework.permissions           import AllowAny
from rest_framework.response              import Response
from rest_framework_simplejwt.tokens      import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from core.utils.get_obj_n_check_err import GetKakaoAccount
from users.serializers              import KakaoSignInSerializer
from users.models                   import User

from drf_yasg.utils import swagger_auto_schema


class KakaoSignInView(APIView):
    
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(responses={201: KakaoSignInSerializer})
    def get(self, request):
        kakao_token = request.headers.get('Authorization')
        if not kakao_token:
            return Response({'detail': '유효하지 않거나 만료된 토큰입니다.'}, status=400)
        
        kakao, err = GetKakaoAccount.get_kakao_user_account_n_check_err(kakao_token)
        if err:
            return Response({'detail': err}, status=401)
        
        try:
            kakao_id = kakao['id']
            email    = kakao['kakao_account']['email']
            nickname = kakao['kakao_account']['profile']['nickname']
        except:
            return Response({'detail': '카카오 계정의 유저정보를 가져올 수 없습니다.'}, status=401)
        
        user, is_created = User.objects\
                               .get_or_create(
                                   kakao_id = kakao_id,
                                   defaults = {'email': email, 'nickname': nickname}
                               )
        
        for token in OutstandingToken.objects.filter(user=user):
            BlacklistedToken.objects\
                            .get_or_create(token=token)
                            
        token         = TokenObtainPairSerializer.get_token(user)
        refresh_token = str(token)
        access_token  = str(token.access_token)
        
        data = {
            'refresh': refresh_token,
            'access' : access_token
        }     
        status = 201 if is_created else 200
        
        serializer = KakaoSignInSerializer(data=data)
        if serializer.is_valid():
            return Response(serializer.data, status=status)
        return Response(serializer.errors, status=400)   