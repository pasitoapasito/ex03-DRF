from django.urls import path

from users.views.social_signin import KakaoSignInView
from users.views.signout       import UserSignOutView

from rest_framework_simplejwt.views import TokenRefreshView


urlpatterns = [
    path('/kakao-signin', KakaoSignInView.as_view()),
    path('/signout', UserSignOutView.as_view()),
]

urlpatterns += [
    path('/token-refresh', TokenRefreshView.as_view()),
]