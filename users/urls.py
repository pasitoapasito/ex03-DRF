from django.urls import path

from users.views.social_signin import KakaoSignInView
from users.views.signout       import UserSignOutView


urlpatterns = [
    path('/kakao-signin', KakaoSignInView.as_view()),
    path('/signout', UserSignOutView.as_view()),
]
