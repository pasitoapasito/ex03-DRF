from django.contrib import admin
from django.urls    import path, re_path, include

from drf_yasg       import openapi
from drf_yasg.views import get_schema_view

from rest_framework import permissions 


"""
Swagger settings
"""
schema_view = get_schema_view(
    openapi.Info(
        title           = 'social-login API',
        default_version = 'v1',
        description     = 'social-login',
    ),
    public = True,
    permission_classes = (permissions.AllowAny,),
)

"""
Django app url patterns
"""
urlpatterns = [
    path('admin/', admin.site.urls),
]

"""
Swagger url patterns
"""
urlpatterns += [
    re_path(r'^swagger(?P<format>\.json|\.yaml)$',schema_view.without_ui(cache_timeout=0),name='schema-json',),
    re_path(r'^swagger$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redoc$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]