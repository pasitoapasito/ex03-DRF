from django.db                  import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser

from core.models import TimeStampModel


class UserManager(BaseUserManager):
    """
    Assignee: 김동규
    
    detail:
      - 커스텀 유저모델 사용 시 UserManager 클래스를 새롭게 정의해야 함
      - UserManager 클래스에는 create_user, create_superuser 함수가 정의되어 있어야 함
    """
    
    def create_user(self, email, nickname, password=None):
        """
        유저 회원가입 시 사용되는 메서드
        """
        if not email:
            raise ValueError('Users must have an email address')
        
        user = self.model(
            email    = self.normalize_email(email),
            nickname = nickname,
        )
        
        user.set_password(password)
        user.is_active = True
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, nickname, password=None):
        """
        어드민 유저 생성 시 사용되는 메서드
        """
        user = self.create_user(
            email    = email,
            password = password,
            nickname = nickname,
        )
        
        user.is_admin = True
        user.save(using=self._db)
        return user
    

class User(AbstractBaseUser, TimeStampModel):
    """
    Assignee: 김동규
    
    detail:
      - 커스텀 유저모델(AbstractBaseUser 클래스를 상속받아야 함)
      - 필수 필드(컬럼): is_active, is_admin
        > 참고내용:
          * is_active가 False일 경우 계정이 비활성화 됨
          * is_admin은 is_staff에서 활용 됨
    """
    
    email     = models.EmailField(unique=True)
    nickname  = models.CharField(max_length=50)
    password  = models.CharField(max_length=255, null=True, blank=True)
    kakao_id  = models.BigIntegerField()
    is_admin  = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    """
    커스텀 유저모델을 사용할 경우 필요함
    """
    objects = UserManager()
    
    """
    유저의 아이디로 사용될 필드 지정
    로그인 시 USERNAME_FIELD에 설정 된 필드와 password가 사용 됨
    """
    USERNAME_FIELD  = 'email'
    
    """
    유저 생성 시 필수로 입력받을 필드 지정
    """
    REQUIRED_FIELDS = ['nickname', ]
    
    def __str__(self):
        return f'{self.nickname} - {self.email}'

    """
    로그인 유저의 특정 테이블 CRUD 권한 설정
    관리자 유저일 경우 항상 True, 비활성화 유저(is_active=False)일 경우 항상 False
    """
    def has_perm(self, perm, obj=None):
        return True

    """
    로그인 유저의 특정 app 접근 권한 설정(app_label에는 특정 app이름이 들어감)
    관리자 유저일 경우 항상 True, 비활성화 유저(is_active=False)일 경우 항상 False
    """
    def has_module_perms(self, app_label):
        return True

    """
    관리자 권한 설정
    """
    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        db_table = 'users'