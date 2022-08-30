from django.db import models


class TimeStampModel(models.Model):
    """
    Assignee: 김동규
    
    detail: Time Stamp 모델
    """
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True