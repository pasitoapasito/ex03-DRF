import requests

from typing import Tuple, Any

from core.utils.api_config import URL, VERSION, DATA, TARGET


class GetKakaoAccount:
    
    def get_kakao_user_account_n_check_err(token: object) -> Tuple[Any, str]:
        headers = {
            'Authorization': f'Bearer {token}'
        }
        url = URL + '/{}/{}/{}'.format(
            VERSION,
            DATA,
            TARGET
        )
        try:
            res  = requests.get(url, headers=headers, timeout=3)
            data = res.json() 
        except:
            return None, '카카오 계정의 유저정보 요청시간이 초과되었습니다.'
            
        if data.get('code') == -401:
            return None, '카카오 계정의 유저정보를 가져올 수 없습니다.'
        
        return data, None