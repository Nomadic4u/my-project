package org.example.service;

import com.baomidou.mybatisplus.extension.service.IService;
import org.example.entity.dto.Account;
import org.example.entity.vo.request.EmailRegisterVO;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String text);

    String registerEmailVerifyCode(String type, String email, String ip); // IP地址限制请求频率

    String registerEmailAccount(EmailRegisterVO vo);
}


