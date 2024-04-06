package org.example.controller;

import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.example.entity.RestBean;
import org.example.service.AccountService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {
    @Resource
    AccountService accountService;

    @GetMapping("ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam String email,
                                        @RequestParam String type, // type代表这是重置密码的邮件还是注册的邮件
                                        HttpServletRequest request) { // 取IP地址

        String message = accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr());
        return message == null ? RestBean.success() : RestBean.failure(400, message);

    }

}
