package org.example.controller;

import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import org.example.entity.RestBean;
import org.example.entity.vo.request.EmailRegisterVO;
import org.example.service.AccountService;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.function.Supplier;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {
    @Resource
    AccountService accountService;

    @GetMapping("ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam @Email String email, // 参数校验
                                        @RequestParam @Pattern(regexp = "(register|reset )") String type, // type代表这是重置密码的邮件还是注册的邮件
                                        HttpServletRequest request) { // 取IP地址

        return this.messageHandle(() -> accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr()));

    }

    @PostMapping("/register")
    public RestBean<Void> register(@RequestBody @Valid EmailRegisterVO vo) {
        return this.messageHandle(() -> accountService.registerEmailAccount(vo));
    }

    private RestBean<Void> messageHandle(Supplier<String> action) {
        String message = action.get();
        return message == null ? RestBean.success() : RestBean.failure(400, message);
    }

}
