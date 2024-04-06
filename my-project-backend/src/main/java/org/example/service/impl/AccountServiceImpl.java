package org.example.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import jakarta.annotation.Resource;
import org.example.entity.dto.Account;
import org.example.mapper.AccountMapper;
import org.example.service.AccountService;
import org.example.utils.Const;
import org.example.utils.FlowUtils;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {


    @Resource
    FlowUtils utils;

    @Resource
    AmqpTemplate amqpTemplate;

    @Resource
    StringRedisTemplate stringRedisTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByNameOrEmail(username);
        if (account == null)
            throw new UsernameNotFoundException("用户名或密码错误");
        return User
                .withUsername(username)
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Override
    public Account findAccountByNameOrEmail(String text) {
        return this.query()
                .eq("username", text).or()
                .eq("email", text)
                .one();
    }

    // 邮箱发送验证码
    @Override
    public String registerEmailVerifyCode(String type, String email, String ip) {
        synchronized (ip.intern()) { // 这里用到了字符串池, String.intern()方法会先看字符串池中是否有这个String对象的字符串, 有的话直接返回, 没有的话就将这个对象添加到字符串池中, 并返回引用. 这个主要是为了确保在多个地方使用ip锁的时候是共用同一个对象
            if(!this.verifyLimit(ip)) {
                return "请求频繁, 请稍后再试";
            }
            // 生成验证码
            Random random = new Random();
            int code = random.nextInt(899999) + 100000;
            Map<String, Object> data = Map.of("type", type, "email", email, "code", code);
            amqpTemplate.convertAndSend("mail", data); // 放入mq队列
            stringRedisTemplate.opsForValue()
                    .set(Const.VERIFY_EMAIL_DATA + email, String.valueOf(code), 3, TimeUnit.MINUTES); // 放入redis
            return null;
        }

    }

    private boolean verifyLimit(String ip) {
        String key = Const.VERIFY_EMAIL_LIMIT + ip; // 根据ip限制;
        return utils.limitOnceCheck(key, 60);
    }
}
