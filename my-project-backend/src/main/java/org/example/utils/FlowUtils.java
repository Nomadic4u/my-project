package org.example.utils;

import jakarta.annotation.Resource;
import net.sf.jsqlparser.expression.DateTimeLiteralExpression;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

/**
 * 验证码60s内限流
 */
@Component
public class FlowUtils {

    @Resource
    StringRedisTemplate template;

    public boolean limitOnceCheck(String key, int blockTime) {
        if (Boolean.TRUE.equals(template.hasKey(key))) {
            return false;
        } else {
            template.opsForValue().set(key, "", blockTime, TimeUnit.SECONDS); // 设置过期时间
            return true;
        }
    }
}
