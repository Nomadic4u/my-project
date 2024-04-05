package org.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {
    @Value("${spring.security.jwt.key}")
    String key; // 读取秘钥

    @Value("${spring.security.jwt.expire}") //token持续时间
    int expire;

    @Resource
    StringRedisTemplate template;

    // 使JWT失效
    public boolean invalidateJwt(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null) {
            return false;
        }
        Algorithm algorithm = Algorithm.HMAC256(key); // 加密方式
        JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // 验证签名
        try {
            DecodedJWT jwt = jwtVerifier.verify(token);
            String id = jwt.getId();
            return deleteToken(id, jwt.getExpiresAt());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    // 设置一个token黑名单, 从而使token失效
    private boolean deleteToken(String uuid, Date time) {
        if(this.isInvalidToken(uuid))
            return false;
        Date now = new Date();
        long expire = Math.max(0, time.getTime() - now.getTime());
        template.opsForValue().set(Const.JWT_BLACK_LIST + uuid, "", expire, TimeUnit.MILLISECONDS);
        return true;
    }

    // 判断token是否失效
    private boolean isInvalidToken(String uuid) {
        return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }

    // 解析token
    public DecodedJWT resolveJwt(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null)
            return null;
        Algorithm algorithm = Algorithm.HMAC256(key); // 加密方式
        JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // 验证签名
        try {
            DecodedJWT verify = jwtVerifier.verify(token); //验证token是否被篡改,然后解码 如果被篡改会抛出一个异常
            if(this.isInvalidToken(verify.getId())) // 判断token是否在黑名单中
                return null;

            Date expiresAt = verify.getExpiresAt(); // 获取过期的日期
            return new Date().after(expiresAt) ? null : verify; //判断是否过期, 如果没有过期, 则返回解析后的JWT
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    public String CreateJwt(UserDetails details, int id, String username) {
        Algorithm algorithm = Algorithm.HMAC256(key); // 加密方式
        Date expire = this.expireTime();
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("id", id)
                .withClaim("name", username)
                .withClaim("authorities", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(expire) // 设置过期时间
                .withIssuedAt(new Date()) // 颁发时间
                .sign(algorithm); // 签名


    }

    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire * 24);
        return calendar.getTime();
    }

    // 将jwt转变为UserDetails
    public UserDetails toUser(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return User
                .withUsername(claims.get("name").asString())
                .password("******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public Integer toId(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }


    // 验证token
    private String convertToken(String headerToken) {
        if (headerToken == null)
            return null;
        return headerToken.substring(7);
    }
}
