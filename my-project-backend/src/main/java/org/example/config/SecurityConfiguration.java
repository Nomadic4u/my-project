package org.example.config;

import com.fasterxml.jackson.databind.util.BeanUtil;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.entity.RestBean;
import org.example.entity.dto.Account;
import org.example.entity.vo.response.AuthorizeVO;
import org.example.filter.JWTAuthorizeFilter;
import org.example.service.AccountService;
import org.example.utils.JwtUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class SecurityConfiguration {

    @Resource
    JwtUtils utils;

    @Resource
    JWTAuthorizeFilter jwtAuthorizeFilter;

    @Resource
    AccountService accountService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("api/auth/**", "/error").permitAll() //放行
                        .anyRequest() // 任何请求都不允许通过
                        .authenticated() // 验证之后才能通过

                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login") //登录的路径 登录用户名默认为username
                        .failureHandler(this::onAuthenticationFailure)
                        .successHandler(this::onAuthenticationSuccess) // 登录成功
                )
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout") //退出的路径
                        .logoutSuccessHandler(this::onLogoutSuccess) //退出成功
                )
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(this::onUnauthorized) //未登录
                        .accessDeniedHandler(this::onAccessDeny)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class) // 过滤器
                .build();
    }


    public void onAccessDeny(HttpServletRequest request,
                             HttpServletResponse response,
                             AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType("application/json");
        response.getWriter().write(RestBean.forbidden(accessDeniedException.getMessage()).asJsonString());
    }


    public void onUnauthorized(HttpServletRequest request,
                               HttpServletResponse response,
                               AuthenticationException exception) throws IOException {
        response.setContentType("application/json");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
    }


    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json"); // 告诉前端对应的格式
        response.setCharacterEncoding("utf-8");
        User user = (User) authentication.getPrincipal(); // 这里是SpringSecurity的user
        Account account = accountService.findAccountByNameOrEmail(user.getUsername());
        String token = utils.CreateJwt(user, account.getId(), account.getUsername());
        AuthorizeVO vo = account.asViewObject(AuthorizeVO.class, v ->{
            v.setExpire(utils.expireTime());
            v.setToken(token);
        });
//        vo.setUsername("小明");
//        BeanUtils.copyProperties(account, vo);
        response.getWriter().write(RestBean.success(vo).asJsonString());
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
    }

    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        PrintWriter writer = response.getWriter();
        String authorization = request.getHeader("Authorization");
        System.out.println(authorization);
        if(utils.invalidateJwt(authorization)) {
            writer.write(RestBean.success().asJsonString());
        } else {
            writer.write(RestBean.failure(400, "退出登录失败").asJsonString());
        }
    }
}



















