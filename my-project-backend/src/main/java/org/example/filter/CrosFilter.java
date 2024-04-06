package org.example.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

import static org.example.utils.Const.ORDER_CORS;

/**
 * 手动配置跨域
 */

@Component
@Order(ORDER_CORS)
public class CrosFilter extends HttpFilter {
    @Override
    protected void doFilter(HttpServletRequest request,
                            HttpServletResponse response,
                            FilterChain chain) throws IOException, ServletException {
        this.addCrosHeader(request, response);
        chain.doFilter(request, response); // 放行
    }

    // 添加跨域对应的响应头
    private void addCrosHeader(HttpServletRequest request,
                               HttpServletResponse response) {
//        response.addHeader("Access-Control-Allow-Origin", request.getHeader("Origin")); //允许那些地址跨域访问
        response.addHeader("Access-Control-Allow-Origin", "http://localhost:5173"); //允许那些地址跨域访问
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"); // 允许放行的方法
        response.addHeader("Access-Control-Allow-Header", "Authorization, Content-Type");
    }
}
