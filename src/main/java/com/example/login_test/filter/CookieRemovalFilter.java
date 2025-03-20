package com.example.login_test.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class CookieRemovalFilter extends OncePerRequestFilter {

    private static final String TARGET_COOKIE = "JSESSIONID"; // 삭제할 쿠키 이름

    @Override
    protected void doFilterInternal(HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain)
        throws ServletException, IOException {

        // 1️⃣ 다음 필터 호출 (필터 체인 진행)
        filterChain.doFilter(request, response);

        // 2️⃣ 응답 후 특정 쿠키 삭제
        deleteCookie(response, TARGET_COOKIE);
    }

    private void deleteCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setMaxAge(0); // 즉시 만료
        cookie.setPath("/"); // 경로 설정 (애플리케이션 전역)
        response.addCookie(cookie); // 응답에 쿠키 추가
    }
}
