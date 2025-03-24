package com.example.login_test;

import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    private final SessionRegistry sessionRegistry = new SessionRegistryImpl();

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication != null) {
            sessionRegistry.removeSessionInformation(request.getSession().getId()); // ✅ 모든 세션 삭제
        }
    }
}
