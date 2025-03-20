package com.example.login_test;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
public class CustomLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) {

        // clear the cookie
        Cookie cookie = new Cookie("JSESSIONID", null);

        // set the cookie to expire in 0 seconds
        cookie.setMaxAge(0);

        // set the cookie path
        cookie.setPath("/");

        // add the cookie to the response
        response.addCookie(cookie);

        // clear the authentication
        authentication.setAuthenticated(false);

    }

}
