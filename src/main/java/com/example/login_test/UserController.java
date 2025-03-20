package com.example.login_test;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final SessionRegistry sessionRegistry;
    private final UserEntityService userEntityService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestParam String email, @RequestParam String password,
        @RequestParam String name) {
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail(email);
        userEntity.setPassword(password);
        userEntity.setName(name);

        userEntityService.register(userEntity);

        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create("/")).build();
    }

    @GetMapping("/loginOk")
    public ResponseEntity<Map<String, String>> loginOk() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();
        String authorities = authentication.getAuthorities().toString();

        log.info("logged in email: {}", email);
        log.info("logged in authorities: {}", authorities);

        Map<String, String> userInfo = new HashMap<>();
        userInfo.put("email", email);
        userInfo.put("authorities", authorities);

        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/loginFail")
    public ResponseEntity<Void> loginFail() {
        return ResponseEntity.status(401).build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response,
        HttpSession httpSession) {
        log.info("logout api called");

        request.getSession(false).invalidate();

        // 쿠키 삭제
        //        Cookie cookie = new Cookie("JSESSIONID", null);
        //        cookie.setHttpOnly(false);
        //        cookie.setPath("/");
        //        cookie.setMaxAge(0);
        //        response.addCookie(cookie);

        // 로그아웃
        SecurityContextHolder.clearContext();

        // 세션 무효화
        //        httpSession.invalidate();

        return ResponseEntity.ok().build();
    }

    @GetMapping("/list")
    public List<String> getActiveSessions() {
        return sessionRegistry.getAllPrincipals().stream()
            .flatMap(principal -> sessionRegistry.getAllSessions(principal, false).stream())
            .map(SessionInformation::getSessionId)
            .collect(Collectors.toList());
    }

    @GetMapping("/logoutOk")
    public ResponseEntity<Void> logoutOk() {
        return ResponseEntity.ok().build();
    }

    @GetMapping("/logoutFail")
    public ResponseEntity<Void> logoutFail() {
        return ResponseEntity.status(401).build();
    }

    @GetMapping("/")
    public ResponseEntity<UserEntity> getUserPage() {
        System.out.println("일반 인증 성공");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        // 유저 정보
        UserEntity user = userEntityService.getUserInfo(email);

        return ResponseEntity.ok(user);
    }
}
