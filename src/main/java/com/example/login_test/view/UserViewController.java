package com.example.login_test.view;

import com.example.login_test.UserEntity;
import com.example.login_test.UserEntityService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class UserViewController {

    private final UserEntityService userEntityService;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/info")
    public String info(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // get email
        String email = authentication.getName();

        // get UserEntity
        UserEntity userEntity = userEntityService.getUserInfo(email);

        if (userEntity != null) {
            model.addAttribute("user", userEntity);
        } else {
            model.addAttribute("user", new UserEntity());
        }

        return "info";
    }
}
