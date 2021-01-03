package com.ys.security.account;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LogInOutController {

    @GetMapping("/my-login-page")
    public String loginForm() {
        return "my-login-page";
    }

    @GetMapping("/my-logout-page")
    public String logout() {
        return "my-logout-page";
    }

}
