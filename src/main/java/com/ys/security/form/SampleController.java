package com.ys.security.form;

import com.ys.security.account.AccountContext;
import com.ys.security.account.AccountRepository;
import com.ys.security.common.SecurityLogger;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
@RequiredArgsConstructor
public class SampleController {

    private final SampleService sampleService;
    private final AccountRepository accountRepository;

    @GetMapping("/")
    public String index(Model model, Principal principal) {

        if (principal == null)
            model.addAttribute("message", "Hello Spring security");
        else
            model.addAttribute("message", "Hello " + principal.getName());

        return "index";
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "Info");

        return "index";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());

        AccountContext.setAccount(accountRepository.findByUsername(principal.getName()));

        sampleService.dashboard();
        return "dashboard";
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());

        return "admin";
    }
    @GetMapping("/user")
    public String user(Model model, Principal principal) {
        model.addAttribute("message", "Hello " + principal.getName());

        return "user";
    }

    @GetMapping("/async-handler")
    @ResponseBody
    public Callable<String> asyncHandler() {

        SecurityLogger.log("MVC");

        return new Callable<String>() {
            @Override
            public String call() throws Exception {
                SecurityLogger.log("Callable");
                return "Async Handler";
            }
        };

    }

    @GetMapping("/async-service")
    @ResponseBody
    public String asyncService() {

        SecurityLogger.log("MVC, before async service" );
        sampleService.asyncService();
        SecurityLogger.log("MVC, after async service" );


        return "Async Service";

    }

}
