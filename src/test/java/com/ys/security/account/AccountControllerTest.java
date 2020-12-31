package com.ys.security.account;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Autowired
    AccountService accountService;

    @Test
    @WithAnonymousUser
    public void index_anonymous() throws Exception {

        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isForbidden());

    }

    @Test
    @WithUser
    public void index_user_youngsoo() throws Exception {
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());

    }

    @Test
    public void index_user() throws Exception {
        mockMvc.perform(get("/")
                .with(user("youngsoo").roles("USER")))// 이러한 가짜 유저가 있다 하고 요청을 보내는것
                .andDo(print())
                .andExpect(status().isOk());

    }

    @Test
    public void admin_user() throws Exception {
        mockMvc.perform(get("/admin")
                .with(user("youngsoo").roles("USER")))// 이러한 가짜 유저가 있다 하고 요청을 보내는것
                .andDo(print())
                .andExpect(status().isForbidden());

    }
    @Test
    public void admin_admin() throws Exception {
        mockMvc.perform(get("/admin")
                .with(user("youngsoo").roles("ADMIN")))// 이러한 가짜 유저가 있다 하고 요청을 보내는것
                .andDo(print())
                .andExpect(status().isOk());

    }

    @Test
    public void login() throws Exception {
        String username = "youngsoo";
        String password = "123";

        Account user = createUser(username, password);

        mockMvc.perform(formLogin().user(user.getUsername()).password(password))
                .andExpect(authenticated());
    }

    private Account createUser(String username, String password) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword(password);
        account.setRole("USER");

        return accountService.createNew(account);
    }

}