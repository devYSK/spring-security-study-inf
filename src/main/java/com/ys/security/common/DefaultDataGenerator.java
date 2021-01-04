package com.ys.security.common;

import com.ys.security.account.Account;
import com.ys.security.account.AccountService;
import com.ys.security.book.Book;
import com.ys.security.book.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    @Autowired
    AccountService accountService;

    @Autowired
    BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        // keesun - spring
        // whiteship - hibernate

        Account keesun = createUser("keesun");
        Account whiteShip = createUser("whiteShip");

        createBook("spring", keesun);
        createBook("hibernate", whiteShip);

    }

    private void createBook(String name, Account author) {
        Book book = new Book();
        book.setTitle(name);
        book.setAuthor(author);
        bookRepository.save(book);
    }

    private Account createUser(String username) {
        Account account = new Account();

        account.setUsername(username);
        account.setPassword("123");
        account.setRole("USER");

        return accountService.createNew(account);
    }
}
