package com.ys.security.book;

import com.ys.security.account.Account;
import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
@Data
public class Book {

    @Id @GeneratedValue
    private Integer id;

    private String title;

    @ManyToOne
    public Account author;

}
