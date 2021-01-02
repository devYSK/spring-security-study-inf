package com.ys.security.common;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLogger {

    public static void log(String message) {
        System.out.println(message); // 현재 위치
        Thread thread = Thread.currentThread();
        System.out.println("thread : " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal();
        System.out.println("principal : " + principal);
    }
}
