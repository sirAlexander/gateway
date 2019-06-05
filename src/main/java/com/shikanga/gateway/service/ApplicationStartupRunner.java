package com.shikanga.gateway.service;

import com.shikanga.gateway.auth.Role;
import com.shikanga.gateway.auth.User;
import com.shikanga.gateway.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Component
public class ApplicationStartupRunner implements ApplicationRunner {

    @Autowired
    private LoginService loginService;

    @Autowired
    UserRepository userRepository;

    private void seedData() {
        userRepository.deleteAll();
        User user1 = new User("alexander@qudini.com", "testpassword01", "alejandro", "Shuboan");
        Set<Role> roles = new HashSet<>();
        roles.add(new Role(12345, "Admin"));
        user1.setRole(roles);
        loginService.saveUser(user1);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        seedData();
    }
}
