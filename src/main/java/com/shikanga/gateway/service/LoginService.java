package com.shikanga.gateway.service;

import com.shikanga.gateway.auth.User;

public interface LoginService {

    String login(String username, String password);

    User saveUser(User user);

    boolean logout(String token);

    boolean isValidToken(String token);

    String createNewToken(String token);

}
