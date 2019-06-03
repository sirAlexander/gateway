package com.shikanga.gateway.service;

import com.shikanga.gateway.auth.JwtToken;
import com.shikanga.gateway.auth.User;
import com.shikanga.gateway.exception.CustomException;
import com.shikanga.gateway.repository.JwtTokenRepository;
import com.shikanga.gateway.repository.UserRepository;
import com.shikanga.gateway.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtTokenRepository jwtTokenRepository;


    @Override
    public String login(String username, String password) {
        String unauthorizedExceptionMessage = "Invalid username or password.";
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );
            User user = userRepository.findByEmail(username);
            if (user == null || user.getRole() == null || user.getRole().isEmpty()) {
                throw new CustomException(unauthorizedExceptionMessage, HttpStatus.UNAUTHORIZED);
            }
            return jwtTokenProvider.createToken(
                    username,
                    user.getRole().stream()
                            .map(role -> "ROLE_" + role.getRole())
                            .filter(Objects::nonNull)
                            .collect(Collectors.toList())
            );
        } catch (AuthenticationException aex) {
            throw new CustomException(unauthorizedExceptionMessage, HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public boolean logout(String token) {
        jwtTokenRepository.delete(new JwtToken(token));
        return true;
    }

    @Override
    public boolean isValidToken(String token) {
        return jwtTokenProvider.validateToken(token);
    }

    @Override
    public String createNewToken(String token) {
        String username = jwtTokenProvider.getUsername(token);
        List<String> roleList = jwtTokenProvider.getRoleList(token);
        return jwtTokenProvider.createToken(username, roleList);
    }
}
