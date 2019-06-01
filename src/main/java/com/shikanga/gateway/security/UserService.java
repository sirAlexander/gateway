package com.shikanga.gateway.security;

import com.shikanga.gateway.auth.MongoUserDetails;
import com.shikanga.gateway.auth.Role;
import com.shikanga.gateway.auth.User;
import com.shikanga.gateway.exception.CustomException;
import com.shikanga.gateway.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);

        if (user == null || user.getRole() == null || user.getRole().isEmpty()) {
            throw new CustomException("Invalid username or password.", HttpStatus.UNAUTHORIZED);
        }
        String[] authorities = new String[user.getRole().size()];
        int count = 0;
        for (Role role : user.getRole()) {
            authorities[count] = "ROLE_" + role.getRole();
            count++;
        }

        return new MongoUserDetails(
                user.getEmail(),
                user.getPassword(),
                user.getActive(),
                user.isLocked(),
                user.isExpired(),
                user.isEnabled(),
                authorities
        );
    }
}
