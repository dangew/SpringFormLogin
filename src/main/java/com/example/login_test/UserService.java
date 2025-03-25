package com.example.login_test;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@AllArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("loadUserByUserName username={}", email);

        // check that userEntity exists
        // if not, throw UsernameNotFoundException
        UserEntity userEntity = userRepository.findByEmail(email).orElse(null);
        if (userEntity == null) {
            log.info("username not found exception email={}", email);
            throw new UsernameNotFoundException(email);
        }

        // make UserDetails instance and return it
        return new User(
            userEntity.getEmail(),
            userEntity.getPassword(),
            List.of(new SimpleGrantedAuthority(userEntity.getRole()))
        );
    }
}
