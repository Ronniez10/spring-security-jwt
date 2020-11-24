package com.neelav.springsecurityjwt.services;
import com.neelav.springsecurityjwt.models.MyUserDetails;
import com.neelav.springsecurityjwt.models.User;
import com.neelav.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;



@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        Optional<User> user = userRepository.findByUserName(username);

        return user.map(MyUserDetails::new).orElseThrow(()-> new UsernameNotFoundException("User does not Exist"));

    }
}
