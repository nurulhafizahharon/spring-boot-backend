package com.spring_boot_backend.service;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.spring_boot_backend.entity.User;
import com.spring_boot_backend.repository.UserRepository;

@Service
public class UserServiceImpl implements UserDetailsService, UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("In UserServiceImpl.java - loadUserByUsername.");
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User is not valid."));
    }

    @Override
    public List<User> getAllUsers() {
        System.out.println("In UserServiceImpl.java - getAllUsers().");
        return userRepository.findAll();
    }

    @Override
    public void deleteUser(int userId) {
        userRepository.deleteById(userId);
    }

}
