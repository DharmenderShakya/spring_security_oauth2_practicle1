package com.Spring_Security_oauth2_practicle1.configuration;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import com.Spring_Security_oauth2_practicle1.customRepository.UserCustomRepository;
import com.Spring_Security_oauth2_practicle1.entity.Users;
import com.Spring_Security_oauth2_practicle1.enums.Role;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class SocialAppService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserCustomRepository userRepository;

    private static final Logger logger = LoggerFactory.getLogger(SocialAppService.class);

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {

        //  Default service to fetch user from Google
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate =
                new DefaultOAuth2UserService();

        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        //  Extract user details
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        logger.info("OAuth2 Login Success: {}", email);

        //  Check if user exists
        Users user = userRepository.getByUserName(email).orElse(null);

        if (user == null) {
            // New user → Save in DB
            user = new Users();
            user.setUserName(email);
            user.setPassword("OAUTH2_USER"); // dummy password
            user.setRole(Role.USER); // default role
            user.setAccountNonLocked(false);
            user.setFailedAttempts(0);

            userRepository.saveUser(user);

            logger.info("New user saved: {}", email);
        }

        // Assign authorities (VERY IMPORTANT)
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
        );

        // Return OAuth2User with authorities
        return new DefaultOAuth2User(
                authorities,
                oAuth2User.getAttributes(),
                "email" // key attribute
        );
    }

}
