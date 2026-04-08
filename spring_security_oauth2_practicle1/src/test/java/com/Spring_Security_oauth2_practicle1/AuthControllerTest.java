package com.Spring_Security_oauth2_practicle1;

import com.Spring_Security_oauth2_practicle1.controller.AuthController;
import com.Spring_Security_oauth2_practicle1.configuration.JWTUtils;
import com.Spring_Security_oauth2_practicle1.configuration.JwtAuthenticationFilter;
import com.Spring_Security_oauth2_practicle1.customRepository.UserCustomRepository;
import com.Spring_Security_oauth2_practicle1.entity.Users;
import com.Spring_Security_oauth2_practicle1.request.AuthRequest;
import com.Spring_Security_oauth2_practicle1.service.LoginAttemptService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(TestSecurityConfig.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JWTUtils jUtils;

    @MockBean
    private LoginAttemptService loService;

    @MockBean
    private UserCustomRepository userRepository;
    
    @MockBean
    private com.Spring_Security_oauth2_practicle1.configuration.OurUserDetailsService ourUserDetailsService;
    
    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;


    @Test
    void testLoginSuccess() throws Exception {

        AuthRequest request = new AuthRequest();
        request.setUserName("test");
        request.setPassword("123");

        Authentication auth = mock(Authentication.class);
        User user = new User("test", "123", new java.util.ArrayList<>());

        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(auth.getPrincipal()).thenReturn(user);
        when(jUtils.generateToken(any())).thenReturn("mock-token");

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                          "userName": "test",
                          "password": "123"
                        }
                        """))
                .andExpect(status().isOk())
                .andExpect(content().string("mock-token"));

        verify(loService).loginSucceeded("test");
    }

    
    @Test
    void testLoginFailure() throws Exception {

        when(authenticationManager.authenticate(any()))
                .thenThrow(new RuntimeException("Bad credentials"));

        mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                          "userName": "test",
                          "password": "wrong"
                        }
                        """))
                .andExpect(status().isOk());

        verify(loService).loginFailed("test");
    }

 
    @Test
    void testCreateUser() throws Exception {

        mockMvc.perform(post("/auth/createUser")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                          "userName": "newUser",
                          "password": "123"
                        }
                        """))
                .andExpect(status().isOk())
                .andExpect(content().string("User Successfully created"));

        verify(userRepository).saveUser(any(Users.class));
    }

   
    @Test
    @WithMockUser(roles = "SUPER_ADMIN")
    void testUnlockSuccess() throws Exception {

        Users user = new Users();
        user.setUserName("test");

        when(userRepository.getByUserName("test")).thenReturn(Optional.of(user));

        mockMvc.perform(put("/auth/unlock/test"))
                .andExpect(status().isOk())
                .andExpect(content().string("Account unlocked for test"));

        verify(userRepository).updateUser(any());
    }

 
    @Test
    @WithMockUser(roles = "USER")
    void testUnlockForbidden() throws Exception {

        try {
            mockMvc.perform(put("/auth/unlock/test"));
        } catch (Exception e) {
            assert(e.getCause() instanceof
                    org.springframework.security.authorization.AuthorizationDeniedException);
        }
    }


    @Test
    void testPublicEndpoint() throws Exception {

        mockMvc.perform(get("/auth/test"))
                .andExpect(status().isOk())
                .andExpect(content().string("TEST WORKING"));
    }

    @Test
    void testHome() throws Exception {

        mockMvc.perform(get("/auth/"))
                .andExpect(status().isOk())
                .andExpect(content().string("Home Page"));
    }


    @Test
    void testOAuthUserNotAuthenticated() throws Exception {

        mockMvc.perform(get("/auth/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User not authenticated"));
    }


    @Test
    @WithMockUser
    void testOAuthUserAuthenticated() throws Exception {

        mockMvc.perform(get("/auth/user"))
                .andExpect(status().isOk());
    }
}
