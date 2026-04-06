package com.Spring_Security_oauth2_practicle1.service;

public interface LoginAttemptService {
	 void loginSucceeded(String username);
	 void loginFailed(String username);
}
