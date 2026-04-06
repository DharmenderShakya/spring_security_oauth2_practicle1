package com.Spring_Security_oauth2_practicle1.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.Spring_Security_oauth2_practicle1.entity.Users;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {

	Optional<Users> findByUserName(String userName);
}
