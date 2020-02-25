package com.androj.springangularauth.security.authentication;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

public interface UserRepository extends CrudRepository<User,Long> {

    User findByLogin(String login);
}
