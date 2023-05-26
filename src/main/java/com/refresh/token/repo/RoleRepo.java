package com.refresh.token.repo;

import com.refresh.token.model.ERole;
import com.refresh.token.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepo extends JpaRepository<Role,Long> {
    Optional<Role> findByName(ERole name);

}
