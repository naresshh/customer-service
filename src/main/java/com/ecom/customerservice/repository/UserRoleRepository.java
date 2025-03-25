package com.ecom.customerservice.repository;


import com.ecom.customerservice.modal.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleRepository extends JpaRepository<UserRole, Long> {
}