package com.example.demo.oauth.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.example.demo.oauth.entity.Client;

public interface ClientRepository extends JpaRepository<Client, String> {
  Optional<Client> findByClientId(String clientId);
}
