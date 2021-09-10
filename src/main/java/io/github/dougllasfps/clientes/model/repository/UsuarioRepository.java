package io.github.dougllasfps.clientes.model.repository;

import io.github.dougllasfps.clientes.model.entity.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
    Optional<Usuario> findByUsername(String username); // Optional porque o usuario pode nao existir - aí retorna um Optional vazio.
    
    // select count(*) > 0 from usuario where username = :login
    boolean existsByUsername(String username);
}
