
  package io.github.dougllasfps.clientes.service;
  
  import
  org.springframework.beans.factory.annotation.Autowired;
import
  org.springframework.security.core.userdetails.User;
import
  org.springframework.security.core.userdetails.UserDetails;
import
  org.springframework.security.core.userdetails.UserDetailsService;
import
  org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.github.dougllasfps.clientes.exception.UsuarioCadastradoException;
import io.github.dougllasfps.clientes.model.entity.Usuario;
import
  io.github.dougllasfps.clientes.model.repository.UsuarioRepository;
  
  @Service 
  public class UsuarioService implements UserDetailsService {
  
	  @Autowired 
	  private UsuarioRepository repository;
		
	  public Usuario salvar(Usuario usuario){ 
		  boolean exists = repository.existsByUsername(usuario.getUsername()); 
		  if(exists){ 
			  throw new UsuarioCadastradoException(usuario.getUsername()); 
		  } return repository.save(usuario); 
	  }
		 
	  
	  @Override 
	  public UserDetails loadUserByUsername( String username ) throws UsernameNotFoundException { 
		  Usuario usuario = repository
				  				.findByUsername(username) 
				  				.orElseThrow(() -> new UsernameNotFoundException("Login não encontrado.") );
		  
		  /* Para definir se será admin
		   String[] roles = usuario.isAdmin() ?
		   			new String[] {"ADMIN", "USER"} : new String[]{"USER"};
		   */
  
		  return User 
				  .builder() 
				  .username(usuario.getUsername())
				  .password(usuario.getPassword()) // Aqui não precisa encriptar porque a senha já está assim no banco de dados
				  .roles("USER") // (roles)
				  .build(); 
	  } 
  }
 