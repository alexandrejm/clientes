package io.github.dougllasfps.clientes.config;

//import io.github.dougllasfps.clientes.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

import io.github.dougllasfps.clientes.service.UsuarioService;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	  @Autowired 
	  private UsuarioService usuarioService;
	  
	  @Bean
	  public PasswordEncoder passwordEncoder(){
	      return new BCryptPasswordEncoder();
	  }
	  
	  @Override 
	  public void configure(AuthenticationManagerBuilder auth) throws Exception { 
		  auth 
		  	.userDetailsService(usuarioService)
		  	.passwordEncoder(passwordEncoder());
	  }
	  
	  /*
	  @Bean 
	  public PasswordEncoder passwordEncoder(){ 
		  return NoOpPasswordEncoder.getInstance(); // esse não altera a senha. Irá usar a senha original do usuário.
	  }
	  */
	   
	 
		/*
		 @Override 
		 public void configure(AuthenticationManagerBuilder auth) throws Exception { 
		 	auth
		 		.inMemoryAuthentication() 
		 		.withUser("fulano") // Esse é o usuário da aplicação. Aqui só terá um, pq configuramos em memória.
		 		.password("123") 
		 		.roles("USER"); 
		 }
		 */
	
	@Bean 
	public AuthenticationManager authenticationManager() throws Exception {
		 return super.authenticationManager(); 
	}
	
	// Para permitir o acesso ao h2-console
	@Override
	public void configure(WebSecurity web) throws Exception {
		web
			.ignoring()
			.antMatchers("/h2-console/**");
	}
	
	@Override 
	protected void configure(HttpSecurity http) throws Exception { 
		http
		  .csrf().disable() // isso não usa em apis, apenas aplicações web
		  .cors() 
		.and()
		  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // A aplicação não irá guardar sessão. O token fará isso.
		
		//http.headers().frameOptions().disable(); // Isso era para permitir o h2-console, mas não funcionou
	}
	 
}
