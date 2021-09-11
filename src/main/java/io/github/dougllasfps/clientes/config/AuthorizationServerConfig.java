package io.github.dougllasfps.clientes.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
    @Autowired
    private AuthenticationManager authenticationManager;
    
    // Adicionado para criptografar a senha do cliente
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    // Esse trecho não é usado com o Token InMemory  
    @Value("${security.jwt.signing-key}") 
	private String signingKey;
	  
	@Bean 
	public TokenStore tokenStore(){ 
	 return new JwtTokenStore(accessTokenConverter()); // Esse token precisa de um AccessTokenConverter
	//return new InMemoryTokenStore();
	}
		
	// Esse trecho não é usado com o Token InMemory
	@Bean 
	public JwtAccessTokenConverter accessTokenConverter(){
	JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
	tokenConverter.setSigningKey(signingKey); // Definindo qual é a chave de assinatura
	return tokenConverter; 
	}
	  
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
            .tokenStore(tokenStore())
            .accessTokenConverter(accessTokenConverter()) // Esse trecho não é usado com o Token InMemory
            .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception { // clients são os clientes, a aplicação Angular
    	
    	String senhaCriptografada = passwordEncoder.encode("@321");
    	
		clients
            .inMemory()
            .withClient("my-angular-app") // Aplicação Angular - client-id
            //.secret("@321") // client-secret
            .secret(senhaCriptografada)
            //.secret("$2a$10$L0YMyhhL6X1u/aWnq6kdie9LlIib9KBOYqq7RNrMXDPMvfDWZy7ty") // Senha @321 criptografada
            .scopes("read", "write")
            .authorizedGrantTypes("password")
            .accessTokenValiditySeconds(1800); // = 30 min
    }
}
