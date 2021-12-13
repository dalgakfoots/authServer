package onthelive.kr.authServer.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RsaKeyGenerator {

    @Bean
    public RSAKey initRsaKey() throws JOSEException {
        RSAKey rsakey = new RSAKeyGenerator(2048)
                .keyID("onTheLive.kr")
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        return rsakey;
    }

}
