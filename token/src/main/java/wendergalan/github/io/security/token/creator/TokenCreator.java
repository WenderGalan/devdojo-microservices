package wendergalan.github.io.security.token.creator;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import wendergalan.github.io.core.model.ApplicationUser;
import wendergalan.github.io.core.property.JwtConfiguration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {
    private final JwtConfiguration jwtConfiguration;

    /**
     * Assina o token
     * @param auth
     * @return
     */
    @SneakyThrows
    public SignedJWT createSignedJWT(Authentication auth) {
        log.info("Starting to create the signed JWT");

        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();

        // Gera as claims
        JWTClaimsSet jwtClainSet = createJWTClainSet(auth, applicationUser);

        // Gera o par de chaves (pública e privada)
        KeyPair rsaKeys = generateKeyPair();

        log.info("Building JWK from the RSA Keys");

        // Gera JSON Web Key a partir da chave pública
        JWK jwk = new RSAKey
                .Builder((RSAPublicKey) rsaKeys.getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        // Gera o Token para ser assinado, passando a chave pública no header e informa o algoritmo, o tipo do objeto e o claimset.
        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClainSet);

        log.info("Signing the token with the private RSA Key");

        // Assina o token usado a chave privada
        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());

        signedJWT.sign(signer);

        // Retorna o token assinado ( ainda falta fazer a criptografia)
        log.info("Serialize token '{}'", signedJWT.serialize());
        return signedJWT;
    }

    /**
     * Monta o ClaimSet do Token
     * @param auth
     * @param applicationUser
     * @return
     */
    private JWTClaimsSet createJWTClainSet(Authentication auth, ApplicationUser applicationUser) {
        log.info("Creating the JwtClaimSet Object for '{}'", applicationUser.toString());

        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList()))
                .issuer("https://wendergalan.github.io/")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    /**
     * Monta as chaves do Token
     * @return
     */
    @SneakyThrows
    private KeyPair generateKeyPair() {
        log.info("Generating RSA 2048 bits Keys");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.genKeyPair();
    }

    /**
     * Criptografar o token
     * @param signedJWT
     * @return
     * @throws JOSEException
     */
    public String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptToken method");

        // Vamos usar criptografia direta usando uma chave privada que está armazenada nas propriedades (JwtConfiguration)
        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));

        log.info("Encrypting token with system's private key");

        jweObject.encrypt(directEncrypter);

        log.info("Token encrypted");

        // Retorna o token criptografado e serializado (no formato de string)
        return jweObject.serialize();
    }
}
