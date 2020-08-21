package wendergalan.github.io.gateway.security.filter;

import com.netflix.zuul.context.RequestContext;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import org.springframework.lang.NonNull;
import wendergalan.github.io.core.property.JwtConfiguration;
import wendergalan.github.io.security.filter.JwtTokenAuthotizationFilter;
import wendergalan.github.io.security.token.creator.converter.TokenConverter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static wendergalan.github.io.security.util.SecurityContextUtil.setSecurityContext;

public class GatewayJwtTokenAuthorizationFilter extends JwtTokenAuthotizationFilter {

    public GatewayJwtTokenAuthorizationFilter(JwtConfiguration jwtConfiguration, TokenConverter tokenConverter) {
        super(jwtConfiguration, tokenConverter);
    }

    @Override
    @SneakyThrows
    @SuppressWarnings("Duplicates")
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader(jwtConfiguration.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfiguration.getHeader().getPrefix())) {
            chain.doFilter(request, response);
            return;
        }

        // Todas as requisições que o gateway recebe são do front-end ou externas e o token sempre virá criptografado...
        String token = header.replace(jwtConfiguration.getHeader().getPrefix(), "").trim();

        // Descriptografa
        String signedToken = tokenConverter.decryptToken(token);

        // Valida a assinatura
        tokenConverter.validateTokenSignature(signedToken);

        // Precisamos do securityContext para validar os Roles
        setSecurityContext(SignedJWT.parse(signedToken));

        // Se a propriedade tipo da configuração for signed (assinado), sobrescreve o header Authorization
        // Substitui o token que está criptografado por apenas um token assinado.
        if (jwtConfiguration.getType().equalsIgnoreCase("signed"))
            RequestContext.getCurrentContext().addZuulRequestHeader("Authorization", jwtConfiguration.getHeader().getPrefix() + signedToken);

        chain.doFilter(request, response);
    }
}
