package onthelive.kr.authServer.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import onthelive.kr.authServer.entity.ClientEntity;
import onthelive.kr.authServer.model.Client;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UtilService {

    public HashMap getGetMappingParameters(HttpServletRequest httpRequest) {
        Map params = httpRequest.getParameterMap();
        Iterator it = params.keySet().iterator();

        HashMap result = new HashMap();

        while (it.hasNext()) {
            String key = (String) it.next();
            String value = ((String[]) params.get(key))[0];
            result.put(key, value);
        }

        return result;
    }

    public HashMap<String, String> decodeClientCredentials(String context) {
        String[] basic_s = context.split("Basic "); // Basic b2F1dGgtY2xpZW50LTE6b2F1dGgtY2xpZW50LXNlY3JldC0x
        byte[] decode = Base64.getDecoder().decode(basic_s[1]); // b2F1dGgtY2xpZW50LTE6b2F1dGgtY2xpZW50LXNlY3JldC0x
        String decoded = new String(decode); // oauth-client-1:oauth-client-secret-1

        String[] arr = decoded.split(":");

        String id = arr[0];
        String secret = arr[1];

        HashMap<String, String> result = new HashMap<>();
        result.put("id", id);
        result.put("secret", secret);

        return result;
    }

    public List getScopes(String scope) {
        return Arrays.asList(scope.split(" "));
    }

    public HashMap<String, String> getPayload(String serializedIdToken) throws JsonProcessingException {

        ObjectMapper objectMapper = new ObjectMapper();

        System.out.println("serializedIdToken = " + serializedIdToken);
        String payload = serializedIdToken.split("\\.")[1];
        System.out.println("payload = " + payload);
        byte[] decode = Base64.getDecoder().decode(payload.getBytes());
        String decodedPayload = new String(decode);
        System.out.println("decodedPayload = " + decodedPayload);

        HashMap<String, String> payloadMapper = objectMapper.readValue(decodedPayload, HashMap.class);
        return payloadMapper;
    }
}
