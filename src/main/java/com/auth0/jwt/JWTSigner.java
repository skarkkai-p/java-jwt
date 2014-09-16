package com.auth0.jwt;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.OperationNotSupportedException;

import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * JwtSigner implementation based on the Ruby implementation from http://jwt.io
 * No support for RSA encryption at present
 */
public class JWTSigner {

    /**
     * Generate a JSON Web Token.
     * 
     * @param claims A map of the JWT claims that form the payload. Registered claims
     *               must be of appropriate Java datatype as following:
     *               <ul>
     *                  <li>iss, sub: String
     *                  <li>exp, nbf, iat, jti: numeric, eg. Long
     *                  <li>aud: String, or Collection<String>
     *               </ul>
     *               All claims with a null value are left out the JWT.
     * 
     * Non-registered claims are not inspected.
     */
    public String encode(Map<String, Object> claims, String key, Algorithm algorithm) {
        List<String> segments = new ArrayList<String>();

        try {
            segments.add(encodedHeader(algorithm));
            segments.add(encodedPayload(claims));
            segments.add(encodedSignature(join(segments, "."), key, algorithm));
        } catch (Exception e) {
            throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
        }

        return join(segments, ".");
    }

    /**
     * Generate a JSON Web Token using the default algorithm HMAC SHA-256 ("HS256").
     * 
     * For details, see the three parameter variant of this method.
     */
    public String encode(Map<String, Object> claims, String key) {
        return encode(claims, key, Algorithm.HS256);
    }

    /**
     * Generate the header part of a JSON web token.
     */
    private String encodedHeader(Algorithm algorithm) throws UnsupportedEncodingException {
        if (algorithm == null) { // default the algorithm if not specified
            algorithm = Algorithm.HS256;
        }

        // create the header
        ObjectNode header = JsonNodeFactory.instance.objectNode();
        header.put("type", "JWT");
        header.put("alg", algorithm.name());

        return base64UrlEncode(header.toString().getBytes("UTF-8"));
    }

    /**
     * Generate the JSON web token payload string from the claims.
     */
    private String encodedPayload(Map<String, Object> _claims) throws Exception {
        Map<String, Object> claims = new HashMap<String, Object>(_claims);
        enforceStringOrURI(claims, "iss");
        enforceStringOrURI(claims, "sub");
        enforceStringOrURICollection(claims, "aud");
        enforceIntDate(claims, "exp");
        enforceIntDate(claims, "nbf");
        enforceIntDate(claims, "iat");
        enforceString(claims, "jti");

        String payload = new ObjectMapper().writeValueAsString(claims);
        return base64UrlEncode(payload.getBytes("UTF-8"));
    }

    private void enforceIntDate(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof Number)) {
            throw new RuntimeException(String.format("Claim '%s' is invalid: must be an instance of Number", claimName));
        }
        long longValue = ((Number) value).longValue();
        if (longValue < 0)
            throw new RuntimeException(String.format("Claim '%s' is invalid: must be non-negative", claimName));
        claims.put(claimName, longValue);
    }

    private void enforceStringOrURICollection(Map<String, Object> claims, String claimName) {
        Object values = handleNullValue(claims, claimName);
        if (values == null)
            return;
        if (values instanceof Collection) {
            @SuppressWarnings({ "unchecked" })
            Iterator<Object> iterator = ((Collection<Object>) values).iterator();
            while (iterator.hasNext()) {
                Object value = iterator.next();
                String error = checkStringOrURI(value);
                if (error != null)
                    throw new RuntimeException(String.format("Claim 'aud' element is invalid: %s", error));
            }
        } else {
            enforceStringOrURI(claims, "aud");
        }
    }

    private void enforceStringOrURI(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        String error = checkStringOrURI(value);
        if (error != null)
            throw new RuntimeException(String.format("Claim '%s' is invalid: %s", claimName, error));
    }

    private void enforceString(Map<String, Object> claims, String claimName) {
        Object value = handleNullValue(claims, claimName);
        if (value == null)
            return;
        if (!(value instanceof String))
            throw new RuntimeException(String.format("Claim '%s' is invalid: not a string", claimName));
    }

    private Object handleNullValue(Map<String, Object> claims, String claimName) {
        if (! claims.containsKey(claimName))
            return null;
        Object value = claims.get(claimName);
        if (value == null) {
            claims.remove(claimName);
            return null;
        }
        return value;
    }

    private String checkStringOrURI(Object value) {
        if (!(value instanceof String))
            return "not a string";
        String stringOrUri = (String) value;
        if (!stringOrUri.contains(":"))
            return null;
        try {
            new URI(stringOrUri);
        } catch (URISyntaxException e) {
            return "not a valid URI";
        }
        return null;
    }
    
    /**
     * Sign the header and payload
     */
    private String encodedSignature(String signingInput, String key, Algorithm algorithm) throws Exception {
        byte[] signature = sign(algorithm, signingInput, key);
        return base64UrlEncode(signature);
    }

    /**
     * Safe URL encode a byte array to a String
     */
    private String base64UrlEncode(byte[] str) {
        return new String(Base64.encodeBase64URLSafe(str));
    }

    /**
     * Switch the signing algorithm based on input, RSA not supported
     */
    private byte[] sign(Algorithm algorithm, String msg, String key) throws Exception {
        switch (algorithm) {
        case HS256:
        case HS384:
        case HS512:
            return signHmac(algorithm, msg, key);
        case RS256:
        case RS384:
        case RS512:
        default:
            throw new OperationNotSupportedException("Unsupported signing method");
        }
    }

    /**
     * Sign an input string using HMAC and return the encrypted bytes
     */
    private byte[] signHmac(Algorithm algorithm, String msg, String key) throws Exception {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(new SecretKeySpec(key.getBytes(), algorithm.getValue()));
        return mac.doFinal(msg.getBytes());
    }

    private String join(List<String> input, String on) {
        int size = input.size();
        int count = 1;
        StringBuilder joined = new StringBuilder();
        for (String string : input) {
            joined.append(string);
            if (count < size) {
                joined.append(on);
            }
            count++;
        }

        return joined.toString();
    }
}
