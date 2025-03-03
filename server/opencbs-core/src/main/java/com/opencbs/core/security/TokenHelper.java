package com.opencbs.core.security;

import com.opencbs.core.domain.User;
import com.opencbs.core.domain.enums.SystemSettingsName;
import com.opencbs.core.helpers.DateHelper;
import com.opencbs.core.services.SystemSettingsService;
import com.opencbs.core.services.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.InvalidKeyException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.mail.Provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Created by Pavel Bastov on 12/01/2017.
 */
@Component
public class TokenHelper {

    private static final String ISSUER = "com.opencbs.core";

    private final SecretKeyProvider secretKeyProvider;

    private final UserService userService;

    private final SystemSettingsService systemSettingsService;


    @Autowired
    public TokenHelper(SecretKeyProvider secretKeyProvider,
                       UserService userService,
                       SystemSettingsService systemSettingsService) {
        this.secretKeyProvider = secretKeyProvider;
        this.userService = userService;
        this.systemSettingsService = systemSettingsService;
    }

    public String getUsernameFromToken(String token) {
        try {
            return this.getClaimsFromToken(token).getSubject();
        }
        catch (Exception e) {
            return null;
        }
    }

    public Boolean verifyToken(String token, User user) {
        final String username = this.getUsernameFromToken(token);
        if (username == null) return false;
        if (username.equals(user.getUsername()) && !IsSessionExpired(user)) {
            return true;
        }

        return false;
    }

    public String tokenFor(User user) {
        if (user == null) {
            throw new IllegalArgumentException("user cannot be null");
        }

        byte[] secretKey = this.secretKeyProvider.getKey();
        // TODO: For now the token does not expire, but down the road we should restrict its lifetime
        return Jwts.builder()
                .subject(user.getUsername())
                .issuer(ISSUER)
				.signWith(getKey(), Jwts.SIG.HS512)
                .compact();
    }

    private Claims getClaimsFromToken(String token) {
        try {
        	return Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(token).getPayload();
//            return Jwts.parser().setSigningKey(this.secretKeyProvider.getKey()).build().parseSignedClaims(token).getBody();
        } catch (Exception e) {
            return null;
        }
    }

    private SecretKey getKey() {
		try {
			return SecretKeyFactory.getInstance("AES").generateSecret(new X509EncodedKeySpec(this.secretKeyProvider.getKey()));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	private boolean IsSessionExpired(User user) {
        Integer minutes = Integer.valueOf(systemSettingsService.getValueByName(SystemSettingsName.EXPIRATION_SESSION_TIME_IN_MINUTES));
        if (minutes == 0) { // session never ended
            return false;
        }
        if (DateHelper.greater(DateHelper.getLocalDateTimeNow(), user.getLastEntryTime().plusMinutes(minutes))) {
            return true;
        }

        return false;
    }

    public void setEventInformation(User user) {
        user.setLastEntryTime(DateHelper.getLocalDateTimeNow());
        userService.update(user);
    }
}
