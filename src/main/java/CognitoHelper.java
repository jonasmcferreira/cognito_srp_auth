import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentity.CognitoIdentityClient;
import software.amazon.awssdk.services.cognitoidentity.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

import static software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType.USER_SRP_AUTH;


public class CognitoHelper {

    private static final String HEX_N =
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    private static final BigInteger N = new BigInteger(HEX_N, 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k;
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = 16;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final String UTF8 = "UTF-8";
    private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
      new ThreadLocal<MessageDigest>() {
          @Override
          protected MessageDigest initialValue() {
              try {
                  return MessageDigest.getInstance("SHA-256");
              } catch (NoSuchAlgorithmException e) {
                  throw new SecurityException("Exception in authentication", e);
              }
          }
      };
    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(g.toByteArray());
            k = new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
    }

    private BigInteger a;
    private BigInteger A;

    private String POOL_ID;
    private String CLIENTAPP_ID;
    private String IDENTITY_POOL_ID;
    private Region REGION;

    public CognitoHelper(){

        // Read the property values
        POOL_ID = System.getenv("USER_POOL_ID");
        CLIENTAPP_ID = System.getenv("CLIENTAPP_ID");
        IDENTITY_POOL_ID = System.getenv("IDENTITY_POOL_ID");
        REGION = Region.of(System.getenv("REGION"));

        System.out.println("==================");
        System.out.println("User Pool     "+POOL_ID);
        System.out.println("ClientAppID   "+CLIENTAPP_ID);
        System.out.println("Identity pool "+IDENTITY_POOL_ID);
        System.out.println("==================");


        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
            A = g.modPow(a, N);
        } while (A.mod(N).equals(BigInteger.ZERO));

    }

    public String performSRPAuthentication(final String username, String password) throws UnsupportedEncodingException {

        CognitoIdentityProviderClient cognitoclient =
          CognitoIdentityProviderClient.builder()
            .region(Region.EU_CENTRAL_1)
            .build();

        Map<String, String> AuthParameters = new HashMap<>();

        AuthParameters.put("USERNAME", username);
        AuthParameters.put("SRP_A", A.toString(16));

        InitiateAuthResponse initiateAuthResponse = cognitoclient.initiateAuth(
          InitiateAuthRequest.builder()
            .authFlow(USER_SRP_AUTH)
            .clientId(CLIENTAPP_ID)
            .authParameters(AuthParameters)
            .build()
        );

        String userIdForSRP = initiateAuthResponse.challengeParameters().get("USER_ID_FOR_SRP");

        BigInteger B = new BigInteger(initiateAuthResponse.challengeParameters().get("SRP_B"), 16);
        if (B.mod(N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(initiateAuthResponse.challengeParameters().get("SALT"), 16);
        byte[] key = getPasswordAuthenticationKey(userIdForSRP, password, B, salt);

        Date timestamp = new Date();
        byte[] hmac = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            mac.update(POOL_ID.split("_", 2)[1].getBytes(UTF8));
            mac.update(userIdForSRP.getBytes(UTF8));
            byte[] secretBlock = Base64.getDecoder().decode(initiateAuthResponse.challengeParameters().get("SECRET_BLOCK"));
            mac.update(secretBlock);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            String dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(UTF8);
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            System.out.println(e);
        }

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", initiateAuthResponse.challengeParameters().get("SECRET_BLOCK"));
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", Base64.getEncoder().encodeToString(hmac));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put("USERNAME", initiateAuthResponse.challengeParameters().get("USERNAME"));

        final RespondToAuthChallengeResponse challengeResponse = cognitoclient.respondToAuthChallenge(
          RespondToAuthChallengeRequest.builder()
            .challengeName(initiateAuthResponse.challengeName())
            .clientId(CLIENTAPP_ID)
            .session(initiateAuthResponse.session())
            .challengeResponses(srpAuthResponses)
            .build()
        );

        return challengeResponse.authenticationResult().idToken();

    }

    private byte[] getPasswordAuthenticationKey(String userId,
                                                String userPassword,
                                                BigInteger B,
                                                BigInteger salt) throws UnsupportedEncodingException {
        // Authenticate the password
        // u = H(A, B)
        MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
        messageDigest.reset();
        messageDigest.update(A.toByteArray());
        BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }

        // x = H(salt | H(poolName | userId | ":" | password))
        messageDigest.reset();
        messageDigest.update(POOL_ID.split("_", 2)[1].getBytes(UTF8));
        messageDigest.update(userId.getBytes(UTF8));
        messageDigest.update(":".getBytes(UTF8));
        byte[] userIdHash = messageDigest.digest(userPassword.getBytes(UTF8));

        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

        HkdfHelper hkdf;
        try {
            hkdf = HkdfHelper.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
        hkdf.init(S.toByteArray(), u.toByteArray());
        byte[] key = hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
        return key;
    }

    public Credentials getTemporaryCredentials(final String jwtToken) {


        CognitoIdentityClient cognitoclient = CognitoIdentityClient.builder().region(Region.EU_CENTRAL_1).build();

        Map<String, String> logins = new HashMap<>();
        logins.put("cognito-idp."+REGION+".amazonaws.com/"+POOL_ID, jwtToken);

        GetIdResponse getIdResponse = cognitoclient.getId(
          GetIdRequest.builder()
            .identityPoolId(IDENTITY_POOL_ID)
            .logins(logins)
            .build()
        );

        GetCredentialsForIdentityResponse response = cognitoclient.getCredentialsForIdentity(
          GetCredentialsForIdentityRequest.builder()
            .identityId(getIdResponse.identityId())
            .logins(logins)
            .build()
        );

        System.out.println("a:"+response.credentials().accessKeyId());
        return response.credentials();

    }


}
