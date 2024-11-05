package Download;

import Models.User;
import Utils.DatabaseUtil;
import Utils.SecurityUtil;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import payload.request.KeyDownloadRequest;
import payload.request.KeyDownloadRequestParser;

import javax.crypto.SecretKey;
import java.io.*;

public class App implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final String bucketName = System.getenv("bucketName");
    private final String region = System.getenv("regionName");
    private final AmazonS3 s3Client = AmazonS3ClientBuilder
            .standard()
            .withRegion(region)
            .build();


    public APIGatewayProxyResponseEvent handleRequest(final APIGatewayProxyRequestEvent input, final Context context) {
        try {
            String username =input.getHeaders().get("username");
            String objectKey = username+"/keys.json";
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();

            String requestBody = input.getBody();
            KeyDownloadRequest keyDownloadRequest = KeyDownloadRequestParser.parseRequest(requestBody);
            User user = new User();
            DatabaseUtil databaseUtil = new DatabaseUtil();
            user = databaseUtil.findByUserName(username);
            if(user == null){
                return response
                        .withBody("Unable to Fetch User Details")
                        .withStatusCode(400);
            }
            if(!user.getKeysBackup()){
                return response
                        .withBody("User Backup doesn't exist!")
                        .withStatusCode(400);
            }
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            if (!passwordEncoder.matches(keyDownloadRequest.getPassword(), user.getPassword())) {
                return response
                        .withBody("Authentication failed!")
                        .withStatusCode(401);
            }
            String decryptionKey = keyDownloadRequest.getPassword();
            Boolean Encrypted = user.getBackupEncryption();

            S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
            String json="";
            if(Encrypted){
                byte[] encryptedData = s3Object.getObjectContent().readAllBytes();
                SecurityUtil securityUtil = new SecurityUtil();
                SecretKey secretKey = securityUtil.generateKey(decryptionKey);
                json = securityUtil.decrypt(encryptedData,secretKey);
//                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//                byte[] keyBytes = decryptionKey.getBytes();
//                SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
//                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
//
//
//                byte[] decryptedData = cipher.doFinal(encryptedData);
//                json = new String(decryptedData);
            }else{
                // Read the content of the object
                BufferedReader reader = new BufferedReader(new InputStreamReader(s3Object.getObjectContent()));
                StringBuilder content = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }

                // Close the reader
                reader.close();
                json=content.toString();
            }




            return response
                    .withBody(json)
                    .withStatusCode(200);
        } catch (IOException e) {
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            return response
                    .withBody("body+"+input.getBody()+"\n"+e.getMessage())
                    .withStatusCode(500);

        }catch (Exception e){
            APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
            return response
                    .withBody("body+"+input.getBody()+"\n"+e.getMessage())
                    .withStatusCode(500);
        }
    }

}

