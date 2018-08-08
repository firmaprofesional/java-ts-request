package com.firmaprofesional.snippet.TSRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

/**
 *
 * @author Firmaprofesional
 */
public class TSRequest {

    static String tsaServer = "http://urlProvidedByFirmaprofesional";
    
    static String username = null;
    static String password = null;
    private final URL url;
    private final MessageDigest digest;
    private static final Logger LOG = Logger.getLogger(TSRequest.class.getName());

    /**
     * Metodo principal para ejecutar la clase
     *
     * @param args
     */
    public static void main(String[] args) {

        String testToHash = "TSA Request snippet";
        String algorithm = "SHA-256";
        try {
            TSRequest tsp = new TSRequest(algorithm);
            TimeStampToken tst = tsp.getTimeStampToken(testToHash.getBytes());
            LOG.log(Level.INFO, "Timestamp from response: {0}", tst.getTimeStampInfo().getGenTime());
        } catch (IOException | TSPException | NoSuchAlgorithmException e) {
            LOG.severe(e.getMessage());
        }
    }
    
    /**
     * TSRequest construct
     * @param algorithm
     * @throws MalformedURLException
     * @throws NoSuchAlgorithmException 
     */
    public TSRequest(String algorithm) throws MalformedURLException, NoSuchAlgorithmException {
        url = new URL(tsaServer);
        digest = MessageDigest.getInstance(algorithm);
    }
    
    /**
     * Metodo para obtener token
     *
     * @param messageImprint
     * @return
     * @throws IOException
     * @throws TSPException
     */
    public TimeStampToken getTimeStampToken(byte[] messageImprint) throws IOException, TSPException {
        digest.reset();
        byte[] hash = digest.digest(messageImprint);

        // 32-bit cryptographic nonce
        SecureRandom random = new SecureRandom();
        int nonce = random.nextInt();

        // generate TSA request
        LOG.info("Genrating TSARequest");
        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = getHashObjectIdentifier(digest.getAlgorithm());
        TimeStampRequest request = tsaGenerator.generate(oid, hash, BigInteger.valueOf(nonce));

        // get TSA response
        LOG.info("Sending TSARequest to TSA server");
        TimeStampResponse response = sendPost(request.getEncoded());
        
        // validate TSA response
        LOG.info("Validating TSA response");
        response.validate(request);

        TimeStampToken token = response.getTimeStampToken();

        if (token == null) {
            throw new IOException("Response has not a valid timestamp token");
        }

        return token;
    }

    /**
     * Metodo que obtiene la respuesta de la TSA
     *
     * @param request
     * @return
     * @throws IOException
     * @throws TSPException
     */
    private TimeStampResponse sendPost(byte[] request) throws IOException, TSPException {

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setDoInput(true);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("Accept", "application/timestamp-reply");
        connection.setRequestProperty("Content-Length", "2048");

        if (username != null && password != null) {
            if (!username.isEmpty() && !password.isEmpty()) {
                String auth = username + ":" + password;
                connection.setRequestProperty("Authorization", "Basic " + DatatypeConverter.printBase64Binary(auth.getBytes()));
            }
        }

        OutputStream output = connection.getOutputStream();
        output.write(request);
        
        InputStream input = connection.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = 0;
        while ((bytesRead = input.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, bytesRead);
        }
        
        LOG.log(Level.INFO, "Http response code: {0}", connection.getResponseCode());
        
        byte[] respBytes = baos.toByteArray();
        TimeStampResponse resp = new TimeStampResponse(respBytes);

        return resp;
    }

    /**
     * Metodo para obtener el ObjectIdentifier de acuerdo al algoritmo
     *
     * @param algorithm
     * @return
     */
    private ASN1ObjectIdentifier getHashObjectIdentifier(String algorithm) {
        switch (algorithm) {
            case "SHA-1":
                return new ASN1ObjectIdentifier("1.3.14.3.2.26");
            case "SHA-256":
                return new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
            default:
                return new ASN1ObjectIdentifier(algorithm);
        }
    }
}
