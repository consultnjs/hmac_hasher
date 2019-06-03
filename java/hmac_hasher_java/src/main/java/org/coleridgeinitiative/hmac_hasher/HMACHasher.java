// package declaration
package org.coleridgeinitiative.hmac_hasher;

// imports - java
import java.io.UnsupportedEncodingException;
// import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
// import javax.xml.bind.DatatypeConverter; // requires --add-modules java.se.ee

// imports - apache commons codec
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

/**
 * HMACHasher example!
 *
 */
public class HMACHasher 
{

    //=======================================================================//
    // static methods
    //=======================================================================//

   
    public static String builtinSHA256Hash( String msg_IN, String encoding_IN )
    {
        /**
         * Non-apache commons HMAC method from http://www.supermind.org/blog/1102/generating-hmac-md5-sha1-sha256-etc-in-java
         * - originally from: https://stackoverflow.com/questions/8396297/android-how-to-create-hmac-md5-string/8396600#8396600
         */

        // return reference
        String value_OUT = null;
        
        // declare variables
        MessageDigest hasher_instance = null;
        byte[] hashed_bytes = null;
        String hashed_hex = null;
        String encoding_charset = null;

        // got an encoding?
        if ( ( encoding_IN == null ) || ( encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encoding_charset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encoding_charset = encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // make hasher instance
            hasher_instance = MessageDigest.getInstance( "SHA-256" );
            
            // hash the value
            hashed_bytes = hasher_instance.digest( msg_IN.getBytes( encoding_charset ) );

            // convert the bytes to hex
            hashed_hex = HMACHasher.bytesToHex( hashed_bytes, true );

        }
        catch ( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try-catch block --//

        value_OUT = hashed_hex;
        
        return value_OUT;

    } //-- END static method builtinSHA256Hash --//


    public static String bytesToHex( byte[] bytes_to_convert_IN, boolean toLowerCase_IN )
    {

        /**
         * Accepts byte array.  Returns digest of those bytes converted to a
         *     hexidecimal string.
         *
         * More details, see: https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/binary/Hex.html
         */

        // return reference
        String value_OUT = null;

        // just use org.apache.commons.codec.binary.Hex
        value_OUT = Hex.encodeHexString( bytes_to_convert_IN, toLowerCase_IN );

        //Manual
        /*
        // declare variables
        StringBuffer hex_buffer = null;
        int byte_index = -1;
        String byte_hex = null;

        // make StringBuffer to hold hash.
        hex_buffer = new StringBuffer();
          
        // convert bytes to hex string.
        for ( byte_index = 0; byte_index < bytes_to_convert_IN.length; byte_index++ )
        {
            // convert the byte to a hhex string.
            byte_hex = Integer.toHexString( 0xFF & bytes_to_convert_IN[ byte_index ] );
            
            // if length 1, append "0"
            if ( byte_hex.length() == 1 )
            {
                hex_buffer.append( '0' );
            }
                
            // append the hex value for the byte to the hash output.
            hex_buffer.append( byte_hex );
        
        } //-- end loop over bytes --//
          
        // convert the hash to a string.
        value_OUT = hex_buffer.toString();
         */

        return value_OUT;

    } //-- END static method bytesToHex() --//
    

    public static String commonsHMACDigest( String msg_IN, String keyString_IN, HmacAlgorithms algo_IN, String message_encoding_IN )
    {
        /**
         * apache commons HMAC method from https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/digest/HmacUtils.html
         */

        // return reference
        String value_OUT = null;
        
        // declare variables
        String encoding_charset = null;
        String key_hash = null;
        byte[] key_bytes = null;
        String hash_output = null;
        HmacUtils hmac_instance = null;

        // got an encoding?
        if ( ( message_encoding_IN == null ) || ( message_encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encoding_charset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encoding_charset = message_encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // get SHA256 hash of key/secret encoded as UTF-8...
            key_hash = HMACHasher.builtinSHA256Hash( keyString_IN, "UTF-8" );
            System.out.println( "key hash = " + key_hash );

            // ...then convert key to bytes.
            //key_bytes = key_hash.getBytes( StandardCharsets.UTF_8 );
            key_bytes = HMACHasher.hexToBytes( key_hash );


            // then, create HMAC instance...
            // HmacUtils hm1 = new HmacUtils("HmacAlgoName", key); // use a valid name here!
            hmac_instance = new HmacUtils( algo_IN, key_bytes );

            // ...and use it to hash.
            hash_output = hmac_instance.hmacHex( msg_IN );

        }
        catch ( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try-catch block --//

        value_OUT = hash_output;
        
        return value_OUT;

    } //-- END static method commonsHMACDigest


    public static byte[] hexToBytes( String hex_to_convert_IN )
    {

        /**
         * Accepts byte array.  Returns digest of those bytes converted to a
         *     hexidecimal string.
         * More details, see: https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/binary/Hex.html
         */

        // return reference
        byte[] value_OUT = null;

        // declare variables

        try
        {

            // convert.
            value_OUT = Hex.decodeHex( hex_to_convert_IN );

        }
        catch( DecoderException de )
        {
            System.out.println( "Caught DecoderException: " + de.toString() );
        } //-- END try...catch --//
        catch( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try...catch --//

        return value_OUT;

    } //-- END static method hexToBytes() --//
    

    public static String javaxCryptoHMACDigest( String msg_IN, String keyString_IN, String algo_IN, String encoding_IN )
    {
        /**
         * Non-apache commons HMAC method from http://www.supermind.org/blog/1102/generating-hmac-md5-sha1-sha256-etc-in-java
         * - originally from: https://stackoverflow.com/questions/8396297/android-how-to-create-hmac-md5-string/8396600#8396600
         */

        // return reference
        String value_OUT = null;
        
        // declare variables
        String key_hash = null;
        byte[] key_bytes = null;
        SecretKeySpec key = null;
        String digest = null;
        String encoding_charset = null;
        Mac hmac_instance = null;
        byte[] bytes = null;

        // got an encoding?
        if ( ( encoding_IN == null ) || ( encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encoding_charset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encoding_charset = encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // get SHA256 hash of key/secret encoded as UTF-8...
            key_hash = HMACHasher.builtinSHA256Hash( keyString_IN, "UTF-8" );
            System.out.println( "key hash = " + key_hash );

            // ...then convert key to bytes.
            //key_bytes = key_hash.getBytes( StandardCharsets.UTF_8 );
            key_bytes = HMACHasher.hexToBytes( key_hash );

            // create SecretKeySpec and HMAC instance.    
            key = new SecretKeySpec( key_bytes, algo_IN );
            hmac_instance = Mac.getInstance( algo_IN );
            hmac_instance.init( key );
    
            // get bytes of message to hash
            bytes = hmac_instance.doFinal( msg_IN.getBytes( encoding_charset ) );
    
            // convert bytes to Hex
            digest = HMACHasher.bytesToHex( bytes, true );

        }
        catch ( UnsupportedEncodingException uee )
        {
            System.out.println( "Caught UnsupportedEncodingException: " + uee.toString() );
        }
        catch (InvalidKeyException ike)
        {
            System.out.println( "Caught InvalidKeyException: " + ike.toString() );
        }
        catch ( NoSuchAlgorithmException nsae )
        {
            System.out.println( "Caught NoSuchAlgorithmException: " + nsae.toString() );
        } //-- END try-catch block --//

        value_OUT = digest;
        
        return value_OUT;

    } //-- END static method javaxCryptoHMACDigest --//


    //=======================================================================//
    // static main method
    //=======================================================================//


    public static void main( String[] args )
    {

        // declare variables
        String message = null;
        String key = null;
        String algorithm_string = null;
        HmacAlgorithms algorithm_instance = null;
        String encoding = null;
        String javaxCryptoDigest = null;
        String commonsDigest = null;

        System.out.println( "Java HMACHasher example!" );

        key = "fakedata";
        message = "123456789";

        // set standard name (https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html) of HMAC algorithm.
        algorithm_string = "HmacSHA256";
        
        // set the Apache commons codec instance for HMAC SHA 256.
        algorithm_instance = HmacAlgorithms.HMAC_SHA_256;
        encoding = "UTF-8";

        // try the javax.crypto method
        javaxCryptoDigest = HMACHasher.javaxCryptoHMACDigest( message, key, algorithm_string, encoding );
        System.out.println( "Manual output: " + javaxCryptoDigest );

        // try the commons method
        commonsDigest = HMACHasher.commonsHMACDigest( message, key, algorithm_instance, encoding );
        System.out.println( "Commons output: " + commonsDigest );

    }

    
} //-- end class HMACHasher --//
