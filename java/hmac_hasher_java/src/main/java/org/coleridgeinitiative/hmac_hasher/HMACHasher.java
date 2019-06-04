// package declaration
package org.coleridgeinitiative.hmac_hasher;

// imports - base java
import java.util.Map;
import java.util.HashMap;

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
    // static variables
    //=======================================================================//


    // debug flag
    public static boolean debugFlag = false;

    // based on https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/digest/HmacAlgorithms.html#HMAC_SHA_256
    public static Map<String, String> m_javaToCommonsAlgoNameMap = new HashMap<String, String>();
    static{
        m_javaToCommonsAlgoNameMap.put( "HmacMD5", "HMAC_MD5" );
        m_javaToCommonsAlgoNameMap.put( "HmacSHA1", "HMAC_SHA_1" );
        m_javaToCommonsAlgoNameMap.put( "HmacSHA224", "HMAC_SHA_224" );
        m_javaToCommonsAlgoNameMap.put( "HmacSHA256", "HMAC_SHA_256" );
        m_javaToCommonsAlgoNameMap.put( "HmacSHA384", "HMAC_SHA_384" );
        m_javaToCommonsAlgoNameMap.put( "HmacSHA512", "HMAC_SHA_512" );
    }


    //=======================================================================//
    // instance variables
    //=======================================================================//


    private byte[] m_keyBytes = null;
    private String m_keyString = null;
    private String m_HMACAlgorithmString = null;
    private HmacAlgorithms m_HMACCodecAlgorithmInstance = null;
    private String m_encodingString = null;
    private HmacUtils m_hmacUtilsInstance = null;

   
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
        MessageDigest hasherInstance = null;
        byte[] hashedBytes = null;
        String hashedHex = null;
        String encodingCharset = null;

        // got an encoding?
        if ( ( encoding_IN == null ) || ( encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encodingCharset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encodingCharset = encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // make hasher instance
            hasherInstance = MessageDigest.getInstance( "SHA-256" );
            
            // hash the value
            hashedBytes = hasherInstance.digest( msg_IN.getBytes( encodingCharset ) );

            // convert the bytes to hex
            hashedHex = HMACHasher.bytesToHex( hashedBytes, true );

        }
        catch ( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try-catch block --//

        value_OUT = hashedHex;
        
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
        String encodingCharset = null;
        String keyHash = null;
        byte[] keyBytes = null;
        String hashOutput = null;
        HmacUtils hmacInstance = null;

        // got an encoding?
        if ( ( message_encoding_IN == null ) || ( message_encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encodingCharset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encodingCharset = message_encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // get SHA256 hash of key/secret encoded as UTF-8...
            keyHash = HMACHasher.builtinSHA256Hash( keyString_IN, "UTF-8" );

            if ( HMACHasher.debugFlag == true )
            {
                System.out.println( "key hash = " + keyHash );
            }

            // ...then convert key to bytes.
            //key_bytes = key_hash.getBytes( StandardCharsets.UTF_8 );
            keyBytes = HMACHasher.hexToBytes( keyHash );


            // then, create HMAC instance...
            // HmacUtils hm1 = new HmacUtils("HmacAlgoName", key); // use a valid name here!
            hmacInstance = new HmacUtils( algo_IN, keyBytes );

            // ...and use it to hash.
            hashOutput = hmacInstance.hmacHex( msg_IN );

        }
        catch ( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try-catch block --//

        value_OUT = hashOutput;
        
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
        String keyHash = null;
        byte[] keyBytes = null;
        SecretKeySpec secret = null;
        String digest = null;
        String encodingCharset = null;
        Mac hmacInstance = null;
        byte[] bytes = null;

        // got an encoding?
        if ( ( encoding_IN == null ) || ( encoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encodingCharset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encodingCharset = encoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // get SHA256 hash of key/secret encoded as UTF-8...
            keyHash = HMACHasher.builtinSHA256Hash( keyString_IN, "UTF-8" );
            if ( HMACHasher.debugFlag == true )
            {
                System.out.println( "key hash = " + keyHash );
            }

            // ...then convert key to bytes.
            //key_bytes = key_hash.getBytes( StandardCharsets.UTF_8 );
            keyBytes = HMACHasher.hexToBytes( keyHash );

            // create SecretKeySpec and HMAC instance.    
            secret = new SecretKeySpec( keyBytes, algo_IN );
            hmacInstance = Mac.getInstance( algo_IN );
            hmacInstance.init( secret );
    
            // get bytes of message to hash
            bytes = hmacInstance.doFinal( msg_IN.getBytes( encodingCharset ) );
    
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
    // constructor
    //=======================================================================//


    public HMACHasher()
    {
        // call parent constructor.
        super();

        // init instance variables.
        this.m_keyBytes = null;
        this.m_keyString = null;
        this.m_HMACAlgorithmString = null;
        this.m_HMACCodecAlgorithmInstance = null;
        this.m_encodingString = null;
        this.m_hmacUtilsInstance = null;
    }

   
    //=======================================================================//
    // isntance methods
    //=======================================================================//


    public HmacAlgorithms getHMACCodecAlgorithmInstance()
    {
        // return reference
        HmacAlgorithms value_OUT = null;

        // return value
        value_OUT = this.m_HMACCodecAlgorithmInstance;

        return value_OUT;
    } //-- END method getHMACCodecAlgorithmInstance() --//


    public String getHMACAlgorithmString()
    {
        // return reference
        String value_OUT = null;

        // return value
        value_OUT = this.m_HMACAlgorithmString;

        return value_OUT;
    } //-- END method getHMACAlgorithmString() --//


    public HmacUtils getHmacUtilsInstance()
    {
        // return reference
        HmacUtils value_OUT = null;

        // ...and store it.
        value_OUT = this.m_hmacUtilsInstance;

        return value_OUT;
    } //-- END method initHmacUtilsInstance() --//


    public byte[] getKeyBytes()
    {
        // return reference
        byte[] value_OUT = null;

        // return value
        value_OUT = this.m_keyBytes;

        return value_OUT;
    } //-- END method getKeyBytes() --//


    public String getKeyString()
    {
        // return reference
        String value_OUT = null;

        // return value
        value_OUT = this.m_keyString;

        return value_OUT;
    } //-- END method getKeyString() --//


    public String commonsHashString( String msg_IN, String messageEncoding_IN )
    {
        /**
         * apache commons HMAC method from https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/digest/HmacUtils.html
         */

        // return reference
        String value_OUT = null;
        
        // declare variables
        String encodingCharset = null;
        String hashOutput = null;
        HmacUtils hmacInstance = null;

        // got an encoding?
        if ( ( messageEncoding_IN == null ) || ( messageEncoding_IN.equals( "" ) ) )
        {

            // no encoding - default to UTF-8 (standard CHARSETS: https://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html)
            encodingCharset = "UTF-8";

        }
        else
        {
        
            // use encoding charset passed in.
            encodingCharset = messageEncoding_IN;
        
        } //-- END check to see if empty encoding --//
        
        try
        {
        
            // get HMAC instance
            hmacInstance = this.getHmacUtilsInstance();

            // ...and use it to hash.
            hashOutput = hmacInstance.hmacHex( msg_IN );

        }
        catch ( Exception e )
        {
            System.out.println( "Caught Exception: " + e.toString() );
        } //-- END try-catch block --//

        value_OUT = hashOutput;
        
        return value_OUT;

    } //-- END method commonsHashString() --//


    public HmacUtils initHmacUtilsInstance()
    {
        // return reference
        HmacUtils value_OUT = null;

        // declare variables
        HmacAlgorithms codecAlgorithmInstance = null;
        byte[] keyBytes = null;
        HmacUtils hmacInstance = null;

        // get what we need.
        codecAlgorithmInstance = this.getHMACCodecAlgorithmInstance();
        keyBytes = this.getKeyBytes();

        //System.out.println( "codecAlgorithmInstance = " + codecAlgorithmInstance );
        //System.out.println( "keyBytes = " + keyBytes );

        // then, create HMAC instance...
        // HmacUtils hm1 = new HmacUtils("HmacAlgoName", key); // use a valid name here!
        hmacInstance = new HmacUtils( codecAlgorithmInstance, keyBytes );

        // ...and store it.
        this.m_hmacUtilsInstance = hmacInstance;

        value_OUT = this.getHmacUtilsInstance();

        return value_OUT;
    } //-- END method initHmacUtilsInstance() --//


    public HmacAlgorithms setHMACCodecAlgorithmInstance( HmacAlgorithms value_IN )
    {
        // return reference
        HmacAlgorithms value_OUT = null;

        // set value
        this.m_HMACCodecAlgorithmInstance = value_IN;

        // return value
        value_OUT = this.getHMACCodecAlgorithmInstance();

        return value_OUT;
    } //-- END method setHMACCodecAlgorithmInstance() --//

   
    public String setHMACAlgorithmString( String value_IN )
    {
        // return reference
        String value_OUT = null;

        // declare variables
        String codecAlgorithmString = null;
        HmacAlgorithms codecAlgorithmInstance = null;

        // set value
        this.m_HMACAlgorithmString = value_IN;

        // return value
        value_OUT = this.getHMACAlgorithmString();

        // look up apache.org.commons.codec name for this algorithm.
        codecAlgorithmString = this.m_javaToCommonsAlgoNameMap.getOrDefault( value_OUT, null );

        if ( codecAlgorithmString != null )
        {
            // load and populate the commons.codec algorithm instance.
            codecAlgorithmInstance = HmacAlgorithms.valueOf( codecAlgorithmString );
            this.setHMACCodecAlgorithmInstance( codecAlgorithmInstance );
        }

        return value_OUT;
    } //-- END method setKeyString() --//

   
    public byte[] setKeyBytes( byte[] value_IN )
    {
        // return reference
        byte[] value_OUT = null;

        // set value
        this.m_keyBytes = value_IN;

        // return value
        value_OUT = this.getKeyBytes();

        return value_OUT;
    } //-- END method setKeyBytes() --//

   
    public String setKeyString( String value_IN )
    {
        // return reference
        String value_OUT = null;

        // declare variables
        String key_hash = null;
        byte[] key_bytes = null;

        // set value
        this.m_keyString = value_IN;

        // get SHA256 hash of key/secret encoded as UTF-8...
        key_hash = HMACHasher.builtinSHA256Hash( value_IN, "UTF-8" );
        if ( HMACHasher.debugFlag == true )
        {
            System.out.println( "key hash = " + key_hash );
        }

        // ...then convert key to bytes.
        //key_bytes = key_hash.getBytes( StandardCharsets.UTF_8 );
        key_bytes = HMACHasher.hexToBytes( key_hash );

        // and store it.
        this.setKeyBytes( key_bytes );

        // return value
        value_OUT = this.getKeyString();

        return value_OUT;
    } //-- END method setKeyString() --//

   
    //=======================================================================//
    // static main method
    //=======================================================================//


    public static void main( String[] args )
    {

        // declare variables
        String message = null;
        String key = null;
        String expectedResult = null;
        String algorithmString = null;
        HmacAlgorithms algorithmInstance = null;
        String encoding = null;
        String javaxCryptoDigest = null;
        String commonsDigest = null;
        HMACHasher myHasherInstance = null;
        String instanceDigest = null;

        System.out.println( "Java HMACHasher example!" );

        key = "fakedata";
        message = "123456789";
        expectedResult = "a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0";

        System.out.println( "- key: " + key );
        System.out.println( "- message: " + message );
        System.out.println( "- expected_result: " + expectedResult );
        System.out.println();

        // set standard name (https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html) of HMAC algorithm.
        
        // encoding.
        encoding = "UTF-8";

        //-------------------------------------------------------------------//
        // try the javax.crypto method
        //-------------------------------------------------------------------//

        algorithmString = "HmacSHA256";
        javaxCryptoDigest = HMACHasher.javaxCryptoHMACDigest( message, key, algorithmString, encoding );
        System.out.println( "Static built-in output: " + javaxCryptoDigest );
        if ( javaxCryptoDigest.equals( expectedResult ) == true )
        {
            System.out.println( "- SUCCESS!" );
        }
        else
        {
            System.out.println( "- ERROR! (expected: " + expectedResult + ")" );
        }

        //-------------------------------------------------------------------//
        // try the commons method
        //-------------------------------------------------------------------//

        algorithmInstance = HmacAlgorithms.HMAC_SHA_256;
        commonsDigest = HMACHasher.commonsHMACDigest( message, key, algorithmInstance, encoding );
        System.out.println( "Static Apache Commons codec output: " + commonsDigest );
        if ( commonsDigest.equals( expectedResult ) == true )
        {
            System.out.println( "- SUCCESS!" );
        }
        else
        {
            System.out.println( "- ERROR! (expected: " + expectedResult + ")" );
        }

        //-------------------------------------------------------------------//
        // test an instance.
        //-------------------------------------------------------------------//

        myHasherInstance = new HMACHasher();

        // init
        myHasherInstance.setKeyString( key );
        myHasherInstance.setHMACAlgorithmString( algorithmString );
        myHasherInstance.initHmacUtilsInstance();

        // hash a string using apache commons.
        instanceDigest = myHasherInstance.commonsHashString( message, encoding );
        System.out.println( "Instance Commons codec output: " + instanceDigest );
        if ( instanceDigest.equals( expectedResult ) == true )
        {
            System.out.println( "- SUCCESS!" );
        }
        else
        {
            System.out.println( "- ERROR! (expected: " + expectedResult + ")" );
        }

    } //-- END public static main() method --//
    
} //-- end class HMACHasher --//
