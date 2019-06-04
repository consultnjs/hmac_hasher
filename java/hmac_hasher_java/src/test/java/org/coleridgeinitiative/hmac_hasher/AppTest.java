package org.coleridgeinitiative.hmac_hasher;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

// imports - apache commons codec
import org.apache.commons.codec.digest.HmacAlgorithms;

// this project imports
import org.coleridgeinitiative.hmac_hasher.HMACHasher;

/**
 * Unit test for simple App.
 */
public class AppTest 
{

    //=======================================================================//
    // static variables
    //=======================================================================//

    public static String testSecret = "fakedata";
    public static String testMessage = "123456789";
    public static String testExpectedResult = "a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0";
    public static String testEncoding = "UTF-8";
    public static String testAlgorithmString = "HmacSHA256";
    public static HmacAlgorithms testAlgorithmInstance = HmacAlgorithms.HMAC_SHA_256;


    //=======================================================================//
    // test methods
    //=======================================================================//

    /**
     * testStaticJavaxCrytoHmac()
     */
    @Test
    public void testStaticJavaxCryptoHmac()
    {
        // declare variables
        String me = "testStaticJavaxCryptoHmac";
        String secret = null;
        String message = null;
        String expectedResult = null;
        String algorithmString = null;
        String encoding = null;
        String javaxCryptoDigest = null;

        System.out.println( "==> Test " + me );

        // init
        secret = AppTest.testSecret;
        message = AppTest.testMessage;
        expectedResult = AppTest.testExpectedResult;

        System.out.println( "- secret: " + secret );
        System.out.println( "- message: " + message );
        System.out.println( "- expected_result: " + expectedResult );
        System.out.println();

        // encoding.
        encoding = "UTF-8";

        //-------------------------------------------------------------------//
        // try the javax.crypto method
        //-------------------------------------------------------------------//

        algorithmString = AppTest.testAlgorithmString;
        javaxCryptoDigest = HMACHasher.javaxCryptoHMACDigest( message, secret, algorithmString, encoding );
        System.out.println( "Built-in output: " + javaxCryptoDigest );
        assertTrue( javaxCryptoDigest.equals( expectedResult ) == true );

    } //-- END method testStaticJavaxCryptoHmac() --//


    /**
     * testStaticJavaxCrytoHmac()
     */
    @Test
    public void testStaticApacheCommonsCodecHmac()
    {
        // declare variables
        String me = "testStaticApacheCommonsCodecHmac";
        String secret = null;
        String message = null;
        String expectedResult = null;
        HmacAlgorithms algorithm_instance = null;
        String encoding = null;
        String commonsDigest = null;

        System.out.println( "==> Test " + me );

        // init
        secret = AppTest.testSecret;
        message = AppTest.testMessage;
        expectedResult = AppTest.testExpectedResult;

        System.out.println( "- secret: " + secret );
        System.out.println( "- message: " + message );
        System.out.println( "- expected_result: " + expectedResult );
        System.out.println();

        // encoding.
        encoding = "UTF-8";

        //-------------------------------------------------------------------//
        // try the org.apache.commons.codec.* method
        //-------------------------------------------------------------------//

        // try the commons method
        algorithm_instance = AppTest.testAlgorithmInstance;
        commonsDigest = HMACHasher.commonsHMACDigest( message, secret, algorithm_instance, encoding );
        System.out.println( "Apache Commons codec output: " + commonsDigest );
        assertTrue( commonsDigest.equals( expectedResult ) == true );

    } //-- END method testStaticApacheCommonsCodecHmac() --//


    /**
     * testStaticJavaxCrytoHmac()
     */
    @Test
    public void testInstanceApacheCommonsCodecHmac()
    {
        // declare variables
        String me = "testStaticJavaxCryptoHmac";
        String secret = null;
        String message = null;
        String expectedResult = null;
        String algorithmString = null;
        String encoding = null;
        String instanceDigest = null;
        HMACHasher myHasherInstance = null;

        System.out.println( "==> Test " + me );

        // init
        secret = AppTest.testSecret;
        message = AppTest.testMessage;
        expectedResult = AppTest.testExpectedResult;

        System.out.println( "- secret: " + secret );
        System.out.println( "- message: " + message );
        System.out.println( "- expected_result: " + expectedResult );
        System.out.println();

        // encoding.
        encoding = "UTF-8";

        //-------------------------------------------------------------------//
        // test an instance.
        //-------------------------------------------------------------------//

        // init
        algorithmString = AppTest.testAlgorithmString;
        myHasherInstance = new HMACHasher();
        myHasherInstance.setKeyString( secret );
        myHasherInstance.setHMACAlgorithmString( algorithmString );
        myHasherInstance.initHmacUtilsInstance();

        // hash a string using apache commons.
        instanceDigest = myHasherInstance.commonsHashString( message, encoding );
        System.out.println( "Instance Commons codec output: " + instanceDigest );
        assertTrue( instanceDigest.equals( expectedResult ) == true );

    } //-- END method testStaticJavaxCryptoHmac() --//


} //-- END hmac_hasher AppTest class. --//
