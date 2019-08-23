# HMAC Hasher

This project includes source and example code for implementing HMAC hashing in different languages (C# and Python, to start).

For Python, includes source code and example Jupyter notebooks for a configurable HMAC Hasher, a class that uses the HMAC encryption algorithm to distribute the information from a secret uniformly through a value that is being obfuscated, rather than combining a salt with each value based on some algorithm, then hashing.  The end result is the same, however - a given value will get the same resulting obfuscated value each time it is run through the HMAC Hasher with the same secret.

The HMAC hasher itself has been written to support either Python 2 or Python 3.  The example code for generating secrets (or salts, in the terminology of hashing) uses the Python 3.6 "secrets" package, and so does not support Python 2 or versions of Python 3 earlier than 3.6.  The basic algorithm laid out in this notebook could be implemented with other libraries in other versions of Python, however.

For C#, includes a basic class that implements HMAC Hashing so that it returns same hash for a given secret and input string as the Python code.

## Repository Contents

- `README.md` - this file - overview of contents of repository and setup instructions.
- `LICENSE` - the GNU Lesser GPL license for this project.
- `.gitignore` - gitignore file for Mac, Windows OS files.
- `/python` - Python HMAC hashing code:

    - `requirements.txt` - list of Python packages needed to run the code included in this  repository, for pip (it is just `pytest` and `six` at the moment).
    - `Hashing-CSV-to-CSV.ipynb` - example file that shows process of hashing a set of data files in CSV format once salt/secrets have been generated and stored in configuration files.
    - `/examples` - directory that includes sample code and example data files used in some examples.

        - `create_salt.py`  - plain Python 3.6 example code for generating a cryptographically sound salt/secret.
        - `create_salt.ipynb` - the same code, in a Jupyter notebook, in case you prefer that.
        - `Fake_Data_Test_001.csv` - first file of fake data used in `Hashing-CSV-to-CSV.ipynb`.
        - `Fake_Data_Test_002.csv` - second file of fake data used in `Hashing-CSV-to-CSV.ipynb`.
        - `name_hashing_configuration.ini` - example configuration file for `Hashing-CSV-to-CSV.ipynb`
        - `ssn_hashing_configuration.ini` - example configuration file for `Hashing-CSV-to-CSV.ipynb`

    - `/hmac_hasher` - contains actual source code for HMAC Hasher, plus testing scripts and an example of running HMAC Hasher from the command line (a very tightly constrained use case).

        - `hmac_hasher.py` - Python source code file that contains actual `HMACHasher` class definition.
        - `requirements.txt` - list of Python packages needed to run the code included in this  repository, for pip (it is just `pytest` and `six` at the moment).
        - `test_HMACHasher.py` - `pytest`  test case definition file (to run tests, install `pytest` package, then cd into this folder and run `pytest` - more details below).
        - `hash_program.py` - hash program you can run on the command line (see below for details).
        - `hash_tester.py` - end-to-end test of hashing that uses sample data file and configuration in this folder to test (to run end-to-end tests, cd into this folder and run `python hash_tester.py` - more details below).
        - `Fake_Data_Test.csv` - test data file.
        - `hashing_configuration.ini` - example configuration file also used in `hash_tester.py`.

- `/c_sharp` - contains a C# project with code that can be used to generate hash values that correspond to those from the Python code above when the same salt/secret is used.

- `java` - contains a Java project with code that can be used to generate hash values that correspond to those from the Python code above when the same salt/secret is used.

## Creating a secret/salt

To create salts/secrets, you can use the code in either "`examples/create_salt.ipynb`" or "`examples/create_salt.py`" (the code itself is identical).

The string that is printed in the last statement in the code is the secret.  You can use it as-is, or add in a delimiter to make it easier to share verbally (hyphen every 5 characters, for example).


## Using the HMAC hasher

There are two ways to use the HMAC hasher in this repository:

- 1) as a standalone program that takes a CSV file and a single configuration (so a single secret/salt) and writes results of hashing all column values using the single shared secret to an output CSV, each column value in the same row as in the input file.  This is a basic use-case.
- 2) For more complex use cases (say, multiple files where a subset of columns need to be hashed, potentially with different secrets/salts per column or per type of information), one or more instances of the Python HMACHasher class can be created, initialized either programmatically or from INI files, and then used in a separate Python program to simply hash values.

### configuration INI file

The HMAC hasher configuration INI file that is used to configure either the standalone hashing program or a HMACHasher class instance has three sections:

- `secret` - for now, just contains the salt or secret.  Supported properties:
	- `passphrase` - string passphrase used to encrypt values with HMAC algorithm.
- `file_paths` - file paths used if program is run at command line.  If HMACHasher class is used in a Python program that handles input and output, these are not needed.  Supported properties:

    - `input_file_path` - path to file whose values we want hashed.
    - `output_file_path` - path to file where we want hashed values stored.

- `configuration` - other configuration options.  Supported properties:

    - `has_header_row` - boolean, "true" results in first row being output in clear text to output file, "false" results in values in first row being treated like all other rows, so hashed and output.

If you are using the standalone program, you'll want to properly configure all properties.  If you are just using the HMACHasher class to hash values in a program of your own design, you'll likely just need to set a `passphrase` in the `secret` section of the file (or forego the file entirely and configure in your Python code).

_Note: Having the secret in a separate file is useful should you ever want to share or version your code files - You are less likely to accidentally commit or share a secret if it is separate from the code that uses it._

### Testing

To run Python unit tests:

- make sure you have installed pytest (using pip, it is `pip install pytest`).
- in a command shell:

    - cd into the `data-tools/deidentification/hmac_hasher/python` folder.
    - run `pytest`

- if successful, you should see something like:

        ============================= test session starts ==============================
        platform darwin -- Python 3.6.4, pytest-3.2.1, py-1.4.34, pluggy-0.4.0
        rootdir: ./hmac_hasher, inifile:
        collected 9 items                                                               
        
        test_HMACHasher.py .........
        
        =========================== 9 passed in 0.05 seconds ===========================

To run the end-to-end test program:

- in a command shell:

    - cd into the `data-tools/deidentification/hmac_hasher/hmac_hasher` folder.
    - run `python hash_tester.py`

- If successful, you should see something like:

        
        ==> Processing file: ./Fake_Data_Test.csv @ 2018-02-15 13:29:36.410136
        
        ==> Processing complete @ 2018-02-15 13:29:36.410998
        
        No status messages - SUCCESS!

### Example: Running standalone program

To run the standalone hashing program that hashes all values in all columns in a given file using a shared secret:

- in a command shell:

    - cd into the `data-tools/deidentification/hmac_hasher/hmac_hasher` folder.
    - run `python hash_program.py <ini_file_path>`

        - WHERE `<ini_file_path>` is the path to your INI file.

    - Example (can be run as-is in repository):

            python hash_program.py ./hashing_configuration.ini 


### Example: Using HMACHasher class instances in separate program

To see an example of the HMACHasher class being used in a standalone program, see the Jupyter notebook [`Hashing-CSV-to-CSV.ipynb`](https://github.com/Coleridge-Initiative/hmac_hasher/blob/master/python/Hashing-CSV-to-CSV.ipynb) in the `python` folder of this repository.

This jupyter notebook contains a more nuanced example where a CSV file is read in, some values are hashed, and then each row is written to a separate output file (if you need jupyter, consider installing Anaconda: [https://www.anaconda.com/download/](https://www.anaconda.com/download/)).

Notes:

- for each separate salt you want to use to hash a set of values (so, if separate salts for first name, last name, and SSN), you'll need to generate a salt value using "`create_salt.ipynb`", then store it in an INI file bsaed on the file "`hmac_hasher/hashing_configuration.ini`".
- In your INI file, if you will be only using the HMACHasher class for actually hashing values, not processing a file, then you will only need to correctly populate your passphrase in the secret section of these INI files.  The other configuration properties can be omitted.

### Example: HMAC in another language

You should be able to make crypto packages in almost any other language produce the same output for the secret "fakedata" with a little fiddling to figure out exactly what format it needs the secret in. For example, in our library, as an extra bit of security, we encode the secret to utf-8, then convert the encoded secret to a SHA256 hash that we then use as the actual key for the HMAC (example code in Python summarized below), to make sure that even short passphrases result in reasonably long key strings.

To figure out how exactly you can use HMAC in another language not desribed here so that output for a given secret is the same as from these programs, you can start by hashing the values in the CSV file `hmac_hasher/python/hmac_hasher/Fake_Data_Test.csv` using the passphrase "fakedata" (without the surrounding quotes) and comparing the resulting hex digest values to the values below.  This file has 5 rows plus a header row with column names.

To turn the passphrase into the HMAC key, in Python, we do the following:

    import hashlib
    
    # what is our secret?
    passphrase = "fakedata"

    # get hasher
    sha256_instance = hashlib.sha256()

    # encode to utf-8, then put the secret in the SHA256 hasher.
    encoded_passphrase = passphrase.encode( "utf-8" )
    sha256_instance.update( encoded_passphrase )

    # get hash as digest (byte array)
    passphrase_hash = sha256_instance.digest()
    print( "digest(): {}".format( passphrase_hash ) )

    # get hash as hexdigest (byte array)
    passphrase_hash_hex = sha256_instance.hexdigest()
    print( "hexdigest(): {}".format( passphrase_hash_hex ) )

Which results in:

    digest(): b'\x8fP\xa1\xb2J\xbc$\xae\xbb\x1bKgt_M\x87v\xff\xebQ\x83\xad\x1e\xbcb\x96\xde\xf1\x0e\x8f1P'
    hexdigest(): 8f50a1b24abc24aebb1b4b67745f4d8776ffeb5183ad1ebc6296def10e8f3150

The resulting byte array of the hash of the passphrase/secret (from call to `digest()`) is then used as the key with which we initialize the HMAC:

    import hmac

    # byte array secret and encoded message (each is required)
    message = "123456789"
    encoded_message = message.encode( "utf-8" )
    hmac_key = passphrase_hash
    hmac_instance = hmac.new( hmac_key, encoded_message, digestmod = hashlib.sha256 )
    hashed_value = hmac_instance.hexdigest()
    print( "Hash of {}: {}".format( message, hashed_value )  )

Which results in:

    Hash of 123456789: a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0

The corresponding C# code at `hmac_hasher/c_sharp/Program.cs` that has same output as Python code for a given secret is an example of how code that ensures the secret string you start with results in the same hash output for a given string across technologies can differ depending on the implementation of HMAC.  To get it to work the same, we had to compute a SHA256 hash of the passphrase/secret after converting it to a utf-8-encoded byte array (`sha256.ComputeHash(Encoding.Default.GetBytes(StringIn));`), rather than hashing the encoded string, then outputting the hash as a byte array (...).

Expected outputs (from hmac_hasher/python/hmac_hasher/hash_tester.py):

    # ==> PK 555555
    current_results_map = {}
    current_results_map[ NAME_EXPECTED_SSN ] = "a69ecf70cab21fdc100165faceaf87f04d0b9fb50d4dc627b04d7e5554a38bc0"
    current_results_map[ NAME_EXPECTED_FNAME ] = "a0c82465bc168bfc72b7e4aab39bfa74debfa4b785f16976eb0248455be03d14"
    current_results_map[ NAME_EXPECTED_MNAME ] = "e60d8aa3a723832d2b298fd2e415d75c8d1ec1c273573d0480b7233ef8021310"
    current_results_map[ NAME_EXPECTED_LNAME ] = "70dba5087a8ab6789d53bc26b02e598c31e2701fe5d8b450a9e4fcbe5eaf296b"
    
    # add to expected results, associated with PK
    expected_results[ "555555" ] = current_results_map
    
    # ==> PK 10101010
    current_results_map = {}
    current_results_map[ NAME_EXPECTED_SSN ] = "5a823abdcc524029e5497e29d65486cf69befc714758b60edf5113748afd79e3"
    current_results_map[ NAME_EXPECTED_FNAME ] = "f315ed89f0cb43c52b96aae0003b4adfd5cbd61f3fc1a3e72075533eb73332af"
    current_results_map[ NAME_EXPECTED_MNAME ] = "4c4768fb4c07d15651adb24f9dbd7f036c226cbf0c26cc5232a1738d59a5337f"
    current_results_map[ NAME_EXPECTED_LNAME ] = "12cfb1171ef0103a81afa8c37414e232e0931e544d6c4ecc599b995312597f38"
    
    # add to expected results, associated with PK
    expected_results[ "10101010" ] = current_results_map
    
    # ==> PK 346712
    current_results_map = {}
    current_results_map[ NAME_EXPECTED_SSN ] = "5f552e4659d4604b44049cc4a70d82b86c4453a0f4a88d7af2df03e8596ac4ad"
    current_results_map[ NAME_EXPECTED_FNAME ] = "15a70ba92649d971a4c4b2c68aa98f52527cc29399e25e57e5aa6ae4df41bbad"
    current_results_map[ NAME_EXPECTED_MNAME ] = "5218afe466a5aedd298e84c8a60a0293f7407cb46ce64f9cc1fe2fd591a35cff"
    current_results_map[ NAME_EXPECTED_LNAME ] = "8a8afb5eaaa282f6132f88562a4502272c8bfa3514e0327e85d4f76a2b271ced"
    
    # add to expected results, associated with PK
    expected_results[ "346712" ] = current_results_map
    
    # ==> PK 987654
    current_results_map = {}
    current_results_map[ NAME_EXPECTED_SSN ] = "27becbaca10ec9cf7f2bbb4c0bece17999cad56d2d14fa5282ac2bbc5f7a82ec"
    current_results_map[ NAME_EXPECTED_FNAME ] = "c4cda429751d60bebdb9624ea19c195bb4111af011524128e30b4854d5104baa"
    current_results_map[ NAME_EXPECTED_MNAME ] = "c41d324c94ab58469f00c85564fe444d5dc18c3b8c8a83cef9883a37c8889485"
    current_results_map[ NAME_EXPECTED_LNAME ] = "722b8277d9828ba4537d130ec31611d9104f740c1bdc8311a2086dbdbc78178a"
    
    # add to expected results, associated with PK
    expected_results[ "987654" ] = current_results_map
    
    # ==> PK 23232323
    current_results_map = {}
    current_results_map[ NAME_EXPECTED_SSN ] = "cc559eb94e32af592d37a9b631a22d7ee320620d24020d59bc56b6019a593ee4"
    current_results_map[ NAME_EXPECTED_FNAME ] = "2ccae105615b7a58714b580f3d6320b9f7fe7b11463e3a773981a0fb2fdd44b5"
    current_results_map[ NAME_EXPECTED_MNAME ] = "11acfc917b5b8a25608085a9a9781b60b0ed8ded17fafd73d294a151c364ed81"
    current_results_map[ NAME_EXPECTED_LNAME ] = "96ccc9b53ef91dc48a6ef634c5d73394b82ea4dbe2d950ea13f6395ad2c2f6b1"
    
    # add to expected results, associated with PK
    expected_results[ "23232323" ] = current_results_map
