
# coding: utf-8

# <h1>Table of Contents<span class="tocSkip"></span></h1>
# <div class="toc"><ul class="toc-item"><li><span><a href="#Hashing-PII-columns-in-data" data-toc-modified-id="Hashing-PII-columns-in-data-1"><span class="toc-item-num">1&nbsp;&nbsp;</span>Hashing PII columns in data</a></span></li><li><span><a href="#Setup" data-toc-modified-id="Setup-2"><span class="toc-item-num">2&nbsp;&nbsp;</span>Setup</a></span><ul class="toc-item"><li><span><a href="#Setup---Imports" data-toc-modified-id="Setup---Imports-2.1"><span class="toc-item-num">2.1&nbsp;&nbsp;</span>Setup - Imports</a></span></li><li><span><a href="#Setup---Files-and-Directories" data-toc-modified-id="Setup---Files-and-Directories-2.2"><span class="toc-item-num">2.2&nbsp;&nbsp;</span>Setup - Files and Directories</a></span></li><li><span><a href="#Setup---Initialize-HMACHasher-with-salts" data-toc-modified-id="Setup---Initialize-HMACHasher-with-salts-2.3"><span class="toc-item-num">2.3&nbsp;&nbsp;</span>Setup - Initialize HMACHasher with salts</a></span><ul class="toc-item"><li><span><a href="#name-HMACHasher" data-toc-modified-id="name-HMACHasher-2.3.1"><span class="toc-item-num">2.3.1&nbsp;&nbsp;</span>name HMACHasher</a></span></li><li><span><a href="#SSN-HMACHasher" data-toc-modified-id="SSN-HMACHasher-2.3.2"><span class="toc-item-num">2.3.2&nbsp;&nbsp;</span>SSN HMACHasher</a></span></li></ul></li><li><span><a href="#Setup---Functions" data-toc-modified-id="Setup---Functions-2.4"><span class="toc-item-num">2.4&nbsp;&nbsp;</span>Setup - Functions</a></span><ul class="toc-item"><li><span><a href="#Functions---hash-functions" data-toc-modified-id="Functions---hash-functions-2.4.1"><span class="toc-item-num">2.4.1&nbsp;&nbsp;</span>Functions - hash functions</a></span></li></ul></li></ul></li><li><span><a href="#Hash-data" data-toc-modified-id="Hash-data-3"><span class="toc-item-num">3&nbsp;&nbsp;</span>Hash data</a></span></li><li><span><a href="#Evaluate" data-toc-modified-id="Evaluate-4"><span class="toc-item-num">4&nbsp;&nbsp;</span>Evaluate</a></span></li></ul></div>

# # Hashing PII columns in data
# 
# This example notebook hashes the Name fields and SSN in a data file.
# 
# In this example a set of data files are broken into multiple files.  This code reads directly from the original files row by row, hashing column values for each row and building an output row with same number of columns, but hashed values where desired, then writing each row to an output file.
# 
# You will need to set values for the location of the hashing, configuration files, and columns you would like to hash and which type of hash you would like to use (e.g., name or ssn, currently) in a separate JSON file. See `../process/template/template.json` for required fields to enter.
# 
# You will then only have to specify that YAML file (one per each dataset, which is defined as a set of data files in a directory all sharing the same schema) in the `configuration_file` variable in **Setup - Files and Directories**
# 
# Logic overiew - for each row in CSV file:
# - reads row from original CSV file into a row value list.
# - makes a copy of the row value list, for output.
# - pulls in the fields to hash, hashes them, then replaces existing values in output list with hashed values.
# - writes hashed row to output CSV.

# # Setup
# 
# - Back to [Table of Contents](#Table-of-Contents)

# **THIS SHOULD BE THE ONLY THING THAT YOU HAVE TO CHANGE IN THIS FILE THEN JUST RUN **

# In[ ]:


import os

CONFIGURATION_FILE_NB_USER_INPUT = os.path.abspath("../process/template/example.json")


# In[ ]:


import copy
import sys
import csv
import json
import datetime
import glob
import hashlib
import six
import uuid

print( "Imports imported at " + str( datetime.datetime.now() ) )


# ## Setup - Imports
# 
# - Back to [Table of Contents](#Table-of-Contents)

# ## Setup - Files and Directories
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


pwd


# In[ ]:


configuration_file = CONFIGURATION_FILE_NB_USER_INPUT
configuration = json.load(open(configuration_file, 'r'))

file_conf = configuration['LOCATIONS']
column_conf = configuration['COLUMNS']


# can get fancy, for example, all are current directory.
# root_directory = file_conf['ROOT_DIRECTORY']
configuration_directory = file_conf['CONFIGURATION_DIRECTORY']
work_directory = file_conf['WORK_DIRECTORY'] # needs to be a directory that has the hmac_hasher folder that sits alongside this file in the repository inside of it.
data_directory = file_conf['DATA_DIRECTORY']
source_directory = data_directory
output_directory = file_conf['OUTPUT_DIRECTORY']

# variable names used in the code below.
input_file_directory_path = source_directory
output_file_directory_path = output_directory

print( "Directories configured at " + str( datetime.datetime.now() ) )


# In[ ]:


print(work_directory)


# ## Setup - Initialize HMACHasher with salts
# 
# - Back to [Table of Contents](#Table-of-Contents)
# 
# We have a shared HMAC passphrase we will use for hashing.  We can just set the object up here, then use map to call it on each column we need to hash.

# In[ ]:


# first, load the HMACHasher class.
hmac_hasher_folder_path = file_conf['HMAC_HASHER_FOLDER_PATH']
print(hmac_hasher_folder_path)
hmac_hasher_class_file_path = file_conf['HMAC_HASHER_CLASS_FILE_PATH']
print(hmac_hasher_class_file_path)


# Use the "%run" command to run the Python file that defines the HMACHasher class and load the class into memory.

# In[ ]:


get_ipython().run_line_magic('run', '$hmac_hasher_class_file_path')

print( "HMACHasher class imported from {} at {}".format( hmac_hasher_class_file_path, str( datetime.datetime.now() ) ) )


# ### name HMACHasher
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


# make instance of the HMACHasher for names
my_name_hasher = HMACHasher()

# load the passphrase/salt from the configuration file
name_hmac_hasher_ini_file_path = file_conf['NAME_HMAC_HASHER_INI_FILE_PATH']

# store configuration file path in HMACHasher, then load config.
my_name_hasher.configuration_ini_file_path = name_hmac_hasher_ini_file_path
config_load_messages = my_name_hasher.load_configuration_from_ini_file()

# errors?
if ( len( config_load_messages ) > 0 ):

    # errors.
    for error_message in config_load_messages:
        
        print( "- " + str( error_message ) )
        
    #-- END loop over errors. --#

else:
    
    print( "Config loaded from path " + str( name_hmac_hasher_ini_file_path ) + " at " + str( datetime.datetime.now() ) )
    
#-- END check for errors loading configuration. --#

print( "HMACHasher instances created at " + str( datetime.datetime.now() ) )


# In[ ]:


# test hashing a value.
expected_value = "2990abf7de79499d1869bef3d1af456c0f24abfb85e7348a59d99ce6a8962ae5"

# with other than the example secret, on first run, this will not match.  To test:
# - Copy value from first run into expected_value, above.
# - stop kernel and clear output.
# - run all cells again.

test_value = "Exculpatory"
test_hash = ""
test_hash = my_name_hasher.hash_value( test_value )
print( "FROM " + str( test_value ) + " TO " + str( test_hash ) )
print( "Equal to expected?: " + str( expected_value == test_hash ) )


# ### SSN HMACHasher
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


# make instance of the HMACHasher for SSN
my_ssn_hasher = HMACHasher()

# load the passphrase/salt from the configuration file
ssn_hmac_hasher_ini_file_path = file_conf['SSN_HMAC_HASHER_INI_FILE_PATH']

# store configuration file path in HMACHasher, then load config.
my_ssn_hasher.configuration_ini_file_path = ssn_hmac_hasher_ini_file_path
config_load_messages = my_ssn_hasher.load_configuration_from_ini_file()

# errors?
if ( len( config_load_messages ) > 0 ):

    # errors.
    for error_message in config_load_messages:
        
        print( "- " + str( error_message ) )
        
    #-- END loop over errors. --#

else:
    
    print( "Config loaded from path " + str( ssn_hmac_hasher_ini_file_path ) + " at " + str( datetime.datetime.now() ) )
    
#-- END check for errors loading configuration. --#

print( "HMACHasher instances created at " + str( datetime.datetime.now() ) )


# In[ ]:


# test hashing a value.
expected_value = "f20444b7c321517ac2b4c73af8de3bc888ddee0980d52cf5c3ec9f348c670192"

# with other than the example secret, on first run, this will not match.  To test:
# - Copy value from first run into expected_value, above.
# - stop kernel and clear output.
# - run all cells again.

test_value = "Exculpatory"
test_hash = ""
test_hash = my_ssn_hasher.hash_value( test_value )
print( "FROM " + str( test_value ) + " TO " + str( test_hash ) )
print( "Equal to expected?: " + str( expected_value == test_hash ) )


# ## Setup - Functions
# 
# - Back to [Table of Contents](#Table-of-Contents)

# ### Functions - hash functions
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


def hash_ssn( value_IN, hasher_IN = my_ssn_hasher ):
    
    # return reference
    hash_OUT = ""
    
    # hash using SSN method:
    # - removes punctuation
    # - replaces multiple spaces with a single space
    # - strips white space from ends
    hash_OUT = hasher_IN.hash_ssn_value( value_IN )
    
    return hash_OUT

#-- END function hash_ssn() --#

print( "Function hash_ssn() declared at " + str( datetime.datetime.now() ) )

    
def hash_name( value_IN, hasher_IN = my_name_hasher ):
    
    # return reference
    hash_OUT = "" 
     
    # hash using name method to standardize:
    # - converts to upper case
    # - removes punctuation
    # - replaces multiple spaces with a single space
    # - strips white space from ends
    hash_OUT = hasher_IN.hash_name_value( value_IN )
    
    return hash_OUT

#-- END function hash_name() --#

print( "Function hash_name() declared at " + str( datetime.datetime.now() ) )


# # Hash data
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


# ==> example data

# declare variables - loop over files
file_list = []
file_path = ""
path_part_list = []
file_name = ""
temp_file_name = ""
file_year = ""
file_quarter = ""

# declare variables - process each file
path_separator = "/"
input_file = ""
input_file_encoding = "utf-8"
has_header_row = True
output_file = ""
line_counter = -1
hash_output_file = None
to_hash_csv_file = None
input_csv_reader = None
output_csv_writer = None
current_record = None

# values from record

row_value_list = []

# first get list of *.csv files in directory.
print( "Looking for files in {}".format( input_file_directory_path ) )
#file_list = glob.glob( input_file_directory_path + "*.csv" )
file_list = [os.path.join(input_file_directory_path, i) for i in os.listdir(input_file_directory_path) if '.csv' in i]
print( "File list: " + str( file_list ) )

for file_path in file_list:
    
    # Parse out the file name.  Name pattern: il_wage_2012q1.csv
    path_part_list = file_path.split( path_separator )
    file_name = path_part_list[ -1 ]
    
    print( "--> Current file: {} @ {}".format( str( file_name ), str( datetime.datetime.now() ) ) )

    # initialize
    line_counter = 0
    input_file = file_path
    output_file = output_file_directory_path + "hashed-" + file_name

    # open the output file for writing.
    with open( output_file, "w", newline = '') as hash_output_file:

        # init CSV writer.
        output_csv_writer = csv.writer( hash_output_file, delimiter = "," )

        # open the input file for reading
        with open( input_file, encoding = input_file_encoding ) as to_hash_csv_file:

            # get a CSV reader
            input_csv_reader = csv.reader( to_hash_csv_file )

            # output header row?
            if ( has_header_row == True ):
                
                # yes - output first row as is.
                row_value_list = input_csv_reader.__next__()
                output_csv_writer.writerow( row_value_list )
                
            #-- END check to see if header row --#

            # loop over records
            for current_record in input_csv_reader:

                # initialize output list with copy of input list
                row_value_list = copy.copy( current_record )

                # increment line counter
                line_counter += 1

                # for each element we have a hashing column for in the configuration
                for conf_item in column_conf:
                    # get values (check if positions are correct)
                
                    curr_index = conf_item['index']
                    curr_value = ''
                    curr_value = current_record[ curr_index ]
                
                    # inititate and generate appropriate hashvalue
                    hashed_curr_value = ''
                    if conf_item['type'] == 'ssn':
                        hashed_curr_value = hash_ssn( curr_value )
                    elif conf_item['type'] == 'name':
                        hashed_curr_value = hash_name( curr_value )
                    else:
                        sys.exit("Check configuration file at: {}. Incorrect type provided - {}".format(CONFIGURATION_FILE_NB_USER_INPUT, conf_item['type']))
                    
                    # write value to same location in copied row
                    row_value_list[ curr_index ] = hashed_curr_value
                
                # write to output file.
                output_csv_writer.writerow( row_value_list )

                if ( ( line_counter % 100000 ) == 0 ):
                    print( "- Hashed " + str( line_counter ) + " lines at " + str( datetime.datetime.now() ) )
                #-- END check to see if we've done 1000 records. --#

            #-- END loop over input lines.

        #-- END with ... to_hash_csv_file --#

    #-- END with ... hash_output_file --#    

#-- END loop over file list --#

print( "All files processed at " + str( datetime.datetime.now() ) )


# # Evaluate
# 
# - Back to [Table of Contents](#Table-of-Contents)
# 
# Check the input and output files for correct number of rows, that the correct columns were hashed and check that the unique values for hashed values are the same for both hashed and unhashed.
