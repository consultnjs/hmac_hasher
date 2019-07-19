
# coding: utf-8

# <h1>Table of Contents<span class="tocSkip"></span></h1>
# <div class="toc"><ul class="toc-item"><li><span><a href="#Hashing-PII-columns-in-data" data-toc-modified-id="Hashing-PII-columns-in-data-1"><span class="toc-item-num">1&nbsp;&nbsp;</span>Hashing PII columns in data</a></span></li><li><span><a href="#Setup" data-toc-modified-id="Setup-2"><span class="toc-item-num">2&nbsp;&nbsp;</span>Setup</a></span><ul class="toc-item"><li><span><a href="#Setup---Imports" data-toc-modified-id="Setup---Imports-2.1"><span class="toc-item-num">2.1&nbsp;&nbsp;</span>Setup - Imports</a></span></li><li><span><a href="#Setup---Files-and-Directories" data-toc-modified-id="Setup---Files-and-Directories-2.2"><span class="toc-item-num">2.2&nbsp;&nbsp;</span>Setup - Files and Directories</a></span></li><li><span><a href="#Setup---Initialize-HMACHasher-with-salts" data-toc-modified-id="Setup---Initialize-HMACHasher-with-salts-2.3"><span class="toc-item-num">2.3&nbsp;&nbsp;</span>Setup - Initialize HMACHasher with salts</a></span><ul class="toc-item"><li><span><a href="#name-HMACHasher" data-toc-modified-id="name-HMACHasher-2.3.1"><span class="toc-item-num">2.3.1&nbsp;&nbsp;</span>name HMACHasher</a></span></li><li><span><a href="#SSN-HMACHasher" data-toc-modified-id="SSN-HMACHasher-2.3.2"><span class="toc-item-num">2.3.2&nbsp;&nbsp;</span>SSN HMACHasher</a></span></li></ul></li><li><span><a href="#Setup---Functions" data-toc-modified-id="Setup---Functions-2.4"><span class="toc-item-num">2.4&nbsp;&nbsp;</span>Setup - Functions</a></span><ul class="toc-item"><li><span><a href="#Functions---hash-functions" data-toc-modified-id="Functions---hash-functions-2.4.1"><span class="toc-item-num">2.4.1&nbsp;&nbsp;</span>Functions - hash functions</a></span></li></ul></li></ul></li><li><span><a href="#Hash-data" data-toc-modified-id="Hash-data-3"><span class="toc-item-num">3&nbsp;&nbsp;</span>Hash data</a></span></li><li><span><a href="#Evaluate" data-toc-modified-id="Evaluate-4"><span class="toc-item-num">4&nbsp;&nbsp;</span>Evaluate</a></span></li></ul></div>

# # Hashing PII columns in data
# 
# This example notebook hashes the Name fields and SSN in a sample data file.
# 
# In this example a set of data files are broken into multiple files, one file per quarter, one row per unit of interest.  This code reads directly from the original files row by row, hashing column values for each row and building an output row with same number of columns, but hashed values where desired, then writing each row to an output file.
# 
# Logic overiew - for each row in CSV file:
# - reads row from original CSV file into a row value list.
# - makes a copy of the row value list, for output.
# - pulls in the fields to hash, hashes them, then replaces existing values in output list with hashed values.
# - writes hashed row to output CSV.

# # Setup
# 
# - Back to [Table of Contents](#Table-of-Contents)

# ## Setup - Imports
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


import copy
import csv
import datetime
import glob
import hashlib
import six
import uuid
import os
print( "Imports imported at " + str( datetime.datetime.now() ) )


# ## Setup - Files and Directories
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


os.getcwd()

# In[ ]:


# work directories
#root_directory = "workspace"
#configuration_directory = "configuration"
#work_directory = root_directory + "work"
#data_directory = root_directory + "ingest"
#source_directory = data_directory + "original_data"
#output_directory = root_directory + "hashed_output"

# can get fancy, for example, all are current directory.
#path_separator = "/"  # unix/macos
path_separator = "\\"  # windows
root_directory = "."
configuration_directory = root_directory + path_separator + "examples"
work_directory = "." # needs to be a directory that has the hmac_hasher folder that sits alongside this file in the repository inside of it.
data_directory = root_directory + path_separator + "examples"
source_directory = data_directory
output_directory = "."

# variable names used in the code below.
input_file_directory_path = source_directory
output_file_directory_path = output_directory

print( "Directories configured at " + str( datetime.datetime.now() ) )


# ## Setup - Initialize HMACHasher with salts
# 
# - Back to [Table of Contents](#Table-of-Contents)
# 
# We have a shared HMAC passphrase we will use for hashing.  We can just set the object up here, then use map to call it on each column we need to hash.

# In[ ]:


# first, load the HMACHasher class.
hmac_hasher_folder_path = work_directory + path_separator + "hmac_hasher"
hmac_hasher_class_file_path = hmac_hasher_folder_path + path_separator + "hmac_hasher.py"


# Use the "%run" command to run the Python file that defines the HMACHasher class and load the class into memory.

# In[ ]:


exec(open(hmac_hasher_class_file_path).read(), globals())
print( "HMACHasher class imported from {} at {}".format( hmac_hasher_class_file_path, str( datetime.datetime.now() ) ) )


# ### name HMACHasher
# 
# - Back to [Table of Contents](#Table-of-Contents)

# In[ ]:


# make instance of the HMACHasher for names
my_name_hasher = HMACHasher()

# load the passphrase/salt from the configuration file
hmac_hasher_ini_file_path = configuration_directory + path_separator + "name_hashing_configuration.ini"

# store configuration file path in HMACHasher, then load config.
my_name_hasher.configuration_ini_file_path = hmac_hasher_ini_file_path
config_load_messages = my_name_hasher.load_configuration_from_ini_file()

# errors?
if ( len( config_load_messages ) > 0 ):

    # errors.
    for error_message in config_load_messages:
        
        print( "- " + str( error_message ) )
        
    #-- END loop over errors. --#

else:
    
    print( "Config loaded from path " + str( hmac_hasher_ini_file_path ) + " at " + str( datetime.datetime.now() ) )
    
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
hmac_hasher_ini_file_path = configuration_directory + path_separator + "ssn_hashing_configuration.ini"

# store configuration file path in HMACHasher, then load config.
my_ssn_hasher.configuration_ini_file_path = hmac_hasher_ini_file_path
config_load_messages = my_ssn_hasher.load_configuration_from_ini_file()

# errors?
if ( len( config_load_messages ) > 0 ):

    # errors.
    for error_message in config_load_messages:
        
        print( "- " + str( error_message ) )
        
    #-- END loop over errors. --#

else:
    
    print( "Config loaded from path " + str( hmac_hasher_ini_file_path ) + " at " + str( datetime.datetime.now() ) )
    
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

# file details - indexes start at 0.
index_given = 
index_family =
index_month = 
index_year = 
index_complete = 
index_given_nickname = 
index_given_first_word = 
index_given_middle_initial = 
index_given_all_but_first = 
index_given_all_but_final = 
index_given_final_initial = 
index_given_final_wordindex = 



# declare variables - process each file
#path_separator = None
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
given_value = ""
family_value = ""
month_value = ""
year_value = ""
complete_value = ""
given_nickname_value = ""
given_first_word_value = ""
given_middle_initial_value = ""
given_all_but_first_value = ""
given_all_but_final_value = ""
given_final_initial_value = ""
given_final_wordindex_value = ""

hashed_given = ""
hashed_family = ""
hashed_month = ""
hashed_year = ""
hashed_complete = ""
hashed_given_nickname = ""
hashed_given_first_word = ""
hashed_given_middle_initial = ""
hashed_given_all_but_first = ""
hashed_given_all_but_final = ""
hashed_given_final_initial = ""
hashed_given_final_wordindex = ""

row_value_list = []

# first get list of *.csv files in directory.
print( "Looking for files in {}".format( input_file_directory_path ) )
file_list = glob.glob( input_file_directory_path + path_separator + "*.csv" )
print( "File list: " + str( file_list ) )

for file_path in file_list:
    
    # Parse out the file name.  Name pattern: il_wage_2012q1.csv
    path_part_list = file_path.split( path_separator )
    file_name = path_part_list[ -1 ]
    
    print( "--> Current file: {} @ {}".format( str( file_name ), str( datetime.datetime.now() ) ) )

    # initialize
    line_counter = 0
    input_file = file_path
    output_file = output_file_directory_path + path_separator + "hashed-" + file_name

    # open the output file for writing.
    # - Unix-like systems just work with a normal "w" flag:
    #with open( output_file, "w" ) as hash_output_file:    
    # - On Windows, need to explicitly tell it to not add a newline after each line.
    # - Windows - python 2:
    #with open( output_file, "wb" ) as hash_output_file:
    # - Windows - python 3:
    with open( output_file, "w", newline = '' ) as hash_output_file:

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

                # get values (check if positions are correct)
                
                # got an given name list index?
                if ( index_given is not None ):

                    # we have an index.  Get value...
                    given_value = current_record[ index_given ]
                    
                    # ...hash...
                    hashed_given = hash_name( given_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given ] = hashed_given
                    
                #-- END check to see if given name index. --#

                # got a family name list index?
                if ( index_family is not None ):

                    # we have an index.  Get value...
                    family_value = current_record[ index_family ]
                    
                    # ...hash...
                    hashed_family = hash_name( family_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_family ] = hashed_family
                    
                #-- END check to see if family name index. --#

                # got a month list index?
                if ( index_month is not None ):

                    # we have an index.  Get value...
                    month_value = current_record[ index_month ]
                    
                    # ...hash...
                    hashed_month = hash_name( month_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_month ] = hashed_month
                    
                #-- END check to see if month index. --#
                
                # got a year list index?
                if ( index_year is not None ):

                    # we have an index.  Get value...
                    year_value = current_record[ index_year ]
                    
                    # ...hash...
                    hashed_year = hash_name( year_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_year ] = hashed_year
                #-- END check to see if year  index. --#


                # got an complete list index?
                if ( index_complete is not None ):

                    # we have an index.  Get value...
                    complete_value = current_record[ index_complete ]
                    
                    # ...hash...
                    hashed_complete = hash_name( complete_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_complete ] = hashed_complete
                    
                #-- END check to see if complete index. --#

                # got an given nickname list index?
                if ( index_given_nickname is not None ):

                    # we have an index.  Get value...
                    given_nickname_value = current_record[ index_given_nickname ]
                    
                    # ...hash...
                    hashed_given_nickname = hash_name( given_nickname_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_nickname ] = hashed_given_nickname
                    
                #-- END check to see if given nick index. --#
                
                # got an given first word list index?
                if ( index_given_first_word is not None ):

                    # we have an index.  Get value...
                    given_first_word_value = current_record[ index_given_first_word ]
                    
                    # ...hash...
                    hashed_given_first_word = hash_name( given_first_word_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_first_word ] = hashed_given_first_word
                    
                #-- END check to see if given first index. --#


                # got an given middle list index?
                if ( index_given_middle_initial is not None ):

                    # we have an index.  Get value...
                    given_middle_initial_value = current_record[ index_given_middle_initial ]
                    
                    # ...hash...
                    hashed_given_middle_initial = hash_name( given_middle_initial_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_middle_initial ] = hashed_given_middle_initial
                    
                #-- END check to see if given middle index. --#

                # got an given all but first list index?
                if ( index_given_all_but_first is not None ):

                    # we have an index.  Get value...
                    given_all_but_first_value = current_record[ index_given_all_but_first ]
                    
                    # ...hash...
                    hashed_given_all_but_first = hash_name( given_all_but_first_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_all_but_first ] = hashed_given_all_but_first
                    
                #-- END check to see if given all but first index. --#

                # got an given all but final list index?
                if ( index_given_all_but_final is not None ):

                    # we have an index.  Get value...
                    given_all_but_final_value = current_record[ index_given_all_but_final ]
                    
                    # ...hash...
                    hashed_given_all_but_final = hash_name( given_all_but_final_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_all_but_final ] = hashed_given_all_but_final
                    
                #-- END check to see if given all but final index. --#


                # got an given final initial list index?
                if ( index_given_final_initial is not None ):

                    # we have an index.  Get value...
                    given_final_initial_value = current_record[ index_given_final_initial ]
                    
                    # ...hash...
                    hashed_given_final_initial = hash_name( given_final_initial_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_final_initial ] = hashed_given_final_initial
                    
                #-- END check to see if given final initial index. --#


                # got an final wordindex list index?
                if ( index_given_final_wordindex is not None ):

                    # we have an index.  Get value...
                    given_final_wordindex_value = current_record[ index_given_final_wordindex ]
                    
                    # ...hash...
                    hashed_given_final_wordindex = hash_name( given_final_wordindex_value )
                    
                    # ...and store in output row.
                    row_value_list[ index_given_final_wordindex ] = hashed_given_final_wordindex
                    
                #-- END check to see if final wordindex index. --#

                    
                
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
# Once the cell above has completed, you should now have two files, `hashed-Fake_Data_Test_001.csv` and `hashed-Fake_Data_Test_002.csv` in your output folder (by default, the same directory as this notebook).  The two input files are identical, so the resulting output should also be identical.
