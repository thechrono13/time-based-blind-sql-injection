# Time-Based-Blind-SQL-Injection Tool

This tool lets the user test security of a web application with respect to Time Based Blind SQL Injection.

The tool takes in input an URL, a method, a list of possibly vulnerable fields and a list of valid values for the respctive fields.
Once found, the tool ask the user to select a database and a table to dump, after it prints the results.

Usage: time_based_blind_sql_injection.py [-h] [-s SLEEP] [-t THREADS] [-v] <url> <GET|POST> <fields> <values>
