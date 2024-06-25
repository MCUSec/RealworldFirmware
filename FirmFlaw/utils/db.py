# Task 2: define some sql sentences such as create table and index, insert sql 
import sqlite3 

FUNC_TABLE_NAME = 'func_table'
# the columns name and type in function table 
FUNC_KEYS  = {
    'name':'TEXT',
    'program':'TEXT',
    'hash':'INTEGER',
    'numAddresses':'INTEGER',
    'mnemonics':'TEXT',
    'block_num':'INTEGER',
    'edge_num':'INTEGER',
    'call_num':'INTEGER',
    'jump_num':'INTEGER'
}

keys_ = list(FUNC_KEYS.keys())
def func_key_idx(key_name: str) -> int:
    return keys_.index(key_name)
    


def sql_create_table(cursor: sqlite3.Cursor, keys: dict, table_name: str):
    create_sql_ = f'CREATE TABLE IF NOT EXISTS {table_name} (id INTEGER PRIMARY KEY,' + ','.join(f'{k} {v}' for (k,v) in keys.items()) + ');'
    print(create_sql_)
    cursor.execute(create_sql_)
    
def sql_create_index(cursor: sqlite3.Cursor, table_name: str, index: list, index_name: str):
    '''
    create index in sql 
    '''
    create_index_ = f'CREATE INDEX IF NOT EXISTS {index_name} on {table_name}(' + ','.join(item for item in index) + ');'
    print(create_index_)
    cursor.execute(create_index_)

from typing import KeysView
def sql_insert(cursor : sqlite3.Cursor, keys: KeysView[str], val: list, table_name: str):
    '''
    insert mutiple rows 
    '''
    # TODO: add the deduplication of database 
    insert_sql_ = f'INSERT INTO {table_name} (' + ','.join(item for item in keys) + ') VALUES (' + ','.join('?' for item in keys) + ')'
    cursor.executemany(insert_sql_, val)
    
def sql_check_duplicate_func(cursor: sqlite3.Cursor, func_name: str, hash_: int, table_name: str) -> bool:
    '''
    check the similar sql lines 
    '''
    check_sql_ = f'SELECT hash from {table_name} WHERE name = "{func_name}"'
    cursor.execute(check_sql_)
    results = cursor.fetchall()
    for db_hash_ in results:
        # configuration for 0.95
        if 0.95 < (db_hash_[0] / hash_) < 1.05:
            # print(f'Duplicate Function {func_name} rate {db_hash_[0] / hash_}')
            return True 
    return False 

def test_import():
    return "Success import database"