import os 
import time
import json
import logging
import argparse
from functools import reduce
from operator import mul
from pathlib import Path
from utils.db import *
from utils.key import *
from utils.match import *
from utils.ghidra_helper import *
from utils.launcher import HeadlessLoggingPyhidraLauncher

log_time = time.strftime("%Y-%m-%d_%H:%M:%S")

def timeout_handler(signum, frame):
    raise TimeoutError("Timed out!")

def main(args):

    # pyhidra launcher 
    launcher = HeadlessLoggingPyhidraLauncher(verbose=True, log_path=f'./logs/Pyhidra_{args.project_name}_{log_time}.log')
    launcher.start()
    
    # create project
    from java.io import IOException
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import ConsoleTaskMonitor
    monitor = ConsoleTaskMonitor()

    # Create Project Dir and name 
    project_location = args.project_path
    project_location.mkdir(exist_ok=True, parents=True)
    project_name = args.project_name

    # create or open project 
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        logging.info(f'Opened project: {project.project.name}')
    except IOException:
        logging.error(f'No project: {project.project.name}')
        return 

    db_ = Path('./db/binfunc_' + args.project_name + ".db")
    if db_.exists():
        # TODO: skip the existed function
        logging.error(f'{db_} exist, remove it')
        os.remove(db_)
    conn = sqlite3.connect(db_)
    cursor = conn.cursor()
    sql_create_table(cursor, FUNC_KEYS, FUNC_TABLE_NAME)
    sql_create_index(cursor, FUNC_TABLE_NAME,['hash'],'index_hash')
    conn.commit()
    num = 0
    func_num = []
    start_time = time.time()
    #signal.signal(signal.SIGALRM, timeout_handler)
    for file_ in project.getRootFolder().getFiles():
        name_ = file_.getName()
        monitor.setMessage(f'Create Database for {name_} at {num}')
        program = project.openProgram('/', name_, True)
        rows_ = []
        for func_ in program.getListing().getFunctions(True):
            if filter_func(func_):
                row_ = (func_.getName(),program.getName())
                inst_ = get_inst_key(func_)
                graph = get_struct_graph_key(func_)
                # make sure the inst_[0] means the numAddress 
                hash_ = reduce(mul,(n for n in graph),1) * inst_[0]
                #if hash_ >= 0xffffffff:
                #    print(f'WARNING: {func_.getName()} hash is a little long {hash_}')
                row_ += (hash_,) + inst_ + graph
                # no check because every bin is different 
                if args.deduplicate:
                    if not sql_check_duplicate_func(cursor, row_[func_key_idx('name')], row_[func_key_idx('hash')], FUNC_TABLE_NAME):
                        rows_.append(row_)
                else:
                    rows_.append(row_)
            # insert the rows    
        sql_insert(cursor, FUNC_KEYS.keys(), rows_, FUNC_TABLE_NAME)
        conn.commit()      
        # remember closing the program to avoid memory usage 
        logging.info(f"{program.getName()} insert {len(rows_)} functions at {num}")
        monitor.setMessage(f"{program.getName()} insert {len(rows_)} functions at {num}")
        func_num.append([name_, len(rows_)])
        num += 1
        project.close(program)
    # write csv 
    with open(f'./res/MatchDB_{project_name}.csv', 'w') as file:
        file.write('Program, Functions\n')
        for i in func_num:
            file.write(f"{i[0]}, {i[1]}\n")
    # end
    logging.info(f"Finish: total annalysis time {time.time() - start_time}")
    conn.close()
    project.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Create Fid database from ghdira project")
    parser.add_argument("project_path",type=Path,default=Path('./ghidra_projects'))
    parser.add_argument("project_name",default="arm_firms")
    parser.add_argument("-d", "--deduplicate",action="store_true")
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(filename=f'./logs/MatchDB_{args.project_name}_{log_time}.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        main(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        project.close() 
