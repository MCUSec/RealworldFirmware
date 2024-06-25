'''
Script to create Function ID database
'''
import time
import json
import argparse
import logging 
from pathlib import Path 
from utils.launcher import HeadlessLoggingPyhidraLauncher
log_time = time.strftime("%Y-%m-%d_%H:%M:%S")
    
def report(name, result):
    logging.info(f'{name}')
    logging.info(f'{result.getTotalAttempted()} total functions visited')
    logging.info(f'{result.getTotalAdded()} total functions added')
    logging.info(f'{result.getTotalExcluded()} total functions excluded')
    logging.info(f'Breakdown for exclusions')
    for entry in result.getFailures().entrySet():
        logging.info(f'   {entry.getKey()}: {entry.getValue()}')
    logging.info(f'List of unresolved symbols:')
    function_names = set()
    for loc_ in result.getUnresolvedSymbols():
        function_names.add(loc_.getFunctionName())
    for name_ in function_names:
        logging.info(f'   {name_}')

def CreateFunctionID(service, fidDb, name, file, langID, monitor):
    from java.io import IOException
    from java.lang import IllegalStateException, NullPointerException
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.util.exception import CancelledException, VersionException
    from java.util import ArrayList
    try:
        result_ = service.createNewLibraryFromPrograms(fidDb, 
                name, "1.0", "", ArrayList([file]), None, langID, None, None, monitor)
        report(name, result_)
    except CancelledException as e:
        logging.error(f'Cancell {name} {e.getMessage()}')
    except MemoryAccessException as e:
        logging.error(f'Unexpected memory access exception {e.getMessage()}')
    except VersionException as e:
        logging.error(f'Version Exception {e.getMessage()}')
    except IllegalStateException as e:
        logging.error(f'Illegal State Exception {e.getMessage()}')
    except IOException as e:
        logging.error(f'FidDb IOException {e.getMessage()}')
    except NullPointerException as e: # has been fixed in 11.1, but keep it
        logging.error(f'FidDb NullPointerException {e.getMessage()}')
        
def create(args):
    launcher = HeadlessLoggingPyhidraLauncher(verbose=True, log_path=f'./logs/Pyhidra_{args.project_name}.log')
    launcher.start()
    # import 
    from ghidra.base.project import GhidraProject
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService
    from ghidra.util.task import ConsoleTaskMonitor

    # create or open project 
    try:
        project = GhidraProject.openProject(args.project_path, args.project_name, True)
        logging.info(f'Opened project: {project.project.name}')
    except IOException:
        loggin.error(f'No this project {args.project_path}/{args.project_name}')
        return 

    monitor = ConsoleTaskMonitor()
    service = FidService()
    fidb_path = Path(f'./fidb/{args.fid_name}.fidb')
    # create FunctionID
    FidFileManager.getInstance().createNewFidDatabase(fidb_path)
    fidfiles = FidFileManager.getInstance().getUserAddedFiles()
    if len(fidfiles) > 1:
        logging.error("multiple fid files {fidfiles}")
        return 
    logging.debug(f'create fid file {fidfiles}')
    fidfile = fidfiles[0]
    fidDb = fidfile.getFidDB(True)
    num = 0
    for file_ in project.getRootFolder().getFiles():
        name_ = file_.getName()
        monitor.setMessage(f'Create FunctionID db from {name_}')
        program_ = project.openProgram('/', file_.getName(), True)
        langID_ = program_.getLanguageID()
        project.close(program_)
        CreateFunctionID(service, fidDb, name_, file_, langID_, monitor)
        num += 1
    logging.debug("Saving FuntionID database")
    fidDb.saveDatabase("Saving", monitor)
    fidDb.close()
    project.close()
    logging.info("Finish, Exit")  

#################################
# Search Function ID

def processMatches(result, program, nameAnalysis, monitor) -> list:
    if result.matches.size() == 0:
        return 
    matches_ = []
    names_ = set()
    for match in result.matches:
        function = match.getFunctionRecord()
        fname_ = function.getName()
        # deduplicate the function based on the name
        if fname_ not in names_:
            names_.add(fname_)
            library = match.getLibraryRecord().toString()
            matches_.append((fname_, library))
    return matches_ 
    

SCORE_THRESHOLD = 14.6
def search_fid(program, monitor, nameAnalysis):
    '''
    search matches of every function in the program and return 
    '''
    from java.io import IOException
    from ghidra.util.exception import CancelledException, VersionException
    from ghidra.feature.fid.service import FidService
    service = FidService()
    pmatches = {}
    if not service.canProcess(program.getLanguage()):
        logging.error(f'{program.getName()} can not process by function id')
    try:
        fidQueryService = service.openFidQueryService(program.getLanguage(), False)
        # monitor.setMessage("FID Analysis")
        # real operation 
        result_ = service.processProgram(program, fidQueryService, SCORE_THRESHOLD, monitor)
        if result_ is None:
            logging.info(f"Search failed for {program.getName()}")
        for entry in result_:
            monitor.checkCancelled()
            monitor.incrementProgress(1)
            if entry.function.isThunk():
                continue 
            if entry.matches.isEmpty():
                logging.debug(f'no result for {entry.function.getName()}')
            else:
                fmatches = processMatches(entry, program, nameAnalysis, monitor)
                if len(fmatches) != 0:
                    pmatches[entry.function.getName()] = fmatches
    except CancelledException as e:
        logging.info('Cancelled')
    except VersionException as e:
        logging.error(f"Version Exception {e.getMessage()}")
    except IOException as e:
        logging.error(f"IOException {e.getMessage()}")
    return pmatches
    

def search(args):
    launcher = HeadlessLoggingPyhidraLauncher(verbose=True, log_path=f'./logs/Pyhidra_{args.project_name}.log')
    launcher.start()
    # import 
    from ghidra.base.project import GhidraProject
    from ghidra.feature.fid.db import FidFileManager
    from ghidra.feature.fid.service import FidService, MatchNameAnalysis
    from ghidra.util.task import ConsoleTaskMonitor
    # create or open project 
    try:
        project = GhidraProject.openProject(args.project_path, args.project_name, True)
        logging.info(f'Opened project: {project.project.name}')
    except IOException:
        loggin.error(f'No this project {args.project_path}/{args.project_name}')
        return 

    monitor = ConsoleTaskMonitor()
    service = FidService()
    fidb_path = Path(f'./fidb/{args.fid_name}.fidb')
    # create FunctionID
    FidFileManager.getInstance().addUserFidFile(fidb_path)
    nameAnalysis = MatchNameAnalysis()
    # statistic value 
    all_matches = {}
    match_num = []
    start_time = time.time()
    # real operation
    for file_ in project.getRootFolder().getFiles():
        name_ = file_.getName()
        program_ = project.openProgram('/', file_.getName(), True)
        logging.info(f"Search {name_} start")
        pmatches = search_fid(program_, monitor, nameAnalysis)
        if len(pmatches) != 0:
            match_num.append([name_,len(pmatches)])
            all_matches[name_[:name_.find('noheader')]] = pmatches
        monitor.setMessage(f"{name_} matches {len(pmatches)} functions")
        logging.info(f"{name_} matches {len(pmatches)} functions")
        project.close(program_)
    # write results
    logging.info(f'Total Search Time {time.time()-start_time} for {len(match_num)} programs')
    with open(f'./res/functionID_{args.project_name}_{args.fid_name}_{log_time}.json', 'w') as file:
        json.dump(all_matches, file, indent=4)
    with open(f'./res/functionID_{args.project_name}_{args.fid_name}_{log_time}.csv', 'w') as file:
        file.write("Program,match\n")
        for i in match_num:
            file.write(f'{i[0]},{i[1]}\n')
    # end 
    project.close()
    logging.info("Finish, Exit")  

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Create Fid database from ghdira project")
    parser.add_argument("-c", "--create", action="store_true", help="create function ID database")
    parser.add_argument("-s", "--search", action="store_true", help="search function in program of the project using function ID database")
    parser.add_argument("project_path",type=Path,default=Path('./ghidra_projects'))
    parser.add_argument("project_name",default="arm_database_project")
    parser.add_argument("fid_name",default="test",help="Name of FunctionID database")
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(filename=f'./logs/fidb_{log_time}.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)
    try:
        if args.create and args.search:
            logging.error("Cannot both search and create at the same time")
        elif args.create:
            create(args)
        elif args.search:
            search(args)
    except KeyboardInterrupt:
        logging.error("Exit with keyboard")
        project.close()
