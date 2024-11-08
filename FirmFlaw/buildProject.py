import os
import time
import json
import signal
import logging
import argparse
from utils.key import *
from pathlib import Path
from utils.ghidra_helper import *
from utils.launcher import HeadlessLoggingPyhidraLauncher

log_time = time.strftime("%Y-%m-%d_%H:%M:%S")
func_num = None
project = None
start_time = None


def timeout_handler(signum, frame):
    raise TimeoutError("Timed out!")


def is_elf(firm: Path) -> bool:
    with open(firm, "rb") as file:
        b = file.read(4)
    if b[1:] == b"ELF":
        return True
    return False


def firmware_size(dir: Path) -> dict:
    firmware_size_ = {}
    for root, dirs, files in os.walk(dir):
        files = [f for f in files if not f.endswith("json")]
        dir_ = Path(root)
        for f in files:
            firmware_size_[f] = os.path.getsize(dir_ / f)
    return firmware_size_


def main(args):
    global func_num
    global project
    global start_time
    # pyhidra launcher
    launcher = HeadlessLoggingPyhidraLauncher(
        verbose=True, log_path=f"./logs/Pyhidra_{args.project_name}_{log_time}.log"
    )
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
        logging.info(f"Opened project: {project.project.name}")
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)
        logging.info(f"Created project: {project.project.name}")

    lang = get_language(lang_str())

    exist_bins_ = set()
    func_num = []
    firm_size = firmware_size(args.file_path)
    num = 0
    for file_ in project.getRootFolder().getFiles():
        noheader_ = file_.getName()
        name_ = noheader_[: noheader_.find("noheader")]
        program_ = project.openProgram("/", noheader_, True)
        funcs_ = program_.getFunctionManager().getFunctionCount()
        if funcs_ == 0:
            flat_api = FlatProgramAPI(program_)
            flat_api.analyzeAll(program_)
        funcs_ = program_.getFunctionManager().getFunctionCount()
        if (size_ := firm_size.get(name_)) is None:
            logging.error(f"Cannot get size of {name_}")
        func_num.append([name_, 0, funcs_, size_, 0])
        project.close(program_)
        exist_bins_.add(noheader_)
        num += 1

    start_time = time.time()
    analysis_time = time.time()
    signal.signal(signal.SIGALRM, timeout_handler)
    for root, dirs, files in os.walk(args.file_path):
        # filter out the json file
        firmwares = [f for f in files if not f.endswith("json")]
        dir_ = Path(root)
        for file_ in firmwares:
            firm_ = dir_ / file_
            if is_elf(firm_):
                noheader_ = firm_
            else:
                noheader_ = firm_valid(firm_)
            if noheader_ is None:
                continue
            logging.info(f"Iter file {firm_} at {num}")
            monitor.setMessage(f"\033[31mIter file {firm_} at {num}\033[0m")
            # firmware has been analyzed
            if noheader_.name in exist_bins_:
                print(f"skip")
                logging.info(f"Skip file {firm_} at {num} because ghidra project exist")
                continue
            # timeout and try
            logging.debug(
                f"import {noheader_.name} with base address {base_address(firm_)}"
            )
            analysis_time = time.time()
            if is_elf(noheader_):
                program = project.importProgram(noheader_)
            else:
                program = project.importProgram(
                    noheader_, lang, get_compiler_spec(lang)
                )
            signal.alarm(600)
            try:
                handler_num = 0
                flat_api = FlatProgramAPI(program)
                # edit when not elf
                if not is_elf(noheader_):
                    old_base = program.getImageBase()
                    image_base = base_address(firm_)
                    # 1. setImageBase (Address base, boolean commit)
                    program.setImageBase(old_base.getNewAddress(image_base), True)
                    # 2. create interrupt handlers
                    handler_num = create_handlers(program, flat_api)
                flat_api.analyzeAll(program)
                analysis_time = int(time.time() - analysis_time)
                func_num.append(
                    [
                        file_,
                        handler_num,
                        program.getFunctionManager().getFunctionCount(),
                        os.path.getsize(noheader_),
                        analysis_time,
                    ]
                )
                monitor.setMessage(
                    f"\033[31mAdd {program.getFunctionManager().getFunctionCount()} functions\033[0m"
                )
                logging.info(
                    f"Add {program.getFunctionManager().getFunctionCount()} functions"
                )
                num += 1
            except TimeoutError:
                logging.info(f"Analyze {file_} timeout!!")
                func_num.append([file_, -1, -1, os.path.getsize(noheader_), -1])
            finally:
                signal.alarm(0)
            project.saveAs(program, "/", program.getName(), True)
            project.close(program)
    # write csv
    with open(f"./res/func_num_{project_name}.csv", "w") as file:
        file.write("Program, Handlers, Functions, Size, AnalysisTime\n")
        for i in func_num:
            line = ", ".join(str(j) for j in i) + "\n"
            file.write(line)
    # end
    logging.info("Finish: total annalysis time {time.time() - start_time}")
    project.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Create Fid database from ghdira project")
    parser.add_argument("project_path", type=Path, default=Path("./ghidra_projects"))
    parser.add_argument("project_name", default="arm_firms")
    parser.add_argument(
        "file_path", default="./firmwares/", help="Path of firmware files"
    )
    parser.add_argument(
        "-s",
        "--script",
        type=Path,
        default=Path("./utils/valid.py"),
        help="Script of firmware valid functions",
    )
    args = parser.parse_args()
    # log
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
    logging.basicConfig(
        filename=f"./logs/buildProject_{args.project_name}_{log_time}.log",
        level=logging.DEBUG,
        format=LOG_FORMAT,
        datefmt=DATE_FORMAT,
    )
    try:
        if not args.project_path.exists():
            logging.error("Invalid project path")
        elif not args.script.exists():
            logging.error("Invalid valid script")
        else:
            # exec valid script
            with open(args.script, "r") as file:
                exec(file.read())
            main(args)
    except KeyboardInterrupt:
        if start_time is not None:
            logging.info("Finish: total annalysis time {time.time() - start_time}")
        logging.error("Exit with keyboard")
        project.close()
        if func_num is not None:
            # write csv
            with open(f"./res/func_num_{project_name}.csv", "w") as file:
                file.write("Program, Handlers, Functions, Size, AnalysisTime\n")
                for i in func_num:
                    line = ", ".join(j for j in i) + "\n"
                    file.write(line)
            # end
