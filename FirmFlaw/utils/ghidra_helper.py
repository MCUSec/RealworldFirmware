from pathlib import Path
# helper funcs 
def get_language(id: str) -> "Language":
    from ghidra.program.util import DefaultLanguageService
    from ghidra.program.model.lang import LanguageID, LanguageNotFoundException
    try:
        service: "LanguageService" = DefaultLanguageService.getLanguageService()
        return service.getLanguage(LanguageID(id))
    except LanguageNotFoundException:
        # suppress the java exception
        pass
    raise ValueError("Invalid Language ID: "+id)
   
def get_compiler_spec(lang: "Language", id: str = None) -> "CompilerSpec":
    if id is None:
        return lang.getDefaultCompilerSpec()
    from ghidra.program.model.lang import CompilerSpecID, CompilerSpecNotFoundException
    try:
        return lang.getCompilerSpecByID(CompilerSpecID(id))
    except CompilerSpecNotFoundException:
        # suppress the java exception
        pass
    lang_id = lang.getLanguageID()
    raise ValueError(f"Invalid CompilerSpecID: {id} for Language: {lang_id.toString()}")

def openProject(project_name: str, project_location: Path) -> 'ghidra.base.project.GhidraProject': 
    from java.io import IOException
    from ghidra.base.project import GhidraProject
    # create or open project 
    try:
        project = GhidraProject.openProject(project_location, project_name, True)
        print(f'Opened project: {project.project.name}')
    except IOException:
        project = GhidraProject.createProject(project_location, project_name, False)
        print(f'Created project: {project.project.name}')
    return project
