import os
import shutil
import pwd
import stat
import sys
import logging

file_identifier = 'Folder'

logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format=f'{file_identifier} [%(levelname)s]: %(message)s')

def delete_folder(folder_path):
    if os.path.exists(folder_path):
        try:
            # Delete the entire folder and its contents
            shutil.rmtree(folder_path)
            logging.debug(f"Folder '{folder_path}' successfully deleted.")
        except PermissionError:
            logging.critical(f"Error: Permission denied. Make sure you have the necessary permissions.")
        except Exception as e:
            logging.error(f"Error: {e}")

def copy_folder(source_folder, destination_folder):
    try:
        # Copy the entire folder and its contents to the destination
        shutil.copytree(source_folder, destination_folder)
        logging.debug(f"Folder '{source_folder}' successfully copied to '{destination_folder}'.")
    except shutil.Error as e:
        logging.error(f"Error: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")

def move_file_keep_structure(source_prefix, source_path, destination_prefix):
    index = source_path.find(source_prefix)
    destination_path = destination_prefix + source_path[index + len(source_prefix):]
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    logging.debug("moving file from " + source_path)
    logging.debug("to " + destination_path)
    shutil.move(source_path, destination_path)
    return destination_path

# Copy file from source_path to destination_path
def copy_file_keep_structure(source_prefix, source_path, destination_prefix):
    index = source_path.find(source_prefix)
    destination_path = destination_prefix + source_path[index + len(source_prefix):]
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    logging.debug("copying file from " + source_path)
    logging.debug("to " + destination_path)
    shutil.copy(source_path, destination_path)
    return destination_path

# Copy file from source_path to destination_path, with new name final_name
def copy_file_keep_structure_new_name(source_prefix, source_path, destination_prefix, final_filename):
    relative_path = os.path.relpath(source_path, source_prefix)
    destination_path = os.path.join(destination_prefix, relative_path)
    destination_path = os.path.join(os.path.dirname(destination_path), final_filename)

    os.makedirs(os.path.dirname(destination_path), exist_ok=True)

    logging.debug("Copying file from " + source_path)
    logging.debug("To " + destination_path)

    shutil.copy(source_path, destination_path)
    return destination_path

def copy_file_new_name(source_prefix, source_path, destination_prefix, final_filepath):
    relative_path = os.path.relpath(final_filepath, source_prefix)
    destination_path = os.path.join(destination_prefix, relative_path)

    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    
    logging.debug("Copying file from " + source_path)
    logging.debug("To " + destination_path)

    shutil.copy(source_path, destination_path)
    return destination_path

def set_current_user_owner_recursive(directory_path):
    # Get the UID of the current real user

    if is_user_root():
        return

    try:
        real_user = os.getenv('SUDO_USER') or os.getenv('USER') or os.getenv('LOGNAME') or os.getlogin() or os.getenv('USERNAME')
    except OSError:
        real_user = os.getenv('SUDO_USER') or os.getenv('USER') or os.getenv('LOGNAME') or os.getenv('USERNAME')

    uid = pwd.getpwnam(real_user).pw_uid
    gid = pwd.getpwnam(real_user).pw_gid


    for root, dirs, files in os.walk(directory_path):
        # Change ownership for the directory itself
        os.chown(root, uid, gid)

        # Change ownership for subdirectories
        for dir_name in dirs:
            logging.debug(f"Changing ownership of {dir_name}")
            dir_path = os.path.join(root, dir_name)
            os.chown(dir_path, uid, gid)
            os.chmod(dir_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

        # Change ownership for files
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if os.path.exists(file_path):
                os.chown(file_path, uid, gid)
                os.chmod(file_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

def is_user_root():
    return os.geteuid() == 0