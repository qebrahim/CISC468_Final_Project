import os


def manage_file_storage(file_path, action, data=None):
    """
    Manages file storage and retrieval on the local device.

    :param file_path: The path to the file to be managed.
    :param action: The action to perform - 'read', 'write', or 'delete'.
    :param data: The data to write if the action is 'write'.
    :return: The content of the file if reading, None otherwise.
    """
    if action == 'read':
        try:
            with open(file_path, 'rb') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Error: The file {file_path} does not exist.")
            return None
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

    elif action == 'write':
        try:
            with open(file_path, 'wb') as file:
                file.write(data)
                print(f"File {file_path} written successfully.")
        except Exception as e:
            print(f"Error writing to file {file_path}: {e}")

    elif action == 'delete':
        try:
            os.remove(file_path)
            print(f"File {file_path} deleted successfully.")
        except FileNotFoundError:
            print(f"Error: The file {file_path} does not exist.")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

    else:
        print("Error: Invalid action. Use 'read', 'write', or 'delete'.")
