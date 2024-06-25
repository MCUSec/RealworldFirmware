import sys
sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import config

output_folder = config.get_folder("crawler.files_folder")

fw_pairs = {}

def process_line(line):
    index = line.find(",pl:")
    if "/UPDATE" in line[:index]:
        id_start = line.find("/DEVICE_POLICY/") + len("/DEVICE_POLICY/")
        id_end = line.find("/UPDATE")
        dev_id = line[id_start:id_end]
        if dev_id not in fw_pairs:
            fw_pairs[dev_id] = []

    if len(line) > 400:
        if "FirmwareUpdatePayload" in line:
            current_device_id = None
            for id in fw_pairs:
                if id in line[:index]:
                    current_device_id = id
                    continue

            if current_device_id:
                start = line.find("Value=\\\"") + len("Value=\\\"")
                interm_data = line[start:]
                end = interm_data.find("\\\"")
                data = interm_data[:end]
                fw_pairs[current_device_id].append(data)
            else:
                topic_string = line[:index]
                current_device_id = topic_string[topic_string.rfind("/")+1:]
                fw_pairs[current_device_id] = []

                start = line.find("Value=\\\"") + len("Value=\\\"")
                interm_data = line[start:]
                end = interm_data.find("\\\"")
                data = interm_data[:end]
                fw_pairs[current_device_id].append(data)


def get_chunks(filepath):
    with open(filepath, 'r') as data:
        for line in data:
            process_line(line)


def convert_chunks_to_file(key):
    # Extract data from each chunk and concatenate
    print("key: " + key)
    appended_chunks = set()

    full_data = ''
    for chunk in fw_pairs[key]:
        chunk_info = chunk.split(":")[3].split('#')
        chunk_number = chunk_info[0]
        if chunk_number not in appended_chunks:
            appended_chunks.add(chunk_number)
            full_data += chunk_info[2].replace('-', '')

    # Convert concatenated data to bytes
    bytes_data = bytes.fromhex(full_data)

    file_name = key + ".bin"
    output_path = os.path.join(output_folder, file_name)

    # Write bytes to a file
    with open(output_path, 'wb') as f:
        f.write(bytes_data)

# Example
# chunks = [
#     "0:2:Write:n1#N3#3E-0E-F0-DF",
#     "0:2:Write:n2#N3#23-A2-5C-62",
#     "0:2:Write:n3#N3#F7-7D-E5"
# ]

def main():
    input_file = sys.argv[1]
    get_chunks(input_file)
    for key in fw_pairs:
        convert_chunks_to_file(key)

if __name__ == "__main__":
    main()