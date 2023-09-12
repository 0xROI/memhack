import os
from pycparser import parse_file

def parse_source_code(folder_path):
    for filename in os.listdir(folder_path):
        if filename.endswith(".c"):
            file_path = os.path.join(folder_path, filename)
            try:
                ast = parse_file(file_path)
                print("Parsing completed for:", filename)
            except Exception as e:
                print("Parsing failed for:", filename)
                print(e)
