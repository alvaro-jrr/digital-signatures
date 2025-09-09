
def create_file(file_path: str, content: bytes):
  """Creates a file with the given content."""

  with open(file_path, 'wb') as file:
    file.write(content)
