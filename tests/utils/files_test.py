import os
import tempfile
from pathlib import Path

from digital_signatures.utils.files import create_file

def test_create_file_with_text_content():
    """Test creating a file with text content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'test.txt')
        content = b'Hello, world!'
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_empty_content():
    """Test creating a file with empty content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'empty.txt')
        content = b''
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content is empty
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_binary_content():
    """Test creating a file with binary content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'binary.bin')
        content = b'\x00\x01\x02\x03\xff\xfe\xfd'
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_large_content():
    """Test creating a file with large content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'large.txt')
        content = b'A' * 10000  # 10KB of data
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content size
        assert os.path.getsize(file_path) == len(content)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_unicode_content():
    """Test creating a file with unicode content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'unicode.txt')
        content = 'Hello, 世界! 🌍'.encode('utf-8')
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_nested_directory():
    """Test creating a file in a nested directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        nested_dir = os.path.join(temp_dir, 'nested', 'directory')
        os.makedirs(nested_dir, exist_ok=True)
        
        file_path = os.path.join(nested_dir, 'test.txt')
        content = b'Nested file content'
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_overwrites_existing():
    """Test that creating a file overwrites existing content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'overwrite.txt')
        
        # Create initial file
        initial_content = b'Initial content'
        create_file(file_path, initial_content)
        
        # Verify initial content
        with open(file_path, 'rb') as f:
            assert f.read() == initial_content
        
        # Overwrite with new content
        new_content = b'New content'
        create_file(file_path, new_content)
        
        # Verify new content
        with open(file_path, 'rb') as f:
            assert f.read() == new_content


def test_create_file_with_special_characters_in_path():
    """Test creating a file with special characters in the path."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'file with spaces.txt')
        content = b'Content with special characters'
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_with_pathlib_path():
    """Test creating a file using pathlib.Path."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = Path(temp_dir) / 'pathlib_test.txt'
        content = b'Pathlib test content'
        
        create_file(str(file_path), content)
        
        # Verify file was created
        assert file_path.exists()
        assert file_path.is_file()
        
        # Verify content
        with open(file_path, 'rb') as f:
            assert f.read() == content


def test_create_file_permissions():
    """Test that created file has appropriate permissions."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file_path = os.path.join(temp_dir, 'permissions.txt')
        content = b'Permission test'
        
        create_file(file_path, content)
        
        # Verify file was created
        assert os.path.exists(file_path)
        assert os.path.isfile(file_path)
        
        # Verify file is readable
        with open(file_path, 'rb') as f:
            assert f.read() == content
        
        # Verify file is writable (can be opened for writing)
        with open(file_path, 'wb') as f:
            f.write(b'Modified content')
