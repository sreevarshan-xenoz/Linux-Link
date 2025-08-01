"""
Tests for file manager functionality
"""

import pytest
import os
import tempfile
from unittest.mock import patch, Mock
from file_manager import get_file_manager, FileManagerError


class TestFileManager:
    """Test file manager operations"""
    
    def test_browse_directory(self, temp_dir):
        """Test directory browsing"""
        # Create test files
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        test_dir = os.path.join(temp_dir, "subdir")
        os.makedirs(test_dir)
        
        fm = get_file_manager()
        result = fm.browse_directory(temp_dir)
        
        assert result["success"] is True
        assert len(result["items"]) >= 2
        
        # Check for test file and directory
        names = [item["name"] for item in result["items"]]
        assert "test.txt" in names
        assert "subdir" in names
    
    def test_browse_nonexistent_directory(self):
        """Test browsing non-existent directory"""
        fm = get_file_manager()
        
        with pytest.raises(FileManagerError):
            fm.browse_directory("/nonexistent/path")
    
    def test_get_file_info(self, temp_dir, sample_file_content):
        """Test getting file information"""
        test_file = os.path.join(temp_dir, "info_test.txt")
        with open(test_file, 'w') as f:
            f.write(sample_file_content)
        
        fm = get_file_manager()
        info = fm.get_file_info(test_file)
        
        assert info["name"] == "info_test.txt"
        assert info["size"] == len(sample_file_content)
        assert info["type"] == "file"
        assert "permissions" in info
        assert "modified_time" in info
    
    def test_create_directory(self, temp_dir):
        """Test directory creation"""
        new_dir = os.path.join(temp_dir, "new_directory")
        
        fm = get_file_manager()
        result = fm.create_directory(new_dir)
        
        assert result is True
        assert os.path.exists(new_dir)
        assert os.path.isdir(new_dir)
    
    def test_delete_file(self, temp_dir):
        """Test file deletion"""
        test_file = os.path.join(temp_dir, "delete_me.txt")
        with open(test_file, 'w') as f:
            f.write("delete this")
        
        assert os.path.exists(test_file)
        
        fm = get_file_manager()
        result = fm.delete_file(test_file)
        
        assert result is True
        assert not os.path.exists(test_file)
    
    def test_copy_file(self, temp_dir, sample_file_content):
        """Test file copying"""
        source_file = os.path.join(temp_dir, "source.txt")
        dest_file = os.path.join(temp_dir, "destination.txt")
        
        with open(source_file, 'w') as f:
            f.write(sample_file_content)
        
        fm = get_file_manager()
        result = fm.copy_file(source_file, dest_file)
        
        assert result is True
        assert os.path.exists(dest_file)
        
        with open(dest_file, 'r') as f:
            assert f.read() == sample_file_content
    
    def test_move_file(self, temp_dir, sample_file_content):
        """Test file moving"""
        source_file = os.path.join(temp_dir, "move_source.txt")
        dest_file = os.path.join(temp_dir, "move_dest.txt")
        
        with open(source_file, 'w') as f:
            f.write(sample_file_content)
        
        fm = get_file_manager()
        result = fm.move_file(source_file, dest_file)
        
        assert result is True
        assert not os.path.exists(source_file)
        assert os.path.exists(dest_file)
        
        with open(dest_file, 'r') as f:
            assert f.read() == sample_file_content
    
    def test_rename_file(self, temp_dir, sample_file_content):
        """Test file renaming"""
        original_file = os.path.join(temp_dir, "original.txt")
        new_name = "renamed.txt"
        
        with open(original_file, 'w') as f:
            f.write(sample_file_content)
        
        fm = get_file_manager()
        result = fm.rename_file(original_file, new_name)
        
        assert result is True
        assert not os.path.exists(original_file)
        
        renamed_file = os.path.join(temp_dir, new_name)
        assert os.path.exists(renamed_file)
        
        with open(renamed_file, 'r') as f:
            assert f.read() == sample_file_content
    
    @patch('file_manager.os.access')
    def test_permission_check(self, mock_access, temp_dir):
        """Test permission checking"""
        mock_access.return_value = False
        
        fm = get_file_manager()
        
        with pytest.raises(FileManagerError):
            fm.browse_directory(temp_dir)
    
    def test_get_disk_usage(self, temp_dir):
        """Test disk usage calculation"""
        # Create some test files
        for i in range(3):
            test_file = os.path.join(temp_dir, f"test_{i}.txt")
            with open(test_file, 'w') as f:
                f.write("x" * 1000)  # 1KB each
        
        fm = get_file_manager()
        usage = fm.get_disk_usage(temp_dir)
        
        assert usage["total_size"] >= 3000  # At least 3KB
        assert usage["file_count"] >= 3
        assert "directories" in usage
    
    def test_search_files(self, temp_dir):
        """Test file searching"""
        # Create test files
        files = ["test.txt", "example.py", "test_data.json", "readme.md"]
        for filename in files:
            with open(os.path.join(temp_dir, filename), 'w') as f:
                f.write(f"content of {filename}")
        
        fm = get_file_manager()
        
        # Search for files containing "test"
        results = fm.search_files(temp_dir, "test")
        result_names = [os.path.basename(r["path"]) for r in results]
        
        assert "test.txt" in result_names
        assert "test_data.json" in result_names
        assert "example.py" not in result_names
    
    def test_file_preview(self, temp_dir):
        """Test file preview functionality"""
        test_file = os.path.join(temp_dir, "preview.txt")
        content = "Line 1\\nLine 2\\nLine 3\\nLine 4\\nLine 5"
        
        with open(test_file, 'w') as f:
            f.write(content)
        
        fm = get_file_manager()
        preview = fm.get_file_preview(test_file, max_size=1024)
        
        assert preview["success"] is True
        assert "Line 1" in preview["content"]
        assert preview["size"] == len(content)
        assert preview["truncated"] is False