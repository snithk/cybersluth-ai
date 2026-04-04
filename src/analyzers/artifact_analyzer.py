import logging
import os
import json
from datetime import datetime
import numpy as np
from src.models.ml_models import ImageAnalyzer, TextAnalyzer
import hashlib
from PIL import Image

logger = logging.getLogger(__name__)

class ArtifactAnalyzer:
    def __init__(self):
        self.image_analyzer = ImageAnalyzer()
        self.text_analyzer = TextAnalyzer()
        self.suspicious_extensions = {
            'executables': ['.exe', '.dll', '.sys', '.scr', '.bat', '.cmd'],
            'scripts': ['.ps1', '.vbs', '.js', '.py', '.sh'],
            'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx'],
            'compressed': ['.zip', '.rar', '.7z', '.tar', '.gz']
        }

    def analyze_artifacts(self, directory=None):
        """Analyze digital artifacts in the specified directory"""
        if directory is None:
            directory = os.getcwd()

        findings = {
            'suspicious_files': [],
            'analyzed_images': [],
            'extracted_text': [],
            'statistics': {
                'total_files': 0,
                'suspicious_count': 0,
                'type_distribution': {}
            }
        }

        try:
            excluded_dirs = {'env', 'venv', '.git', '__pycache__', 'node_modules', '.venv'}
            for root, dirs, files in os.walk(directory):
                # Modify dirs in-place to skip excluded directories
                dirs[:] = [d for d in dirs if d not in excluded_dirs]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    self._analyze_file(file_path, findings)

            self._generate_analysis_summary(findings)
            return findings

        except Exception as e:
            logger.error(f"Error during artifact analysis: {str(e)}")
            raise

    def _analyze_file(self, file_path, findings):
        """Analyze individual file"""
        try:
            findings['statistics']['total_files'] += 1
            
            # Get file extension and basic metadata
            file_ext = os.path.splitext(file_path)[1].lower()
            file_size = os.path.getsize(file_path)
            
            # Guess file type based on extension
            file_type = self._guess_file_type(file_ext)
            
            # Update type distribution
            findings['statistics']['type_distribution'][file_type] = \
                findings['statistics']['type_distribution'].get(file_type, 0) + 1

            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if file is suspicious
            if self._is_suspicious_file(file_path, file_ext):
                findings['suspicious_files'].append({
                    'path': file_path,
                    'type': file_type,
                    'size': file_size,
                    'hash': file_hash,
                    'timestamp': datetime.fromtimestamp(os.path.getctime(file_path))
                })
                findings['statistics']['suspicious_count'] += 1

            # Analyze based on file type
            if file_ext.lower() in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
                self._analyze_image(file_path, findings)
            elif file_ext.lower() in ['.txt', '.log', '.csv', '.md', '.json', '.xml', '.html']:
                self._analyze_text(file_path, findings)

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")

    def _guess_file_type(self, file_ext):
        """Guess file type based on extension"""
        ext_to_type = {
            '.txt': 'text/plain',
            '.log': 'text/plain',
            '.csv': 'text/csv',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.exe': 'application/x-msdownload',
            '.dll': 'application/x-msdownload',
            '.zip': 'application/zip',
            '.rar': 'application/x-rar-compressed',
            '.7z': 'application/x-7z-compressed'
        }
        return ext_to_type.get(file_ext.lower(), 'application/octet-stream')

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _is_suspicious_file(self, file_path, file_ext):
        """Check if file is suspicious based on various criteria"""
        # Check extension
        for category, extensions in self.suspicious_extensions.items():
            if file_ext in extensions:
                return True

        # Check file size anomalies
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # Files larger than 100MB
            return True

        # Check for hidden files
        if os.path.basename(file_path).startswith('.'):
            return True

        # Check for unusual permissions
        try:
            if os.access(file_path, os.X_OK) and not file_ext in self.suspicious_extensions['executables']:
                return True
        except:
            pass

        return False

    def _analyze_image(self, file_path, findings):
        """Analyze image files for suspicious content"""
        try:
            with Image.open(file_path) as img:
                # Extract metadata
                metadata = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size
                }
                
                # Convert image to numpy array for analysis
                img_array = np.array(img)
                
                # Perform image analysis using ML model
                analysis_result = self.image_analyzer.analyze(img_array)

                findings['analyzed_images'].append({
                    'path': file_path,
                    'metadata': metadata,
                    'analysis_result': analysis_result
                })

        except Exception as e:
            logger.error(f"Error analyzing image {file_path}: {str(e)}")

    def _analyze_text(self, file_path, findings):
        """Analyze text files for suspicious content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Analyze text content using ML model
                analysis_result = self.text_analyzer.analyze(content)
                
                if analysis_result['suspicious']:
                    findings['extracted_text'].append({
                        'path': file_path,
                        'analysis': analysis_result,
                        'excerpt': content[:1000]  # First 1000 characters
                    })

        except Exception as e:
            logger.error(f"Error analyzing text file {file_path}: {str(e)}")

    def _generate_analysis_summary(self, findings):
        """Generate summary of analysis findings"""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_files_analyzed': findings['statistics']['total_files'],
            'suspicious_files_found': findings['statistics']['suspicious_count'],
            'type_distribution': findings['statistics']['type_distribution'],
            'suspicious_images_found': len(findings['analyzed_images']),
            'suspicious_text_files': len(findings['extracted_text'])
        }
        
        findings['summary'] = summary
        
        # Log summary
        logger.info(f"Analysis Summary: {json.dumps(summary, indent=2)}")

    def get_statistics(self):
        """Get current analysis statistics"""
        return self.findings.get('statistics', {}) 