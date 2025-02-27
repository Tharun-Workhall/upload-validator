const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const crypto = require('crypto');
const unzipper = require('unzipper');
const JSZip = require('jszip');
const xml2js = require('xml2js');
const pdfParse = require('pdf-parse');

const app = express();
const port = 3000;

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads/temp');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure random filename to prevent path traversal
    const safeFilename = crypto.randomBytes(16).toString('hex') + 
                        path.extname(file.originalname).toLowerCase();
    cb(null, safeFilename);
  }
});

// Create upload middleware with file restrictions
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allowed file extensions - can be customized based on requirements
    const allowedExts = ['.txt', '.csv', '.ppt', '.pptx', '.xls', '.xlsx', '.doc', '.docx', '.pdf', '.jpg', '.jpeg', '.png', '.svg'];
    const ext = path.extname(file.originalname).toLowerCase();
    
    if (!allowedExts.includes(ext)) {
      return cb(new Error('File type not allowed'), false);
    }
    cb(null, true);
  }
});

// Malicious content detection functions
const securityChecks = {
  // Common malicious patterns across file types
  commonMaliciousPatterns: [
    /<script/i, 
    /javascript:/i, 
    /eval\(/i, 
    /document\.write/i, 
    /fromCharCode/i, 
    /iframe/i,
    /onload=/i, 
    /onerror=/i, 
    /onclick=/i,
    /execCommand/i,
    /ActiveXObject/i,
    /shellexecute/i,
    /powershell -e/i,
    /cmd\.exe/i,
    /cmd \/c/i,
    /bash -i/i,
    /system\(/i,
    /passthru\(/i,
    /exec\(/i,
    /base64_decode\(/i
  ],

  // Detect suspicious content in text files
  async scanTextFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      
      // Check for common malicious patterns
      for (const pattern of this.commonMaliciousPatterns) {
        if (pattern.test(content)) {
          return {
            safe: false,
            reason: `Suspicious pattern detected: ${pattern}`
          };
        }
      }
      
      // Check for Unicode encoding tricks
      const unicodeSuspicious = /\u200C|\u200D|\u202C|\u202D|\u202E/.test(content);
      if (unicodeSuspicious) {
        return {
          safe: false,
          reason: 'Suspicious Unicode control characters detected'
        };
      }
      
      // Check for potential polyglot indicators
      if (content.includes('<?php') || 
          content.includes('<%') || 
          content.includes('<!DOCTYPE html>')) {
        return {
          safe: false,
          reason: 'File appears to contain code in another language'
        };
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning text file: ${error.message}`
      };
    }
  },

  // Detect malicious content in CSV files
  async scanCSVFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      
      // Check for formula injections
      const formulaPatterns = [
        /^=/i,        // Any formula starting with '='
        /^@/i,        // '@' can sometimes be used in formulas
        /^\+/i,       // '+' might indicate a formula
        /^-/i,        // '-' might be a formula
        /^cmd/i,      // Possible command execution formula
        /^=.*!/,      // External sheet reference
        /^=hyperlink/i, // HYPERLINK function can be exploited
        /^=dde/i,      // Dynamic Data Exchange (DDE) attacks
        /^=webservice/i, // WEB SERVICE function (potential data exfiltration)
        /^=http/i      // HTTP links in formulas
    ];
    
      
      for (const line of lines) {
        const cells = line.split(',');
        
        for (const cell of cells) {
          const trimmedCell = cell.trim();
          
          // Check for formula injections
          for (const pattern of formulaPatterns) {
            if (pattern.test(trimmedCell)) {
              return {
                safe: false,
                reason: `Detected formula injection: ${trimmedCell}`
              };
            }
          }
          
          // Check for common malicious patterns
          for (const pattern of this.commonMaliciousPatterns) {
            if (pattern.test(trimmedCell)) {
              return {
                safe: false,
                reason: `Suspicious pattern in CSV: ${pattern}`
              };
            }
          }
        }
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning CSV file: ${error.message}`
      };
    }
  },

  // Detect malicious content in PowerPoint files
  async scanPowerPointFile(filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();
      
      if (ext === '.pptx') {
        // For PPTX (modern format)
        return await this.scanOfficeOpenXMLFile(filePath);
      } else {
        // For PPT (binary format)
        // Use strings command to extract strings and look for suspicious patterns
        const { stdout } = await execPromise(`strings "${filePath}"`);
        
        // Check for VBA macros
        if (stdout.includes('VBA') || 
            stdout.includes('ThisDocument') ||
            stdout.includes('Auto_Open') ||
            stdout.includes('AutoExec')) {
          return {
            safe: false,
            reason: 'PowerPoint file contains macros'
          };
        }
        
        // Check for OLE objects
        if (stdout.includes('Ole10Native') ||
            stdout.includes('ObjectPool')) {
          return {
            safe: false,
            reason: 'PowerPoint file contains embedded OLE objects'
          };
        }
        
        // Check for common malicious patterns
        for (const pattern of this.commonMaliciousPatterns) {
          if (pattern.test(stdout)) {
            return {
              safe: false,
              reason: `Suspicious pattern in PowerPoint: ${pattern}`
            };
          }
        }
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning PowerPoint file: ${error.message}`
      };
    }
  },

  // Scan Office OpenXML files (PPTX, XLSX, DOCX)
  async scanOfficeOpenXMLFile(filePath) {
    try {
      // Create a temporary directory for extraction
      const extractDir = filePath + '_extracted';
      if (!fs.existsSync(extractDir)) {
        fs.mkdirSync(extractDir, { recursive: true });
      }
      
      // Extract the OpenXML file (it's a zip archive)
      const fileContent = fs.readFileSync(filePath);
      const zip = await JSZip.loadAsync(fileContent);
      
      // Check for macros (vbaProject.bin)
      if (zip.files['vbaProject.bin']) {
        return {
          safe: false,
          reason: 'Office file contains VBA macros'
        };
      }
      
      // Check for external relationships
      let hasExternalLinks = false;
      
      if (zip.files['_rels/.rels']) {
        const relsContent = await zip.files['_rels/.rels'].async('string');
        const parser = new xml2js.Parser();
        const relsData = await parser.parseStringPromise(relsContent);
        
        // Check for external relationships
        if (relsData?.Relationships?.Relationship) {
          for (const rel of relsData.Relationships.Relationship) {
            if (rel.$.Target && (
                rel.$.Target.startsWith('http') || 
                rel.$.Target.startsWith('file:') ||
                rel.$.Target.startsWith('\\\\')
              )) {
              hasExternalLinks = true;
              break;
            }
          }
        }
      }
      
      if (hasExternalLinks) {
        return {
          safe: false,
          reason: 'Office file contains external links'
        };
      }
      
      // Scan all XML files in the package
      for (const filename in zip.files) {
        if (filename.endsWith('.xml') || filename.endsWith('.rels')) {
          const content = await zip.files[filename].async('string');
          
          // Check for common malicious patterns in XML
          for (const pattern of this.commonMaliciousPatterns) {
            if (pattern.test(content)) {
              return {
                safe: false,
                reason: `Suspicious pattern in Office XML: ${pattern}`
              };
            }
          }
          
          // Check for XML external entities
          if (content.includes('<!ENTITY') && 
              (content.includes('SYSTEM') || content.includes('PUBLIC'))) {
            return {
              safe: false,
              reason: 'Office file contains potentially dangerous XML external entities'
            };
          }
        }
      }
      
      // Clean up extraction directory
      fs.rmSync(extractDir, { recursive: true, force: true });
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning Office OpenXML file: ${error.message}`
      };
    }
  },

  // Scan Excel files
  async scanExcelFile(filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();
      
      if (ext === '.xlsx') {
        // For XLSX (modern format)
        return await this.scanOfficeOpenXMLFile(filePath);
      } else {
        // For XLS (binary format)
        const { stdout } = await execPromise(`strings "${filePath}"`);
        
        // Check for XLM/Excel 4.0 macros
        if (stdout.includes('FORMULA') &&
            (stdout.includes('EXEC') || 
             stdout.includes('CALL') ||
             stdout.includes('RUN'))) {
          return {
            safe: false,
            reason: 'Excel file contains XLM/Excel 4.0 macros'
          };
        }
        
        // Check for DDE commands
        if (stdout.includes('DDE') ||
            stdout.includes('DDEAUTO')) {
          return {
            safe: false,
            reason: 'Excel file contains DDE commands'
          };
        }
        
        // Additional checks for binary XLS
        if (stdout.includes('VBA') ||
            stdout.includes('_VBA_PROJECT')) {
          return {
            safe: false,
            reason: 'Excel file contains VBA macros'
          };
        }
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning Excel file: ${error.message}`
      };
    }
  },

  // Scan JPEG/JPG images
  async scanJPEGFile(filePath) {
    try {
      // Use strings to extract text content that might be embedded
      const { stdout } = await execPromise(`strings "${filePath}"`);
      
      // Check for common malicious patterns
      for (const pattern of this.commonMaliciousPatterns) {
        if (pattern.test(stdout)) {
          return {
            safe: false,
            reason: `Suspicious pattern in JPEG: ${pattern}`
          };
        }
      }
      
      // Check for HTML/JS content that might indicate a polyglot file
      if (stdout.includes('<!DOCTYPE') ||
          stdout.includes('<html') ||
          stdout.includes('<script')) {
        return {
          safe: false,
          reason: 'JPEG file appears to contain HTML/JavaScript (polyglot file)'
        };
      }
      
      // Check EXIF metadata for suspicious content
      try {
        const { stdout: exifOutput } = await execPromise(`exiftool "${filePath}"`);
        const suspiciousMetadata = ['Comment', 'UserComment', 'XMP'].some(field => {
          const regexp = new RegExp(`${field}\\s*:.*?[<\\(]script`, 'i');
          return regexp.test(exifOutput);
        });
        
        if (suspiciousMetadata) {
          return {
            safe: false,
            reason: 'JPEG file contains suspicious content in metadata'
          };
        }
      } catch (exifError) {
        // If exiftool isn't available, skip this check
        console.log('ExifTool not available, skipping metadata check');
      }
      
      // Check for content after JPEG EOI marker (FF D9)
      try {
        const { stdout: hexOutput } = await execPromise(`hexdump -C "${filePath}" | grep -A 10 "ff d9"`);
        if (hexOutput && hexOutput.split('\n').length > 2) {
          return {
            safe: false,
            reason: 'JPEG file contains data after end marker - possible appended payload'
          };
        }
      } catch (hexError) {
        // If hexdump isn't available, skip this check
        console.log('hexdump not available, skipping EOI marker check');
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning JPEG file: ${error.message}`
      };
    }
  },

  // Scan SVG files (known high-risk format)
  async scanSVGFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      
      // Check for script tags
      if (/<script[\s\S]*?>[\s\S]*?<\/script>/i.test(content)) {
        return {
          safe: false,
          reason: 'SVG file contains script tags'
        };
      }
      
      // Check for event handlers
      const eventHandlers = [
        'onload', 'onmouseover', 'onclick', 'onfocus', 
        'onerror', 'onwheel', 'onmouseenter'
      ];
      
      const eventHandlerPattern = new RegExp(`(${eventHandlers.join('|')})\\s*=`, 'i');
      if (eventHandlerPattern.test(content)) {
        return {
          safe: false,
          reason: 'SVG file contains event handlers'
        };
      }
      
      // Check for embedded images with suspicious content
      if (/data:[^;]+;base64,[A-Za-z0-9+/=]+/i.test(content)) {
        // Extract and check Base64 data
        const base64Matches = content.match(/data:[^;]+;base64,([A-Za-z0-9+/=]+)/g) || [];
        
        for (const match of base64Matches) {
          const base64Data = match.split(',')[1];
          try {
            const decodedData = Buffer.from(base64Data, 'base64').toString('utf8');
            
            // Check decoded data for malicious patterns
            for (const pattern of this.commonMaliciousPatterns) {
              if (pattern.test(decodedData)) {
                return {
                  safe: false,
                  reason: 'SVG file contains suspicious Base64-encoded content'
                };
              }
            }
          } catch (e) {
            // If we can't decode it as text, it might be binary data - treat with caution
            if (base64Data.length > 1000) {  // Arbitrary threshold
              return {
                safe: false,
                reason: 'SVG file contains large Base64-encoded binary data'
              };
            }
          }
        }
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning SVG file: ${error.message}`
      };
    }
  },

  // Scan PDF files
  async scanPDFFile(filePath) {
    try {
      // Use pdf-parse to extract text and metadata
      const dataBuffer = fs.readFileSync(filePath);
      const pdfData = await pdfParse(dataBuffer);
      
      // Check extracted text for JavaScript
      const jsKeywords = [
        '/JS', '/JavaScript', 'eval(', 'getAnnots',
        'app.alert', 'app.exec', 'app.launchURL'
      ];
      
      for (const keyword of jsKeywords) {
        if (pdfData.text.includes(keyword)) {
          return {
            safe: false,
            reason: `PDF file contains JavaScript: ${keyword}`
          };
        }
      }
      
      // Use external tools for deeper inspection if available
      try {
        const { stdout } = await execPromise(`pdfid "${filePath}"`);
        
        // Check for risky PDF features
        const riskyFeatures = {
          '/JS': 'JavaScript',
          '/JavaScript': 'JavaScript',
          '/AA': 'Automatic Action',
          '/OpenAction': 'Automatic Action',
          '/Launch': 'Launch Action',
          '/URI': 'URI Action',
          '/SubmitForm': 'Form Submission',
          '/RichMedia': 'Rich Media (Flash)'
        };
        
        for (const [feature, description] of Object.entries(riskyFeatures)) {
          // Look for feature followed by non-zero value
          const regex = new RegExp(`${feature}\\s+([1-9][0-9]*)`, 'i');
          const match = stdout.match(regex);
          
          if (match && parseInt(match[1]) > 0) {
            return {
              safe: false,
              reason: `PDF contains potentially malicious feature: ${description}`
            };
          }
        }
      } catch (toolError) {
        // pdfid tool not available, continue with basic checks
        console.log('pdfid tool not available, using basic checks only');
      }
      
      return { safe: true };
    } catch (error) {
      return {
        safe: false,
        reason: `Error scanning PDF file: ${error.message}`
      };
    }
  },

  // Main scanner function that routes to the appropriate scanner based on file type
  async scanFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    
    // First, check the file signature (magic bytes) to prevent extension spoofing
    const fileSignature = await this.getFileSignature(filePath);
    const mimeType = this.getMimeTypeFromSignature(fileSignature);
    
    // Reject if extension doesn't match actual file type
    if (!this.isExtensionMatchingMimeType(ext, mimeType)) {
      return {
        safe: false,
        reason: `File extension mismatch. Declared: ${ext}, Actual: ${mimeType}`
      };
    }
    
    // Route to the appropriate scanner based on file type
    switch (ext) {
      case '.txt':
        return await this.scanTextFile(filePath);
      case '.csv':
        return await this.scanCSVFile(filePath);
      case '.ppt':
      case '.pptx':
        return await this.scanPowerPointFile(filePath);
      case '.xls':
      case '.xlsx':
        return await this.scanExcelFile(filePath);
      case '.doc':
      case '.docx':
        return await this.scanOfficeOpenXMLFile(filePath);
      case '.jpg':
      case '.png':
      case '.jpeg':
        return await this.scanJPEGFile(filePath);
      case '.svg':
        return await this.scanSVGFile(filePath);
      case '.pdf':
        return await this.scanPDFFile(filePath);
      default:
        return {
          safe: false,
          reason: `Unsupported file type: ${ext}`
        };
    }
  },

  // Read file signature (first bytes of the file)
  async getFileSignature(filePath) {
    try {
      const fd = fs.openSync(filePath, 'r');
      const buffer = Buffer.alloc(8); // Read first 8 bytes
      fs.readSync(fd, buffer, 0, 8, 0);
      fs.closeSync(fd);
      return buffer;
    } catch (error) {
      console.error('Error reading file signature:', error);
      return Buffer.alloc(0);
    }
  },

  // Get MIME type from file signature
  getMimeTypeFromSignature(signature) {
    // Common file signatures (magic numbers) - simplified version
    const hex = signature.toString('hex').toLowerCase();
    
    if (hex.startsWith('89504e47')) return 'image/png';
    if (hex.startsWith('ffd8ff')) return 'image/jpeg';
    if (hex.startsWith('25504446')) return 'application/pdf';
    if (hex.startsWith('504b0304')) return 'application/zip'; // Could be Office OpenXML
    if (hex.startsWith('d0cf11e0')) return 'application/msoffice'; // Office Binary Format
    if (hex.startsWith('3c3f786d6c') || hex.startsWith('3c737667')) return 'image/svg+xml';
    
    // Default to text/plain for files starting with ASCII text
    if (signature.every(byte => (byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13)) {
      return 'text/plain';
    }
    
    return 'application/octet-stream';
  },

  // Check if file extension matches the detected MIME type
  isExtensionMatchingMimeType(extension, mimeType) {
    const mimeMap = {
      '.txt': ['text/plain'],
      '.csv': ['text/plain', 'text/csv'],
      '.ppt': ['application/msoffice'],
      '.pptx': ['application/zip'],
      '.xls': ['application/msoffice'],
      '.xlsx': ['application/zip'],
      '.doc': ['application/msoffice'],
      '.docx': ['application/zip'],
      '.pdf': ['application/pdf'],
      '.jpg': ['image/jpeg'],
      '.jpeg': ['image/jpeg'],
      '.png': ['image/png'],
      '.svg': ['image/svg+xml', 'text/plain']
    };
    
    return mimeMap[extension]?.includes(mimeType) || false;
  }
};

// Set up file upload route
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const filePath = req.file.path;
    console.log(`File uploaded: ${req.file.originalname} (${req.file.mimetype})`);
    
    const scanResult = await securityChecks.scanFile(filePath);
    
    if (!scanResult.safe) {
      // Delete unsafe file
      fs.unlinkSync(filePath);
      
      return res.status(403).json({
        status: 'rejected',
        reason: scanResult.reason
      });
    }
    
    // File is safe - move to permanent storage
    const safeStorageDir = path.join(__dirname, 'uploads/safe');
    if (!fs.existsSync(safeStorageDir)) {
      fs.mkdirSync(safeStorageDir, { recursive: true });
    }
    
    const safeFilePath = path.join(safeStorageDir, req.file.filename);
    fs.renameSync(filePath, safeFilePath);
    
    res.json({
      status: 'accepted',
      filename: req.file.filename,
      originalName: req.file.originalname
    });
    
  } catch (error) {
    console.error('Error in file upload handler:', error);
    
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({ error: 'File upload failed', details: error.message });
  }
});

// Simple HTML form for testing
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure File Upload</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .upload-form { border: 1px solid #ccc; padding: 20px; border-radius: 5px; }
        .result { margin-top: 20px; padding: 15px; border-radius: 5px; display: none; }
        .success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .error { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
      </style>
    </head>
    <body>
      <h1>Secure File Upload</h1>
      <div class="upload-form">
        <form id="uploadForm" enctype="multipart/form-data">
          <div>
            <input type="file" id="fileInput" name="file" required>
          </div>
          <div style="margin-top: 15px;">
            <button type="submit">Upload</button>
          </div>
        </form>
      </div>
      
      <div id="resultBox" class="result"></div>
      
      <script>
        document.getElementById('uploadForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          
          const formData = new FormData();
          const fileInput = document.getElementById('fileInput');
          formData.append('file', fileInput.files[0]);
          
          const resultBox = document.getElementById('resultBox');
          resultBox.style.display = 'none';
          
          try {
            const response = await fetch('/upload', {
              method: 'POST',
              body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
              resultBox.className = 'result success';
              resultBox.textContent = 'File uploaded successfully!';
            } else {
              resultBox.className = 'result error';
              resultBox.textContent = 'Upload rejected: ' + result.reason;
            }
          } catch (error) {
            resultBox.className = 'result error';
            resultBox.textContent = 'Error: ' + error.message;
          }
          
          resultBox.style.display = 'block';
        });
      </script>
    </body>
    </html>
  `);
});

// Start server
app.listen(port, () => {
  console.log(`Secure file upload server running on port ${port}`);
});