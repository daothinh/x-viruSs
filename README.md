<center>
x-viruSs - easy with multiple APIs
</center>

usage: x-virus.py [options] [value]

x-vriuSs: A tool for analyzing the performance of a file system

options:
  -x PATH [PATH ...]    check detection ratio of file on VirusTotal
  -pecheck FILE         show file version, timestamp, and digital signature details
  -hybrid HASH [HASH ...]
                        download sample malicious file from Hybrid Analysis
  -v, --version         show program's version number and exit
  -h, --help            show this help message and 
  

Documents:
-hybrid: chấp nhận đối số là 1, nhiều mã hash cùng lúc hoặc đường dẫn chứa thông tin list_hash
        + list_hash cần tuân theo format csv như sau: hash, name

-x: chấp nhận đối số là đường dẫn file hoặc đường dẫn folder
-vrshare: