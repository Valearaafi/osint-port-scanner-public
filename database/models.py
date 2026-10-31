import sqlite3
import json
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

class DatabaseManager:
    """Database management for scan results and history"""
    
    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self) -> None:
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            
            # Scan sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    results TEXT,
                    risk_score INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'completed',
                    duration REAL DEFAULT 0.0
                )
            ''')
            
            # Discovered hosts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discovered_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    ip_address TEXT,
                    hostname TEXT,
                    open_ports TEXT,
                    services TEXT,
                    os_info TEXT,
                    vulnerabilities TEXT,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    cve_id TEXT,
                    severity TEXT,
                    description TEXT,
                    service TEXT,
                    port INTEGER,
                    remediation TEXT,
                    cvss_score REAL DEFAULT 0.0,
                    FOREIGN KEY (host_id) REFERENCES discovered_hosts (id)
                )
            ''')
            
            # API usage tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    query TEXT,
                    response_code INTEGER,
                    rate_limit_remaining INTEGER
                )
            ''')
            
            conn.commit()
        finally:
            conn.close()
    
    def save_scan_session(self, target: str, scan_type: str, results: Dict[str, Any], 
                         risk_score: int = 0, duration: float = 0.0,
                         status: str = "completed") -> int:
        """Save scan session to database"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_sessions (target, scan_type, timestamp, results, risk_score, status, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (target, scan_type, datetime.now().isoformat(), 
                     json.dumps(results), risk_score, status, duration))
                
                session_id = cursor.lastrowid
                
                # Save discovered hosts only for completed scans
                if status == "completed":
                    self._save_hosts(cursor, session_id, results)
                
                conn.commit()
                return session_id
            finally:
                conn.close()
    
    def _save_hosts(self, cursor: sqlite3.Cursor, session_id: int, results: Dict[str, Any]) -> None:
        """Save discovered hosts to database"""
        target_ip = results.get('target_ip', '')
        target_hostname = results.get('target', '')
        
        open_ports = json.dumps(results.get('tcp_ports', []))
        services = json.dumps(results.get('services', {}))
        vulnerabilities = json.dumps(results.get('vulnerabilities', []))
        
        cursor.execute('''
            INSERT INTO discovered_hosts (session_id, ip_address, hostname, open_ports, services, vulnerabilities)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, target_ip, target_hostname, open_ports, services, vulnerabilities))
        
        host_id = cursor.lastrowid
        
        # Save individual vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            cursor.execute('''
                INSERT INTO vulnerabilities (host_id, cve_id, severity, description, service, cvss_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, vuln.get('cve_id', ''), vuln.get('severity', ''),
                 vuln.get('description', ''), vuln.get('service', ''), vuln.get('cvss_score', 0.0)))
    
    def get_scan_history(self, limit: int = 50) -> List[Tuple]:
        """Get scan history from database"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, target, scan_type, timestamp, results, risk_score, status, duration
                FROM scan_sessions 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
        finally:
            conn.close()
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Tuple]:
        """Get specific scan by ID"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_sessions WHERE id = ?
            ''', (scan_id,))
            return cursor.fetchone()
        finally:
            conn.close()
    
    def delete_scan(self, scan_id: int) -> bool:
        """Delete scan and related data"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()
                    
                    # Delete vulnerabilities first
                    cursor.execute('''
                        DELETE FROM vulnerabilities 
                        WHERE host_id IN (
                            SELECT id FROM discovered_hosts WHERE session_id = ?
                        )
                    ''', (scan_id,))
                    
                    # Delete discovered hosts
                    cursor.execute('DELETE FROM discovered_hosts WHERE session_id = ?', (scan_id,))
                    
                    # Delete scan session
                    cursor.execute('DELETE FROM scan_sessions WHERE id = ?', (scan_id,))
                    
                    conn.commit()
                    return True
                finally:
                    conn.close()
            except Exception as e:
                print(f"Error deleting scan: {e}")
                return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            
            stats = {}
            
            # Total scans
            cursor.execute('SELECT COUNT(*) FROM scan_sessions')
            stats['total_scans'] = cursor.fetchone()[0]
            
            # Scans by type
            cursor.execute('SELECT scan_type, COUNT(*) FROM scan_sessions GROUP BY scan_type')
            stats['scans_by_type'] = dict(cursor.fetchall())
            
            # Average risk score
            cursor.execute('SELECT AVG(risk_score) FROM scan_sessions')
            avg_risk = cursor.fetchone()[0]
            stats['average_risk_score'] = round(avg_risk, 2) if avg_risk else 0
            
            # Total vulnerabilities
            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            stats['total_vulnerabilities'] = cursor.fetchone()[0]
            
            return stats
        finally:
            conn.close()