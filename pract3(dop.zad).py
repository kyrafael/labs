import sqlite3
import datetime

DB_NAME = 'security_log.db'


def create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("PRAGMA foreign_keys = ON;")  # Ensure foreign key constraints are enforced
        print(f"Successfully connected to database: {DB_NAME} (SQLite version: {sqlite3.sqlite_version})")
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
    return conn


def create_tables(conn):
    """Create the tables in the database as per the requirements."""
    sql_create_event_sources_table = """
    CREATE TABLE IF NOT EXISTS EventSources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        location TEXT,
        type TEXT
    );
    """
    sql_create_event_types_table = """
    CREATE TABLE IF NOT EXISTS EventTypes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type_name TEXT UNIQUE NOT NULL,
        severity TEXT NOT NULL
    );
    """
    sql_create_security_events_table = """
    CREATE TABLE IF NOT EXISTS SecurityEvents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        source_id INTEGER NOT NULL,
        event_type_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        ip_address TEXT,
        username TEXT,
        FOREIGN KEY (source_id) REFERENCES EventSources (id) ON DELETE CASCADE,
        FOREIGN KEY (event_type_id) REFERENCES EventTypes (id) ON DELETE CASCADE
    );
    """
    try:
        c = conn.cursor()
        print("Creating table EventSources...")
        c.execute(sql_create_event_sources_table)
        print("Creating table EventTypes...")
        c.execute(sql_create_event_types_table)
        print("Creating table SecurityEvents...")
        c.execute(sql_create_security_events_table)
        conn.commit()
        print("Tables created successfully.")
    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")


def populate_event_types(conn):
    """Populate the EventTypes table with initial data. [cite: 4, 5]"""
    event_types_data = [
        ("Login Success", "Informational"),  # [cite: 5]
        ("Login Failed", "Warning"),  # [cite: 5]
        ("Port Scan Detected", "Warning"),  # [cite: 5]
        ("Malware Alert", "Critical")  # [cite: 5]
    ]
    sql = '''INSERT OR IGNORE INTO EventTypes (type_name, severity) VALUES (?, ?)'''
    try:
        cur = conn.cursor()
        cur.executemany(sql, event_types_data)
        conn.commit()
        print(f"{cur.rowcount} rows inserted or already existing in EventTypes.")
    except sqlite3.Error as e:
        print(f"Error populating EventTypes: {e}")


def populate_event_sources_test_data(conn):
    """Populate the EventSources table with some test data. [cite: 6]"""
    sources_data = [
        ("Firewall_A", "192.168.1.1", "Firewall"),
        ("Web_Server_Logs", "appserver01.example.com", "Web Server"),
        ("IDS_Sensor_B", "DMZ Network Segment", "IDS"),
        ("Workstation_101", "Office_Room_3 / 10.1.5.101", "Endpoint"),
        ("Database_Audit", "db01.internal", "Database")
    ]
    sql = '''INSERT OR IGNORE INTO EventSources (name, location, type) VALUES (?, ?, ?)'''
    try:
        cur = conn.cursor()
        cur.executemany(sql, sources_data)
        conn.commit()
        print(f"{cur.rowcount} rows inserted or already existing in EventSources.")
    except sqlite3.Error as e:
        print(f"Error populating EventSources: {e}")

    # Fetch IDs for SecurityEvents population
    cur.execute("SELECT id, name FROM EventSources")
    sources_map = {name: id for id, name in cur.fetchall()}
    cur.execute("SELECT id, type_name FROM EventTypes")
    types_map = {type_name: id for id, type_name in cur.fetchall()}
    return sources_map, types_map


def populate_security_events_test_data(conn, sources_map, types_map):
    """Populate the SecurityEvents table with 10+ test values. [cite: 6]"""
    if not sources_map or not types_map:
        print("Cannot populate SecurityEvents: missing source or type mappings.")
        return

    now = datetime.datetime.now()

    # Helper to safely get IDs, defaulting to None if key is missing
    def get_id(mapping, key_name):
        res_id = mapping.get(key_name)
        if res_id is None:
            print(f"Warning: ID for '{key_name}' not found in mappings. Skipping events that rely on it.")
        return res_id

    login_failed_id = get_id(types_map, "Login Failed")
    login_success_id = get_id(types_map, "Login Success")
    port_scan_id = get_id(types_map, "Port Scan Detected")
    malware_alert_id = get_id(types_map, "Malware Alert")

    firewall_a_id = get_id(sources_map, "Firewall_A")
    web_server_id = get_id(sources_map, "Web_Server_Logs")
    ids_sensor_b_id = get_id(sources_map, "IDS_Sensor_B")
    workstation_101_id = get_id(sources_map, "Workstation_101")
    db_audit_id = get_id(sources_map, "Database_Audit")

    security_events_data = [
        # Recent "Login Failed" for last 24h query
        ((now - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Failed login for user 'admin' from 192.0.2.10", "192.0.2.10", "admin"),
        ((now - datetime.timedelta(hours=23)).strftime("%Y-%m-%d %H:%M:%S"), web_server_id, login_failed_id,
         "Failed login for user 'service_acc' from 203.0.113.5", "203.0.113.5", "service_acc"),

        # Data for brute-force detection (>5 attempts from same IP in 1 hour)
        ((now - datetime.timedelta(minutes=55)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),
        ((now - datetime.timedelta(minutes=54)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),
        ((now - datetime.timedelta(minutes=53)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),
        ((now - datetime.timedelta(minutes=52)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),
        ((now - datetime.timedelta(minutes=51)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),
        ((now - datetime.timedelta(minutes=50)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, login_failed_id,
         "Brute-force attempt on SSH from 198.51.100.22", "198.51.100.22", "root"),  # 6th attempt

        # Critical events for last week query
        ((now - datetime.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"), ids_sensor_b_id, malware_alert_id,
         "Critical Ransomware signature 'LockBit' detected on 10.1.5.101", "10.1.5.101", "SYSTEM"),
        ((now - datetime.timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"), web_server_id, malware_alert_id,
         "Web server compromised: Shell uploaded to /var/www/html/uploads/shell.php", "203.0.113.10", None),
        ((now - datetime.timedelta(days=6)).strftime("%Y-%m-%d %H:%M:%S"), db_audit_id, malware_alert_id,
         "Critical: SQL Injection attack pattern identified from 192.0.2.50 targeting user table.", "192.0.2.50",
         "web_app_user"),

        # Other events
        ((now - datetime.timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"), workstation_101_id, login_success_id,
         "User 'jdoe' logged in successfully.", "10.1.5.101", "jdoe"),
        ((now - datetime.timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"), ids_sensor_b_id, port_scan_id,
         "Nmap FIN scan detected from 192.0.2.100 against multiple hosts.", "192.0.2.100", None),
        ((now - datetime.timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S"), firewall_a_id, malware_alert_id,
         "Old critical event (should not appear in last week query)", "1.2.3.4", "test")
    ]

    # Filter out events where essential IDs are None
    valid_events_data = [event for event in security_events_data if event[1] is not None and event[2] is not None]

    # Use INSERT OR IGNORE to be safe if script is run multiple times, though SecurityEvents typically don't need it
    # as they are individual timestamped logs. However, for testing fixed data, it can be useful.
    # For real logging, simple INSERT is fine.
    sql = '''INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
             VALUES (?, ?, ?, ?, ?, ?)'''
    try:
        cur = conn.cursor()
        cur.executemany(sql, valid_events_data)
        conn.commit()
        print(f"{cur.rowcount} rows inserted into SecurityEvents.")
    except sqlite3.Error as e:
        print(f"Error populating SecurityEvents: {e}")


# --- Core Functions ---
def register_event_source(conn, name, location, type_val):
    """Register a new event source. Corresponds to [cite: 3] for structure."""
    sql = '''INSERT INTO EventSources (name, location, type) VALUES (?, ?, ?)'''
    try:
        cur = conn.cursor()
        cur.execute(sql, (name, location, type_val))
        conn.commit()
        print(f"Event source '{name}' registered successfully with id {cur.lastrowid}.")
        return cur.lastrowid
    except sqlite3.IntegrityError:  # Handles UNIQUE constraint violation for 'name'
        print(f"Error: Event source with name '{name}' already exists.")
    except sqlite3.Error as e:
        print(f"Error registering event source '{name}': {e}")
    return None


def register_event_type(conn, type_name, severity):
    """Register a new event type. [cite: 7]"""
    sql = '''INSERT INTO EventTypes (type_name, severity) VALUES (?, ?)'''
    try:
        cur = conn.cursor()
        cur.execute(sql, (type_name, severity))
        conn.commit()
        print(f"Event type '{type_name}' registered successfully with id {cur.lastrowid}.")
        return cur.lastrowid
    except sqlite3.IntegrityError:  # Handles UNIQUE constraint violation for 'type_name'
        print(f"Error: Event type with name '{type_name}' already exists.")
    except sqlite3.Error as e:
        print(f"Error registering event type '{type_name}': {e}")
    return None


def log_security_event(conn, source_id, event_type_id, message, ip_address=None, username=None):
    """Log a new security event with an automatic timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = '''INSERT INTO SecurityEvents (timestamp, source_id, event_type_id, message, ip_address, username)
             VALUES (?, ?, ?, ?, ?, ?)'''
    try:
        cur = conn.cursor()
        cur.execute(sql, (timestamp, source_id, event_type_id, message, ip_address, username))
        conn.commit()
        print(f"Security event logged successfully with id {cur.lastrowid} at {timestamp}.")
        return cur.lastrowid
    except sqlite3.Error as e:
        print(f"Error logging security event: {e}")
    return None


# --- Query Functions ---
def get_login_failed_last_24_hours(conn):
    """Get all 'Login Failed' events from the last 24 hours. [cite: 8]"""
    time_24_hours_ago = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    sql = """
    SELECT se.id, se.timestamp, es.name as source_name, se.message, se.ip_address, se.username
    FROM SecurityEvents se
    JOIN EventTypes et ON se.event_type_id = et.id
    JOIN EventSources es ON se.source_id = es.id
    WHERE et.type_name = 'Login Failed' AND se.timestamp >= ?
    ORDER BY se.timestamp DESC;
    """
    try:
        cur = conn.cursor()
        print(f"\n--- Query: 'Login Failed' events since {time_24_hours_ago} ---")
        cur.execute(sql, (time_24_hours_ago,))
        events = cur.fetchall()
        if events:
            for event in events:
                print(
                    f"  ID: {event[0]}, Time: {event[1]}, Source: {event[2]}, IP: {event[4]}, User: {event[5]}, Msg: {event[3]}")
        else:
            print("  No 'Login Failed' events found in the last 24 hours.")
        return events
    except sqlite3.Error as e:
        print(f"  Error querying 'Login Failed' events: {e}")
        return []


def detect_brute_force_ips(conn):
    """Detect IP addresses with more than 5 failed login attempts in any 1-hour window. [cite: 9]"""
    # This query groups failed logins by IP address and the hour they occurred.
    # If an IP has more than 5 failed logins within the same hour block, it's flagged.
    sql = """
    SELECT
        se.ip_address,
        STRFTIME('%Y-%m-%d %H:00:00', se.timestamp) as event_hour_block,
        COUNT(se.id) as failed_attempts_in_hour
    FROM SecurityEvents se
    JOIN EventTypes et ON se.event_type_id = et.id
    WHERE et.type_name = 'Login Failed' AND se.ip_address IS NOT NULL
    GROUP BY se.ip_address, event_hour_block
    HAVING COUNT(se.id) > 5
    ORDER BY failed_attempts_in_hour DESC, se.ip_address, event_hour_block;
    """
    try:
        cur = conn.cursor()
        print("\n--- Query: IPs with > 5 failed logins in a 1-hour window ---")
        cur.execute(sql)
        ips = cur.fetchall()
        if ips:
            for ip_data in ips:
                print(f"  IP: {ip_data[0]}, Hour Block: {ip_data[1]}, Attempts: {ip_data[2]}")
        else:
            print("  No IPs flagged for potential brute-force activity based on current data.")
        return ips
    except sqlite3.Error as e:
        print(f"  Error detecting brute force IPs: {e}")
        return []


def get_critical_events_last_week_by_source(conn):
    """Get all 'Critical' events from the last week, grouped by source. [cite: 10]"""
    time_1_week_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    sql = """
    SELECT es.name as source_name, es.location, es.type as source_type, 
           se.id, se.timestamp, et.type_name as event_type, se.message, se.ip_address, se.username
    FROM SecurityEvents se
    JOIN EventTypes et ON se.event_type_id = et.id
    JOIN EventSources es ON se.source_id = es.id
    WHERE et.severity = 'Critical' AND se.timestamp >= ?
    ORDER BY es.name, se.timestamp DESC;
    """
    try:
        cur = conn.cursor()
        print(f"\n--- Query: 'Critical' events since {time_1_week_ago}, grouped by source ---")
        cur.execute(sql, (time_1_week_ago,))
        events = cur.fetchall()
        if events:
            current_source_name = None
            for event in events:
                if event[0] != current_source_name:
                    current_source_name = event[0]
                    print(f"\n  Source: {event[0]} (Location: {event[1]}, Type: {event[2]})")
                print(
                    f"    - Event ID: {event[3]}, Time: {event[4]}, Type: {event[5]}, IP: {event[7]}, User: {event[8]}, Msg: {event[6]}")
        else:
            print("  No 'Critical' events found in the last week.")
        return events
    except sqlite3.Error as e:
        print(f"  Error querying 'Critical' events: {e}")
        return []


def find_events_by_keyword(conn, keyword):
    """Find all events containing a specific keyword in the message. [cite: 11]"""
    sql = """
    SELECT se.id, se.timestamp, es.name as source_name, et.type_name as event_type, 
           se.message, se.ip_address, se.username
    FROM SecurityEvents se
    JOIN EventTypes et ON se.event_type_id = et.id
    JOIN EventSources es ON se.source_id = es.id
    WHERE se.message LIKE ?
    ORDER BY se.timestamp DESC;
    """
    try:
        cur = conn.cursor()
        print(f"\n--- Query: Events containing keyword '{keyword}' ---")
        cur.execute(sql, (f'%{keyword}%',))  # Add wildcards for 'contains' search
        events = cur.fetchall()
        if events:
            for event in events:
                print(
                    f"  ID: {event[0]}, Time: {event[1]}, Source: {event[2]}, Type: {event[3]}, IP: {event[5]}, User: {event[6]}, Msg: {event[4]}")
        else:
            print(f"  No events found containing keyword '{keyword}'.")
        return events
    except sqlite3.Error as e:
        print(f"  Error finding events by keyword '{keyword}': {e}")
        return []


def main():
    # Establish database connection
    conn = create_connection()

    if conn is not None:
        # Create tables if they don't exist
        create_tables(conn)

        # Populate initial and test data
        print("\n--- Populating Initial Data ---")
        populate_event_types(conn)  # As per [cite: 4, 5]
        sources_map, types_map = populate_event_sources_test_data(conn)  # As per [cite: 6]
        populate_security_events_test_data(conn, sources_map, types_map)  # As per [cite: 6]

        # --- Demonstrate Core Functions ---
        print("\n\n--- Demonstrating Core Functions ---")

        # Register a new event source
        print("\n* Registering new event source:")
        new_source_id = register_event_source(conn, "VPN_Gateway_01", "Datacenter A, Rack 5", "VPN Concentrator")
        register_event_source(conn, "VPN_Gateway_01", "Datacenter A, Rack 5", "VPN Concentrator")  # Attempt duplicate

        # Register a new event type
        print("\n* Registering new event type: [cite: 7]")
        new_type_id = register_event_type(conn, "File Integrity Violation", "High")
        register_event_type(conn, "File Integrity Violation", "High")  # Attempt duplicate

        # Log a new security event (using newly created source/type if available)
        print("\n* Logging new security event:")
        if new_source_id and types_map.get("Port Scan Detected"):
            log_security_event(conn, new_source_id, types_map["Port Scan Detected"],
                               "Aggressive scan detected from 10.255.255.1 to multiple internal IPs", "10.255.255.1")
        else:
            print("  Skipping logging event with new source/type due to registration failure or type not found.")

        # Log another event using existing IDs for demonstration
        if sources_map.get("Web_Server_Logs") and types_map.get("Login Success"):
            log_security_event(conn, sources_map["Web_Server_Logs"], types_map["Login Success"],
                               "Admin 'webmaster' logged in from 192.168.0. Admin panel accessed.", "192.168.0. Admin",
                               "webmaster")

        # --- Demonstrate Query Functions ---
        print("\n\n--- Demonstrating Query Functions ---")

        # Query 1: Get all "Login Failed" events for the last 24 hours [cite: 8]
        get_login_failed_last_24_hours(conn)

        # Query 2: Detect IPs with > 5 failed login attempts in 1 hour [cite: 9]
        detect_brute_force_ips(conn)

        # Query 3: Get all "Critical" events for the last week, grouped by source [cite: 10]
        get_critical_events_last_week_by_source(conn)

        # Query 4: Find all events containing a specific keyword [cite: 11]
        find_events_by_keyword(conn, "Malware")
        find_events_by_keyword(conn, "SSH")
        find_events_by_keyword(conn, "non_existent_keyword_xyz123")

        # Close the database connection
        conn.close()
        print(f"\nDisconnected from database: {DB_NAME}")
    else:
        print("CRITICAL: Could not establish database connection. Program terminated.")


if __name__ == '__main__':
    main()
    print(f"\nScript finished. You should now have a '{DB_NAME}' file in the same directory.")
    print(f"You can inspect it using an SQLite browser like the one at: https://sqlitebrowser.org/ [cite: 2]")