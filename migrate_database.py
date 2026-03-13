"""
Database Migration Script
Adds new columns to existing database
"""
import sqlite3
import os

def migrate_database():
    """Migrate existing database to new schema"""
    
    db_path = 'database.db'
    
    if not os.path.exists(db_path):
        print("No existing database found. Will be created on first run.")
        return
    
    print("Starting database migration...")
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Check if cvss_score column exists
        c.execute("PRAGMA table_info(scans)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'cvss_score' not in columns:
            print("Adding cvss_score column...")
            c.execute("ALTER TABLE scans ADD COLUMN cvss_score REAL DEFAULT 0.0")
            print("✓ cvss_score column added")
        else:
            print("✓ cvss_score column already exists")
        
        if 'open_ports' not in columns:
            print("Adding open_ports column...")
            c.execute("ALTER TABLE scans ADD COLUMN open_ports INTEGER DEFAULT 0")
            print("✓ open_ports column added")
        else:
            print("✓ open_ports column already exists")
        
        conn.commit()
        conn.close()
        
        print("\n✅ Database migration completed successfully!")
        print("You can now run the application: python app.py\n")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {str(e)}")
        print("\nAlternative: Delete database.db and restart app to create fresh database")

if __name__ == '__main__':
    migrate_database()
